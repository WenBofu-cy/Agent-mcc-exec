#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-04
模块名称: 工具注册中心
所属分区: 二、工具管理集群
核心职责: 作为 MCC 行动执行层的工具元数据中心，维护所有可用工具的全生命周期注册信息。
          管理工具名称、类型、参数模板、调用方式、配额预设、安全等级等元数据。支持运行时
          动态注册新工具、注销已废弃工具、更新工具版本与参数约束。为 ag-mcc-01（执行调度
          核心）提供工具类型路由依据，为 ag-mcc-03（资源配额管控单元）提供各工具的预设资源
          配额，为 ag-mcc-05（工具参数校验器）提供参数合法性校验模板。不参与工具的实际调用，
          仅负责工具元数据的存储、检索与版本管理。

依赖模块:
    无（作为工具元数据的基础设施，不依赖其他 MCC 内部模块）
被依赖模块:
    ag-mcc-01, ag-mcc-03, ag-mcc-05, ag-mcc-06

安全约束:
  R-01: 工具注册/注销操作必须持有有效的授权令牌
  R-02: 安全等级为 CRITICAL 的工具不可通过运行时注册接口动态注册
  R-03: 工具元数据中不得存储任何认证密钥或敏感凭证
  R-04: 工具注销后，其元数据不得立即删除，应保留至少 30 天供审计追溯
  R-05: 工具版本更新时必须保留至少上一个版本的元数据快照，支持紧急回滚
"""

from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid
import copy


class RegistryState(Enum):
    NORMAL_SERVICE = "normal_service"
    REGISTERING = "registering"
    UNREGISTERING = "unregistering"
    SYSTEM_PAUSED = "system_paused"


class ToolType(Enum):
    API = "API"
    CODE = "CODE"
    FILE = "FILE"
    LLM = "LLM"
    DB = "DB"


class SecurityLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ToolStatus(Enum):
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    DISABLED = "DISABLED"


@dataclass
class ToolMetadata:
    tool_name: str = ""
    tool_type: ToolType = ToolType.API
    version: str = "1.0.0"
    param_template: Dict[str, Any] = field(default_factory=dict)
    endpoint: str = ""
    auth_method: str = "NONE"
    quota_preset: Dict[str, Any] = field(default_factory=dict)
    security_level: SecurityLevel = SecurityLevel.LOW
    default_timeout_sec: int = 30
    max_concurrency: int = 5
    status: ToolStatus = ToolStatus.ACTIVE
    registered_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    deprecated_at: float = 0.0


@dataclass
class ToolQueryRequest:
    requester_module: str = ""
    query_type: str = "single"  # single / all / by_type
    tool_name: str = ""
    tool_type: Optional[ToolType] = None


@dataclass
class ToolRegisterRequest:
    tool_name: str = ""
    tool_type: ToolType = ToolType.API
    version: str = "1.0.0"
    param_template: Dict[str, Any] = field(default_factory=dict)
    endpoint: str = ""
    auth_method: str = "NONE"
    quota_preset: Dict[str, Any] = field(default_factory=dict)
    security_level: SecurityLevel = SecurityLevel.LOW
    default_timeout_sec: int = 30
    max_concurrency: int = 5
    authorization_token: str = ""


@dataclass
class ToolUnregisterRequest:
    tool_name: str = ""
    reason: str = ""
    force: bool = False
    authorization_token: str = ""


@dataclass
class ToolQueryResult:
    tools: List[ToolMetadata] = field(default_factory=list)
    total_matched: int = 0


@dataclass
class ToolRegisterConfirm:
    tool_name: str = ""
    success: bool = True
    operation: str = ""  # "新增" / "更新"
    old_version: str = ""
    new_version: str = ""
    error_reason: str = ""


@dataclass
class ToolUnregisterConfirm:
    tool_name: str = ""
    success: bool = True
    error_reason: str = ""


@dataclass
class ToolChangeNotification:
    change_type: str = ""  # "注册" / "更新" / "注销"
    tool_name: str = ""
    version: str = ""
    timestamp: float = field(default_factory=time.time)


class ToolRegistry:
    # 工具元数据保留期限（秒）—— 30 天
    RETENTION_SEC = 30 * 86400

    def __init__(self):
        self.module_id = "ag-mcc-04"
        self.module_name = "工具注册中心"
        self.version = "V1.0"

        self.state = RegistryState.NORMAL_SERVICE
        self._tools: Dict[str, ToolMetadata] = {}
        self._version_history: Dict[str, List[ToolMetadata]] = {}
        self._deprecated_tools: Dict[str, ToolMetadata] = {}
        self._pending_logs: List[Dict[str, Any]] = []

        # 回调注入
        self._query_tool_request = None
        self._query_register_request = None
        self._query_unregister_request = None

        self._publish_query_result = None
        self._publish_register_confirm = None
        self._publish_unregister_confirm = None
        self._publish_change_notification = None
        self._publish_event_log = None

        # 预置工具
        self._load_preset_tools()

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成, 已注册工具数={len(self._tools)}")

    # ========== 回调注入 ==========
    def set_tool_request_query(self, callback: Callable[[], Optional[ToolQueryRequest]]):
        self._query_tool_request = callback

    def set_register_request_query(self, callback: Callable[[], Optional[ToolRegisterRequest]]):
        self._query_register_request = callback

    def set_unregister_request_query(self, callback: Callable[[], Optional[ToolUnregisterRequest]]):
        self._query_unregister_request = callback

    def set_query_result_publisher(self, callback: Callable[[ToolQueryResult], None]):
        self._publish_query_result = callback

    def set_register_confirm_publisher(self, callback: Callable[[ToolRegisterConfirm], None]):
        self._publish_register_confirm = callback

    def set_unregister_confirm_publisher(self, callback: Callable[[ToolUnregisterConfirm], None]):
        self._publish_unregister_confirm = callback

    def set_change_notification_publisher(self, callback: Callable[[ToolChangeNotification], None]):
        self._publish_change_notification = callback

    def set_event_log_publisher(self, callback: Callable[[Dict[str, Any]], None]):
        self._publish_event_log = callback

    # ========== 主循环 ==========
    def run_registry_cycle(self):
        if self.state == RegistryState.SYSTEM_PAUSED:
            return

        # 处理查询
        query = self._query_tool_request() if self._query_tool_request else None
        if query:
            self._handle_query(query)
            return

        # 处理注册
        register = self._query_register_request() if self._query_register_request else None
        if register:
            self._handle_register(register)
            return

        # 处理注销
        unregister = self._query_unregister_request() if self._query_unregister_request else None
        if unregister:
            self._handle_unregister(unregister)

    # ========== 查询处理 ==========
    def _handle_query(self, request: ToolQueryRequest):
        matched = []
        if request.query_type == "single":
            tool = self._tools.get(request.tool_name)
            if tool:
                matched = [tool]
        elif request.query_type == "by_type" and request.tool_type:
            matched = [t for t in self._tools.values() if t.tool_type == request.tool_type]
        else:
            matched = list(self._tools.values())

        if self._publish_query_result:
            self._publish_query_result(ToolQueryResult(
                tools=matched,
                total_matched=len(matched)
            ))

    # ========== 注册处理 ==========
    def _handle_register(self, request: ToolRegisterRequest):
        self.state = RegistryState.REGISTERING

        # 校验授权令牌
        if len(request.authorization_token) < 10:
            self._send_register_confirm(request.tool_name, False, error="授权令牌无效")
            self.state = RegistryState.NORMAL_SERVICE
            return

        # 校验必填字段
        if not request.tool_name or not request.tool_type:
            self._send_register_confirm(request.tool_name, False, error="缺少必填字段")
            self.state = RegistryState.NORMAL_SERVICE
            return

        # 安全等级限制
        if request.security_level == SecurityLevel.CRITICAL:
            self._send_register_confirm(request.tool_name, False, error="CRITICAL 安全等级工具禁止运行时注册")
            self.state = RegistryState.NORMAL_SERVICE
            return

        existing = self._tools.get(request.tool_name)
        if existing:
            # 版本号校验
            if request.version <= existing.version:
                self._send_register_confirm(request.tool_name, False, error=f"版本号必须高于当前版本 {existing.version}")
                self.state = RegistryState.NORMAL_SERVICE
                return

            # 备份旧版本
            old_copy = copy.deepcopy(existing)
            if request.tool_name not in self._version_history:
                self._version_history[request.tool_name] = []
            self._version_history[request.tool_name].append(old_copy)

            # 更新元数据
            existing.version = request.version
            existing.param_template = request.param_template
            existing.endpoint = request.endpoint
            existing.auth_method = request.auth_method
            existing.quota_preset = request.quota_preset
            existing.security_level = request.security_level
            existing.default_timeout_sec = request.default_timeout_sec
            existing.max_concurrency = request.max_concurrency
            existing.status = ToolStatus.ACTIVE
            existing.updated_at = time.time()

            self._send_register_confirm(request.tool_name, True, operation="更新",
                                        old_version=old_copy.version, new_version=request.version)
        else:
            # 新注册
            meta = ToolMetadata(
                tool_name=request.tool_name,
                tool_type=request.tool_type,
                version=request.version,
                param_template=request.param_template,
                endpoint=request.endpoint,
                auth_method=request.auth_method,
                quota_preset=request.quota_preset,
                security_level=request.security_level,
                default_timeout_sec=request.default_timeout_sec,
                max_concurrency=request.max_concurrency,
                status=ToolStatus.ACTIVE,
                registered_at=time.time(),
                updated_at=time.time()
            )
            self._tools[request.tool_name] = meta
            self._send_register_confirm(request.tool_name, True, operation="新增",
                                        new_version=request.version)

        # 发送变更通知
        if self._publish_change_notification:
            self._publish_change_notification(ToolChangeNotification(
                change_type="注册/更新",
                tool_name=request.tool_name,
                version=request.version
            ))

        self.state = RegistryState.NORMAL_SERVICE

    def _send_register_confirm(self, tool_name: str, success: bool, operation: str = "",
                               old_version: str = "", new_version: str = "", error: str = ""):
        if self._publish_register_confirm:
            self._publish_register_confirm(ToolRegisterConfirm(
                tool_name=tool_name,
                success=success,
                operation=operation,
                old_version=old_version,
                new_version=new_version,
                error_reason=error
            ))

    # ========== 注销处理 ==========
    def _handle_unregister(self, request: ToolUnregisterRequest):
        self.state = RegistryState.UNREGISTERING

        if len(request.authorization_token) < 10:
            self._send_unregister_confirm(request.tool_name, False, "授权令牌无效")
            self.state = RegistryState.NORMAL_SERVICE
            return

        tool = self._tools.get(request.tool_name)
        if not tool:
            self._send_unregister_confirm(request.tool_name, False, "工具不存在")
            self.state = RegistryState.NORMAL_SERVICE
            return

        if request.force:
            tool.status = ToolStatus.DISABLED
        else:
            tool.status = ToolStatus.DEPRECATED

        tool.deprecated_at = time.time()
        self._deprecated_tools[request.tool_name] = tool
        del self._tools[request.tool_name]

        self._send_unregister_confirm(request.tool_name, True)
        self._log_event("TOOL_UNREGISTERED", {"tool_name": request.tool_name, "reason": request.reason})

        if self._publish_change_notification:
            self._publish_change_notification(ToolChangeNotification(
                change_type="注销",
                tool_name=request.tool_name,
                version=tool.version
            ))

        self.state = RegistryState.NORMAL_SERVICE

    def _send_unregister_confirm(self, tool_name: str, success: bool, error: str = ""):
        if self._publish_unregister_confirm:
            self._publish_unregister_confirm(ToolUnregisterConfirm(
                tool_name=tool_name,
                success=success,
                error_reason=error
            ))

    # ========== 预置工具 ==========
    def _load_preset_tools(self):
        presets = [
            ToolMetadata(tool_name="weather_api", tool_type=ToolType.API, version="1.0.0",
                         param_template={"city": {"type": "string", "required": True}},
                         endpoint="https://api.weather.com/v2", auth_method="API_KEY",
                         quota_preset={"api_calls": 1, "memory_mb": 10, "tokens": 50},
                         security_level=SecurityLevel.LOW, default_timeout_sec=30),
            ToolMetadata(tool_name="file_read", tool_type=ToolType.FILE, version="1.0.0",
                         param_template={"path": {"type": "string", "required": True}},
                         quota_preset={"memory_mb": 5, "storage_kb": 10},
                         security_level=SecurityLevel.LOW, default_timeout_sec=10),
            ToolMetadata(tool_name="python_exec", tool_type=ToolType.CODE, version="1.0.0",
                         param_template={"code": {"type": "string", "required": True}},
                         quota_preset={"memory_mb": 128, "api_calls": 1},
                         security_level=SecurityLevel.MEDIUM, default_timeout_sec=30),
        ]
        for tool in presets:
            self._tools[tool.tool_name] = tool

    # ========== 查询接口（供其他模块同步调用） ==========
    def get_tool(self, tool_name: str) -> Optional[ToolMetadata]:
        return self._tools.get(tool_name)

    def get_all_tools(self) -> List[ToolMetadata]:
        return list(self._tools.values())

    def get_tools_by_type(self, tool_type: ToolType) -> List[ToolMetadata]:
        return [t for t in self._tools.values() if t.tool_type == tool_type]

    def get_param_template(self, tool_name: str) -> Optional[Dict[str, Any]]:
        tool = self._tools.get(tool_name)
        return tool.param_template if tool else None

    def get_quota_preset(self, tool_name: str) -> Optional[Dict[str, Any]]:
        tool = self._tools.get(tool_name)
        return tool.quota_preset if tool else None

    # ========== 辅助 ==========
    def get_state(self) -> RegistryState:
        return self.state

    def emergency_shutdown(self):
        self.state = RegistryState.SYSTEM_PAUSED
        print(f"[{self.module_id}] 紧急熔断")

    def _log_event(self, event_type: str, details: Dict[str, Any]):
        entry = {
            "log_id": f"log-{uuid.uuid4().hex[:8]}",
            "event_type": event_type,
            "source_module": self.module_id,
            "details": details,
            "timestamp": time.time()
        }
        self._pending_logs.append(entry)
        if self._publish_event_log:
            self._publish_event_log(entry)

    def collect_pending_logs(self) -> List[Dict[str, Any]]:
        logs = self._pending_logs.copy()
        self._pending_logs.clear()
        return logs


# ========== 演示与测试 ==========
def print_separator(title: str):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def demo_main():
    print("=" * 70)
    print("  Agent-mcc-exec 工具注册中心 (ag-mcc-04) 演示")
    print("=" * 70)

    registry = ToolRegistry()

    print_separator("STEP 1: 查询已有工具")
    registry.set_tool_request_query(lambda: ToolQueryRequest(
        requester_module="ag-mcc-01", query_type="single", tool_name="weather_api"
    ))
    registry.run_registry_cycle()

    print_separator("STEP 2: 注册新工具")
    registry.set_register_request_query(lambda: ToolRegisterRequest(
        tool_name="new_search", tool_type=ToolType.API, version="1.0.0",
        param_template={"query": {"type": "string"}},
        authorization_token="valid-admin-token-12345"
    ))
    registry.run_registry_cycle()
    print(f"  工具总数: {len(registry._tools)}")

    print_separator("STEP 3: 注销工具")
    registry.set_unregister_request_query(lambda: ToolUnregisterRequest(
        tool_name="new_search", reason="已废弃", authorization_token="valid-admin-token-12345"
    ))
    registry.run_registry_cycle()
    print(f"  工具总数: {len(registry._tools)}")

    print("\n✅ 工具注册中心演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("ag-mcc-04 工具注册中心 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        def setup_registry():
            return ToolRegistry()

        # TC-MCC-04-01: 查询已有工具
        print("\n[TC-MCC-04-01] 查询已有工具")
        try:
            r = setup_registry()
            tool = r.get_tool("weather_api")
            assert tool is not None
            assert tool.tool_type == ToolType.API
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-04-02: 注册新工具
        print("\n[TC-MCC-04-02] 注册新工具")
        try:
            r = setup_registry()
            r.set_register_request_query(lambda: ToolRegisterRequest(
                tool_name="test_tool", tool_type=ToolType.API, version="1.0.0",
                authorization_token="valid-token-1234567890"
            ))
            r.run_registry_cycle()
            assert "test_tool" in r._tools
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-04-03: 版本号不升反降拒绝
        print("\n[TC-MCC-04-03] 版本号不升反降拒绝")
        try:
            r = setup_registry()
            # weather_api 已有版本 1.0.0
            r.set_register_request_query(lambda: ToolRegisterRequest(
                tool_name="weather_api", tool_type=ToolType.API, version="0.9.0",
                authorization_token="valid-token-1234567890"
            ))
            r.run_registry_cycle()
            # 版本未变
            assert r._tools["weather_api"].version == "1.0.0"
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-04-04: 注销工具
        print("\n[TC-MCC-04-04] 注销工具")
        try:
            r = setup_registry()
            r.set_unregister_request_query(lambda: ToolUnregisterRequest(
                tool_name="file_read", reason="测试", authorization_token="valid-token-1234567890"
            ))
            r.run_registry_cycle()
            assert "file_read" not in r._tools
            assert "file_read" in r._deprecated_tools
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-04-05: 授权令牌无效拒绝注册
        print("\n[TC-MCC-04-05] 授权令牌无效拒绝注册")
        try:
            r = setup_registry()
            r.set_register_request_query(lambda: ToolRegisterRequest(
                tool_name="hack_tool", tool_type=ToolType.API, version="1.0.0",
                authorization_token="short"
            ))
            r.run_registry_cycle()
            assert "hack_tool" not in r._tools
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-04-06: 紧急熔断
        print("\n[TC-MCC-04-06] 紧急熔断")
        try:
            r = setup_registry()
            r.emergency_shutdown()
            assert r.state == RegistryState.SYSTEM_PAUSED
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        print("\n" + "=" * 60)
        print(f"测试结果: {passed} PASS, {failed} FAIL")
        print("=" * 60)
    else:
        demo_main()