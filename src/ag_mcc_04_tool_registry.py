#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-04
模块名称: 工具注册中心
所属分区: 二、工具管理集群
版本: V1.0
原创提出者: 文波福
开源协议: CC BY-NC 4.0

核心职责:
    作为 MCC 行动执行层的工具元数据中心，维护所有可用工具的全生命周期注册信息。
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
  R-02: 安全等级为 CRITICAL 的工具不可通过运行时注册接口动态注册，仅允许预置或系统级更新
  R-03: 工具元数据中不得存储任何认证密钥或敏感凭证
  R-04: 工具注销后，其元数据不得立即删除，应保留至少 30 天供审计追溯
  R-05: 工具版本更新时必须保留至少上一个版本的元数据快照，支持紧急回滚

约束与异常处理补充:
  - 注销请求指定了仍有活跃任务的工具 → 默认拒绝注销，除非请求中标记为“强制注销”
"""

import time
import threading
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import copy
import uuid


class RegistryState(Enum):
    NORMAL_SERVICE = "NORMAL_SERVICE"
    REGISTERING = "REGISTERING"
    UNREGISTERING = "UNREGISTERING"
    SYSTEM_PAUSED = "SYSTEM_PAUSED"


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
    """工具元数据（严格按照SPEC定义）"""
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


class ToolRegistry:
    # 工具元数据保留期限（秒）—— 30 天
    RETENTION_SEC = 30 * 86400

    def __init__(self):
        self.module_id = "ag-mcc-04"
        self.module_name = "工具注册中心"
        self.version = "V1.0"

        # 总线引用（由主入口注入）
        self.bus = None                 # InternalBus

        self.state = RegistryState.NORMAL_SERVICE
        self._lock = threading.Lock()
        self._tools: Dict[str, ToolMetadata] = {}
        self._version_history: Dict[str, List[ToolMetadata]] = {}
        self._deprecated_tools: Dict[str, ToolMetadata] = {}
        
        # 新增：活跃任务引用计数（工具名 -> 正在执行的任务数）
        self._active_tasks: Dict[str, int] = {}

        # 预置工具
        self._load_preset_tools()

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成, 已注册工具数={len(self._tools)}")

    # ====================== 主循环（SPEC 定义的标准方法名） ======================
    def tool_registry_main_loop(self):
        """执行一个主循环周期"""
        with self._lock:
            if self.state == RegistryState.SYSTEM_PAUSED:
                return

        # 定期清理过期注销工具
        self._cleanup_expired_tools()

    # ====================== 消息处理（InternalBus） ======================
    def handle_message(self, message):
        """处理来自 InternalBus 的消息"""
        if not self.bus:
            return

        data = message.data if message.data else {}
        topic = message.topic

        # 接收工具查询请求
        if topic == "ag-mcc-04.tool_query":
            query_type = data.get("query_type", "single")
            tool_name = data.get("tool_name", "")
            tool_type_str = data.get("tool_type", "")
            
            if query_type == "single" and tool_name:
                result = self.get_tool(tool_name)
                tools = [result] if result else []
            elif query_type == "by_type" and tool_type_str:
                try:
                    ttype = ToolType(tool_type_str)
                    tools = self.get_tools_by_type(ttype)
                except ValueError:
                    tools = []
            else:
                tools = self.get_all_tools()

            self.bus.publish_to_module(
                target_module=data.get("requester_module", ""),
                event_type="tool_query_result",
                source_module=self.module_id,
                data={
                    "tools": [self._metadata_to_dict(t) for t in tools],
                    "total_matched": len(tools)
                }
            )

        # 接收工具注册请求
        elif topic == "ag-mcc-04.tool_register":
            request_data = {
                "tool_name": data.get("tool_name", ""),
                "tool_type": data.get("tool_type", "API"),
                "version": data.get("version", "1.0.0"),
                "param_template": data.get("param_template", {}),
                "endpoint": data.get("endpoint", ""),
                "auth_method": data.get("auth_method", "NONE"),
                "quota_preset": data.get("quota_preset", {}),
                "security_level": data.get("security_level", "LOW"),
                "default_timeout_sec": data.get("default_timeout_sec", 30),
                "max_concurrency": data.get("max_concurrency", 5),
                "authorization_token": data.get("authorization_token", "")
            }
            self._handle_register(request_data)

        # 接收工具注销请求
        elif topic == "ag-mcc-04.tool_unregister":
            request_data = {
                "tool_name": data.get("tool_name", ""),
                "reason": data.get("reason", ""),
                "force": data.get("force", False),
                "authorization_token": data.get("authorization_token", "")
            }
            self._handle_unregister(request_data)

        # 接收工具回滚请求
        elif topic == "ag-mcc-04.tool_rollback":
            tool_name = data.get("tool_name", "")
            self._handle_rollback(tool_name)

        # 新增：任务开始通知 (ag-mcc-01 分发任务后发送)
        elif topic == "ag-mcc-04.task_start":
            tool_name = data.get("tool_name", "")
            if tool_name:
                with self._lock:
                    self._active_tasks[tool_name] = self._active_tasks.get(tool_name, 0) + 1

        # 新增：任务结束通知 (ag-mcc-01 回收任务后发送)
        elif topic == "ag-mcc-04.task_end":
            tool_name = data.get("tool_name", "")
            if tool_name:
                with self._lock:
                    count = self._active_tasks.get(tool_name, 0)
                    if count > 1:
                        self._active_tasks[tool_name] = count - 1
                    elif count == 1:
                        del self._active_tasks[tool_name]

        # 接收全局调度指令（来自 ag-mcc-01）
        elif topic == "ag-mcc-04.global_command":
            command = data.get("command", "")
            if command == "emergency_shutdown":
                self.emergency_shutdown()

    # ====================== 注册处理 ======================
    def _handle_register(self, request: Dict[str, Any]):
        with self._lock:
            self.state = RegistryState.REGISTERING

        tool_name = request.get("tool_name", "")
        authorization_token = request.get("authorization_token", "")

        # 校验授权令牌
        if not self._is_valid_token(authorization_token):
            self._send_register_confirm(tool_name, False, error="授权令牌无效")
            with self._lock:
                self.state = RegistryState.NORMAL_SERVICE
            return

        # 校验必填字段
        if not tool_name:
            self._send_register_confirm("", False, error="缺少工具名称")
            with self._lock:
                self.state = RegistryState.NORMAL_SERVICE
            return

        # 安全等级限制 (R-02)
        security_level = SecurityLevel(request.get("security_level", "LOW"))
        if security_level == SecurityLevel.CRITICAL:
            self._send_register_confirm(tool_name, False, error="CRITICAL 安全等级工具禁止运行时注册，仅允许预置或系统级更新")
            with self._lock:
                self.state = RegistryState.NORMAL_SERVICE
            return

        new_version = request.get("version", "1.0.0")
        existing = self._tools.get(tool_name)

        if existing:
            # 版本号校验
            if new_version <= existing.version:
                self._send_register_confirm(tool_name, False, error=f"版本号必须高于当前版本 {existing.version}")
                with self._lock:
                    self.state = RegistryState.NORMAL_SERVICE
                return

            # 备份旧版本 (R-05)
            old_copy = copy.deepcopy(existing)
            with self._lock:
                if tool_name not in self._version_history:
                    self._version_history[tool_name] = []
                self._version_history[tool_name].append(old_copy)

                # 更新元数据
                existing.version = new_version
                existing.param_template = request.get("param_template", {})
                existing.endpoint = request.get("endpoint", "")
                existing.auth_method = request.get("auth_method", "NONE")
                existing.quota_preset = request.get("quota_preset", {})
                existing.security_level = security_level
                existing.default_timeout_sec = request.get("default_timeout_sec", 30)
                existing.max_concurrency = request.get("max_concurrency", 5)
                existing.status = ToolStatus.ACTIVE
                existing.updated_at = time.time()

            self._send_register_confirm(tool_name, True, operation="更新",
                                        old_version=old_copy.version, new_version=new_version)
        else:
            # 新注册
            meta = ToolMetadata(
                tool_name=tool_name,
                tool_type=ToolType(request.get("tool_type", "API")),
                version=new_version,
                param_template=request.get("param_template", {}),
                endpoint=request.get("endpoint", ""),
                auth_method=request.get("auth_method", "NONE"),
                quota_preset=request.get("quota_preset", {}),
                security_level=security_level,
                default_timeout_sec=request.get("default_timeout_sec", 30),
                max_concurrency=request.get("max_concurrency", 5),
                status=ToolStatus.ACTIVE,
                registered_at=time.time(),
                updated_at=time.time()
            )
            with self._lock:
                self._tools[tool_name] = meta
            self._send_register_confirm(tool_name, True, operation="新增", new_version=new_version)

        # 发送变更通知
        self._publish_change_notification("注册/更新", tool_name, new_version)
        with self._lock:
            self.state = RegistryState.NORMAL_SERVICE

    def _send_register_confirm(self, tool_name: str, success: bool, operation: str = "",
                               old_version: str = "", new_version: str = "", error: str = ""):
        if not self.bus:
            return
        self.bus.publish_to_module(
            target_module="ag-mcc-01",
            event_type="tool_register_confirm",
            source_module=self.module_id,
            data={
                "tool_name": tool_name,
                "success": success,
                "operation": operation,
                "old_version": old_version,
                "new_version": new_version,
                "error_reason": error
            }
        )

    # ====================== 注销处理 ======================
    def _handle_unregister(self, request: Dict[str, Any]):
        with self._lock:
            self.state = RegistryState.UNREGISTERING

        tool_name = request.get("tool_name", "")
        authorization_token = request.get("authorization_token", "")

        if not self._is_valid_token(authorization_token):
            self._send_unregister_confirm(tool_name, False, "授权令牌无效")
            with self._lock:
                self.state = RegistryState.NORMAL_SERVICE
            return

        with self._lock:
            tool = self._tools.get(tool_name)
            if not tool:
                self._send_unregister_confirm(tool_name, False, "工具不存在")
                self.state = RegistryState.NORMAL_SERVICE
                return

            # 活跃任务检查（新增）
            active_tasks = self._active_tasks.get(tool_name, 0)
            force = request.get("force", False)
            if active_tasks > 0 and not force:
                self._send_unregister_confirm(tool_name, False, f"工具存在 {active_tasks} 个活跃任务，无法注销。使用强制注销可忽略此检查。")
                self.state = RegistryState.NORMAL_SERVICE
                return

            if force:
                tool.status = ToolStatus.DISABLED
            else:
                tool.status = ToolStatus.DEPRECATED

            tool.deprecated_at = time.time()
            self._deprecated_tools[tool_name] = tool
            del self._tools[tool_name]
            # 清除活跃任务计数（强制注销后不再跟踪）
            self._active_tasks.pop(tool_name, None)

        self._send_unregister_confirm(tool_name, True)
        self._publish_change_notification("注销", tool_name, tool.version)

        # 记录审计日志
        if self.bus:
            self.bus.publish(
                topic="ag-mcc-12.log_event",
                source_module=self.module_id,
                data={
                    "log_id": f"log-{uuid.uuid4().hex[:8]}",
                    "event_type": "TOOL_UNREGISTERED",
                    "source_module": self.module_id,
                    "details": {"tool_name": tool_name, "reason": request.get("reason", ""), "force": force},
                    "timestamp": time.time()
                }
            )

        with self._lock:
            self.state = RegistryState.NORMAL_SERVICE

    def _send_unregister_confirm(self, tool_name: str, success: bool, error: str = ""):
        if not self.bus:
            return
        self.bus.publish_to_module(
            target_module="ag-mcc-01",
            event_type="tool_unregister_confirm",
            source_module=self.module_id,
            data={
                "tool_name": tool_name,
                "success": success,
                "error_reason": error
            }
        )

    # ====================== 回滚处理 ======================
    def _handle_rollback(self, tool_name: str):
        """处理工具版本回滚请求 (R-05)"""
        with self._lock:
            if tool_name not in self._version_history or not self._version_history[tool_name]:
                if self.bus:
                    self.bus.publish_to_module(
                        target_module="ag-mcc-01",
                        event_type="tool_rollback_confirm",
                        source_module=self.module_id,
                        data={"tool_name": tool_name, "success": False, "error_reason": "无历史版本可回滚"}
                    )
                return

            # 获取上一个版本
            previous_version = self._version_history[tool_name].pop()
            current_tool = self._tools.get(tool_name)

            if current_tool:
                # 备份当前版本到历史
                self._version_history[tool_name].append(copy.deepcopy(current_tool))

            # 恢复历史版本
            self._tools[tool_name] = previous_version
            self._tools[tool_name].status = ToolStatus.ACTIVE
            self._tools[tool_name].updated_at = time.time()

        if self.bus:
            self.bus.publish_to_module(
                target_module="ag-mcc-01",
                event_type="tool_rollback_confirm",
                source_module=self.module_id,
                data={"tool_name": tool_name, "success": True, "new_version": previous_version.version}
            )
            self._publish_change_notification("回滚", tool_name, previous_version.version)

    # ====================== 变更通知 ======================
    def _publish_change_notification(self, change_type: str, tool_name: str, version: str):
        if not self.bus:
            return
        self.bus.publish(
            topic="ag-mcc-04.tool_change",
            source_module=self.module_id,
            data={
                "change_type": change_type,
                "tool_name": tool_name,
                "version": version,
                "timestamp": time.time()
            }
        )

    # ====================== 定期清理 ======================
    def _cleanup_expired_tools(self):
        """清理超过保留期限的注销工具元数据 (R-04)"""
        now = time.time()
        expired = []
        with self._lock:
            for tool_name, tool in list(self._deprecated_tools.items()):
                if tool.deprecated_at > 0 and (now - tool.deprecated_at) >= self.RETENTION_SEC:
                    expired.append(tool_name)
            
            for tool_name in expired:
                del self._deprecated_tools[tool_name]
                # 同时清理对应的版本历史
                if tool_name in self._version_history:
                    del self._version_history[tool_name]

    # ====================== 预置工具 ======================
    def _load_preset_tools(self):
        """加载系统预置工具（不受运行时注册限制）"""
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

    # ====================== 同步查询接口（供其他模块直接调用） ======================
    def get_tool(self, tool_name: str) -> Optional[ToolMetadata]:
        with self._lock:
            return self._tools.get(tool_name)

    def get_all_tools(self) -> List[ToolMetadata]:
        with self._lock:
            return list(self._tools.values())

    def get_tools_by_type(self, tool_type: ToolType) -> List[ToolMetadata]:
        with self._lock:
            return [t for t in self._tools.values() if t.tool_type == tool_type]

    def get_param_template(self, tool_name: str) -> Optional[Dict[str, Any]]:
        tool = self.get_tool(tool_name)
        return tool.param_template if tool else None

    def get_quota_preset(self, tool_name: str) -> Optional[Dict[str, Any]]:
        tool = self.get_tool(tool_name)
        return tool.quota_preset if tool else None

    # ====================== 辅助方法 ======================
    def _is_valid_token(self, token: str) -> bool:
        """校验授权令牌"""
        return bool(token) and len(token) >= 10

    def _metadata_to_dict(self, meta: ToolMetadata) -> Dict[str, Any]:
        """将元数据对象转换为字典（用于总线传输）"""
        return {
            "tool_name": meta.tool_name,
            "tool_type": meta.tool_type.value,
            "version": meta.version,
            "param_template": meta.param_template,
            "endpoint": meta.endpoint,
            "auth_method": meta.auth_method,
            "quota_preset": meta.quota_preset,
            "security_level": meta.security_level.value,
            "default_timeout_sec": meta.default_timeout_sec,
            "max_concurrency": meta.max_concurrency,
            "status": meta.status.value,
            "registered_at": meta.registered_at,
            "updated_at": meta.updated_at
        }

    def get_state(self) -> RegistryState:
        with self._lock:
            return self.state

    def emergency_shutdown(self):
        with self._lock:
            self.state = RegistryState.SYSTEM_PAUSED
        print(f"[{self.module_id}] 紧急熔断")

    def shutdown(self):
        with self._lock:
            self.state = RegistryState.NORMAL_SERVICE
        print(f"[{self.module_id}] 已安全关闭")


# ====================== 演示与测试 ======================
def demo_main():
    print("=" * 70)
    print("  ag-mcc-04 工具注册中心 V1.0 演示")
    print("=" * 70)

    from memory_bus import InternalBus
    bus = InternalBus()
    bus.register_module("ag-mcc-04")
    bus.register_module("ag-mcc-01")
    bus.register_module("ag-mcc-12")

    registry = ToolRegistry()
    registry.bus = bus
    bus.subscribe_to_module("ag-mcc-04", registry.handle_message)

    # 模拟查询请求
    print("\n[演示] 查询已有工具")
    bus.publish_to_module("ag-mcc-04", "tool_query", "ag-mcc-01", {
        "query_type": "single",
        "tool_name": "weather_api",
        "requester_module": "ag-mcc-01"
    })
    bus.process_all()
    registry.tool_registry_main_loop()

    # 模拟任务开始
    print("\n[演示] 工具任务开始")
    bus.publish_to_module("ag-mcc-04", "task_start", "ag-mcc-01", {"tool_name": "file_read"})
    bus.process_all()
    print(f"  活跃任务数: {registry._active_tasks}")

    # 模拟注销有活跃任务的工具（默认拒绝）
    print("\n[演示] 注销有活跃任务的工具（应被拒绝）")
    bus.publish_to_module("ag-mcc-04", "tool_unregister", "ag-mcc-01", {
        "tool_name": "file_read", "reason": "测试", "authorization_token": "valid-token-1234567890"
    })
    bus.process_all()
    registry.tool_registry_main_loop()
    print(f"  工具是否仍在: {'file_read' in registry._tools}")

    # 模拟强制注销
    print("\n[演示] 强制注销有活跃任务的工具（应成功）")
    bus.publish_to_module("ag-mcc-04", "tool_unregister", "ag-mcc-01", {
        "tool_name": "file_read", "reason": "强制测试", "force": True, "authorization_token": "valid-token-1234567890"
    })
    bus.process_all()
    registry.tool_registry_main_loop()
    print(f"  工具是否仍在: {'file_read' in registry._tools}")

    print("\n✅ 演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("ag-mcc-04 工具注册中心 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        def setup():
            from memory_bus import InternalBus
            bus = InternalBus()
            bus.register_module("ag-mcc-04")
            bus.register_module("ag-mcc-01")
            bus.register_module("ag-mcc-12")
            r = ToolRegistry()
            r.bus = bus
            bus.subscribe_to_module("ag-mcc-04", r.handle_message)
            return r, bus

        # TC01: 查询已有工具
        print("\n[TC01] 查询已有工具")
        try:
            r, bus = setup()
            tool = r.get_tool("weather_api")
            assert tool is not None and tool.tool_type == ToolType.API
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC02: 注册新工具
        print("\n[TC02] 注册新工具")
        try:
            r, bus = setup()
            bus.publish_to_module("ag-mcc-04", "tool_register", "ag-mcc-01", {
                "tool_name": "test_tool", "tool_type": "API", "version": "1.0.0",
                "authorization_token": "valid-token-1234567890"
            })
            bus.process_all()
            r.tool_registry_main_loop()
            assert "test_tool" in r._tools
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC03: 版本号不升反降拒绝
        print("\n[TC03] 版本号不升反降拒绝")
        try:
            r, bus = setup()
            bus.publish_to_module("ag-mcc-04", "tool_register", "ag-mcc-01", {
                "tool_name": "weather_api", "tool_type": "API", "version": "0.9.0",
                "authorization_token": "valid-token-1234567890"
            })
            bus.process_all()
            r.tool_registry_main_loop()
            assert r._tools["weather_api"].version == "1.0.0"
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC04: 注销工具（无活跃任务）
        print("\n[TC04] 注销工具（无活跃任务）")
        try:
            r, bus = setup()
            bus.publish_to_module("ag-mcc-04", "tool_unregister", "ag-mcc-01", {
                "tool_name": "file_read", "reason": "测试", "authorization_token": "valid-token-1234567890"
            })
            bus.process_all()
            r.tool_registry_main_loop()
            assert "file_read" not in r._tools
            assert "file_read" in r._deprecated_tools
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC05: 授权令牌无效拒绝注册
        print("\n[TC05] 授权令牌无效拒绝注册")
        try:
            r, bus = setup()
            bus.publish_to_module("ag-mcc-04", "tool_register", "ag-mcc-01", {
                "tool_name": "hack_tool", "tool_type": "API", "version": "1.0.0",
                "authorization_token": "short"
            })
            bus.process_all()
            r.tool_registry_main_loop()
            assert "hack_tool" not in r._tools
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC06: 注销时存在活跃任务，默认拒绝
        print("\n[TC06] 注销时存在活跃任务，默认拒绝")
        try:
            r, bus = setup()
            # 模拟任务开始
            bus.publish_to_module("ag-mcc-04", "task_start", "ag-mcc-01", {"tool_name": "file_read"})
            bus.process_all()
            # 尝试注销
            bus.publish_to_module("ag-mcc-04", "tool_unregister", "ag-mcc-01", {
                "tool_name": "file_read", "reason": "测试", "authorization_token": "valid-token-1234567890"
            })
            bus.process_all()
            r.tool_registry_main_loop()
            # 应该仍然在
            assert "file_read" in r._tools
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC07: 强制注销（活跃任务存在）
        print("\n[TC07] 强制注销（活跃任务存在）")
        try:
            r, bus = setup()
            bus.publish_to_module("ag-mcc-04", "task_start", "ag-mcc-01", {"tool_name": "file_read"})
            bus.process_all()
            bus.publish_to_module("ag-mcc-04", "tool_unregister", "ag-mcc-01", {
                "tool_name": "file_read", "reason": "强制测试", "force": True, "authorization_token": "valid-token-1234567890"
            })
            bus.process_all()
            r.tool_registry_main_loop()
            assert "file_read" not in r._tools
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC08: 版本回滚
        print("\n[TC08] 版本回滚")
        try:
            r, bus = setup()
            bus.publish_to_module("ag-mcc-04", "tool_register", "ag-mcc-01", {
                "tool_name": "rollback_test", "tool_type": "API", "version": "1.0.0",
                "authorization_token": "valid-token-1234567890"
            })
            bus.process_all()
            bus.publish_to_module("ag-mcc-04", "tool_register", "ag-mcc-01", {
                "tool_name": "rollback_test", "tool_type": "API", "version": "2.0.0",
                "authorization_token": "valid-token-1234567890"
            })
            bus.process_all()
            bus.publish_to_module("ag-mcc-04", "tool_rollback", "ag-mcc-01", {
                "tool_name": "rollback_test"
            })
            bus.process_all()
            r.tool_registry_main_loop()
            assert r.get_tool("rollback_test").version == "1.0.0"
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        print("\n" + "=" * 60)
        print(f"测试结果: {passed} PASS, {failed} FAIL")
        print("=" * 60)
    else:
        demo_main()