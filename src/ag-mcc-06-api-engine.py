#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-06
模块名称: API调用引擎
所属分区: 三、调用执行引擎
核心职责: 作为 MCC 行动执行层中负责执行外部 API 调用的专属模块，接收 ag-mcc-01（执行调度
          核心）下发的 API 类型工具调用指令，根据 ag-mcc-04（工具注册中心）中存储的端点配置、
          认证方式与请求模板，构建标准的 HTTP 请求并发送至外部服务。管理请求超时、重试策略、
          响应解析与错误处理。将执行结果返回至 ag-mcc-01。不参与工具选择或参数决策，仅负责
          API 请求的构建、发送与响应处理。

依赖模块:
    ag-mcc-01(执行调度核心), ag-mcc-04(工具注册中心), ag-mcc-05(工具参数校验器)
被依赖模块:
    ag-mcc-01, ag-mcc-03(资源配额管控单元)

安全约束:
  A-01: 不得在日志或返回结果中暴露完整的认证凭证
  A-02: 所有外部 API 请求必须通过 HTTPS 发送
  A-03: 响应数据在返回前必须校验数据大小，超过上限截断并标记
  A-04: OAuth2 Token 刷新过程必须在独立的安全上下文中执行
  A-05: 重试请求必须携带幂等键
"""

from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid
import json


class EngineState(Enum):
    WAITING_COMMAND = "waiting_command"
    REQUESTING = "requesting"
    RETRYING = "retrying"
    SYSTEM_PAUSED = "system_paused"


class AuthMethod(Enum):
    NONE = "NONE"
    API_KEY = "API_KEY"
    OAUTH2 = "OAUTH2"
    TOKEN = "TOKEN"


@dataclass
class ApiCallCommand:
    command_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    tool_name: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    timeout_sec: float = 60.0
    security_token: str = ""
    retry_override: Optional[Dict[str, Any]] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class ApiEndpointConfig:
    tool_name: str = ""
    method: str = "GET"
    url_template: str = ""
    headers_template: Dict[str, str] = field(default_factory=dict)
    auth_method: AuthMethod = AuthMethod.NONE
    auth_credential_ref: str = ""
    response_format: str = "json"
    max_response_size_bytes: int = 10 * 1024 * 1024  # 10MB


@dataclass
class ApiExecutionResult:
    command_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    status: str = "success"  # success / failure / timeout / exception
    response_data: Any = None
    http_status_code: int = 0
    error_code: str = ""
    error_message: str = ""
    duration_sec: float = 0.0
    retry_count: int = 0
    resource_consumption: Dict[str, float] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class ResourceReleaseNotice:
    command_id: str = ""
    api_calls_released: int = 1
    tokens_released: int = 0


@dataclass
class EngineStatus:
    state: EngineState = EngineState.WAITING_COMMAND
    active_requests: int = 0
    today_calls: int = 0
    success_rate: float = 0.0
    avg_response_ms: float = 0.0


class ApiCallEngine:
    # 重试策略
    RETRYABLE_STATUS_CODES = {429, 503}
    MAX_RETRIES = 3
    BASE_RETRY_DELAY_SEC = 1.0
    # 超时
    CONNECT_TIMEOUT_SEC = 10
    READ_TIMEOUT_SEC = 30
    # 并发
    MAX_CONCURRENT = 5
    # 统计上报间隔
    STATUS_REPORT_INTERVAL_SEC = 60

    def __init__(self):
        self.module_id = "ag-mcc-06"
        self.module_name = "API调用引擎"
        self.version = "V1.0"

        self.state = EngineState.WAITING_COMMAND
        self._active_requests: Dict[str, Dict[str, Any]] = {}
        self._waiting_queue: List[ApiCallCommand] = []
        self._total_calls: int = 0
        self._success_count: int = 0
        self._total_response_time: float = 0.0
        self._last_status_time: float = time.time()
        self._pending_logs: List[Dict[str, Any]] = []

        # 回调注入
        self._query_api_command = None
        self._query_endpoint_config = None

        self._publish_execution_result = None
        self._publish_resource_release = None
        self._publish_status_report = None
        self._publish_event_log = None

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ========== 回调注入 ==========
    def set_api_command_query(self, callback: Callable[[], Optional[ApiCallCommand]]):
        self._query_api_command = callback

    def set_endpoint_config_query(self, callback: Callable[[str], Optional[ApiEndpointConfig]]):
        self._query_endpoint_config = callback

    def set_execution_result_publisher(self, callback: Callable[[ApiExecutionResult], None]):
        self._publish_execution_result = callback

    def set_resource_release_publisher(self, callback: Callable[[ResourceReleaseNotice], None]):
        self._publish_resource_release = callback

    def set_status_report_publisher(self, callback: Callable[[EngineStatus], None]):
        self._publish_status_report = callback

    def set_event_log_publisher(self, callback: Callable[[Dict[str, Any]], None]):
        self._publish_event_log = callback

    # ========== 主循环 ==========
    def run_engine_cycle(self) -> Optional[ApiExecutionResult]:
        now = time.time()

        if self.state == EngineState.SYSTEM_PAUSED:
            return None

        # 定期状态上报
        if now - self._last_status_time >= self.STATUS_REPORT_INTERVAL_SEC:
            self._publish_status()
            self._last_status_time = now

        # 处理等待队列
        if self._waiting_queue and len(self._active_requests) < self.MAX_CONCURRENT:
            next_cmd = self._waiting_queue.pop(0)
            self._execute_request(next_cmd)

        # 接收新指令
        command = self._query_api_command() if self._query_api_command else None
        if command is None:
            return None

        if len(self._active_requests) >= self.MAX_CONCURRENT:
            self._waiting_queue.append(command)
            return None

        self._execute_request(command)
        return None

    def _execute_request(self, command: ApiCallCommand):
        self.state = EngineState.REQUESTING

        # 获取端点配置
        config = self._query_endpoint_config(command.tool_name) if self._query_endpoint_config else None
        if config is None:
            result = ApiExecutionResult(
                command_id=command.command_id,
                step_id=command.step_id,
                plan_id=command.plan_id,
                status="failure",
                error_code="ENDPOINT_NOT_FOUND",
                error_message=f"API端点配置不存在: {command.tool_name}"
            )
            self._finalize_result(result, command)
            return

        # 构建请求上下文
        context = {
            "command": command,
            "config": config,
            "retry_count": 0,
            "start_time": time.time(),
            "idempotency_key": str(uuid.uuid4())
        }
        self._active_requests[command.command_id] = context

        # 模拟 HTTP 请求（实际实现会发送网络请求）
        self._simulate_http_call(command.command_id)

    def _simulate_http_call(self, command_id: str):
        """模拟 HTTP 请求，实际实现会替换为真实的网络调用"""
        context = self._active_requests.get(command_id)
        if not context:
            return

        command = context["command"]
        config = context["config"]

        # 模拟成功响应
        start_time = context["start_time"]
        duration = min(command.timeout_sec * 0.5, 2.0)  # 模拟耗时
        time.sleep(0.01)  # 实际中这是异步的

        result = ApiExecutionResult(
            command_id=command_id,
            step_id=command.step_id,
            plan_id=command.plan_id,
            status="success",
            response_data={"result": "模拟响应数据", "tool": command.tool_name},
            http_status_code=200,
            duration_sec=duration,
            retry_count=context["retry_count"],
            resource_consumption={"api_calls": 1, "tokens": 50}
        )
        self._finalize_result(result, command)

    def _finalize_result(self, result: ApiExecutionResult, command: ApiCallCommand):
        """完成请求并清理"""
        if result.command_id in self._active_requests:
            del self._active_requests[result.command_id]

        self._total_calls += 1
        if result.status == "success":
            self._success_count += 1
        self._total_response_time += result.duration_sec

        # 发送执行结果
        if self._publish_execution_result:
            self._publish_execution_result(result)

        # 发送资源释放通知
        if self._publish_resource_release:
            self._publish_resource_release(ResourceReleaseNotice(
                command_id=result.command_id,
                api_calls_released=1,
                tokens_released=result.resource_consumption.get("tokens", 0)
            ))

        if not self._active_requests and not self._waiting_queue:
            self.state = EngineState.WAITING_COMMAND

    # ========== 辅助 ==========
    def _publish_status(self):
        if self._publish_status_report:
            rate = self._success_count / max(self._total_calls, 1)
            avg = self._total_response_time / max(self._total_calls, 1) * 1000
            self._publish_status_report(EngineStatus(
                state=self.state,
                active_requests=len(self._active_requests),
                today_calls=self._total_calls,
                success_rate=round(rate, 3),
                avg_response_ms=round(avg, 2)
            ))

    def get_state(self) -> EngineState:
        return self.state

    def emergency_shutdown(self):
        self.state = EngineState.SYSTEM_PAUSED
        self._active_requests.clear()
        self._waiting_queue.clear()
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
    print("  Agent-mcc-exec API调用引擎 (ag-mcc-06) 演示")
    print("=" * 70)

    engine = ApiCallEngine()
    engine.set_endpoint_config_query(lambda tool_name: ApiEndpointConfig(
        tool_name=tool_name, method="GET", url_template=f"https://api.{tool_name}.com",
        auth_method=AuthMethod.API_KEY
    ))

    print_separator("STEP 1: 正常 API 调用")
    engine.set_api_command_query(lambda: ApiCallCommand(
        command_id="CMD-001", step_id="S01", plan_id="P01",
        tool_name="weather_api", parameters={"city": "北京"}
    ))
    engine.run_engine_cycle()

    print_separator("STEP 2: 并发满时排队")
    engine._active_requests = {f"T{i}": {"command": None, "config": None, "retry_count": 0, "start_time": time.time()} for i in range(engine.MAX_CONCURRENT)}
    engine.set_api_command_query(lambda: ApiCallCommand(
        command_id="CMD-002", tool_name="search_engine", parameters={"q": "test"}
    ))
    engine.run_engine_cycle()
    print(f"  等待队列: {len(engine._waiting_queue)}")

    print_separator("STEP 3: 端点配置不存在")
    engine._active_requests.clear()
    engine._waiting_queue.clear()
    engine.set_endpoint_config_query(lambda tool_name: None)
    engine.set_api_command_query(lambda: ApiCallCommand(
        command_id="CMD-003", tool_name="unknown_tool", parameters={}
    ))
    engine.run_engine_cycle()

    print("\n✅ API调用引擎演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("ag-mcc-06 API调用引擎 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        def setup_engine():
            e = ApiCallEngine()
            e.set_endpoint_config_query(lambda tool_name: ApiEndpointConfig(
                tool_name=tool_name, method="GET", url_template=f"https://api.{tool_name}.com",
                auth_method=AuthMethod.API_KEY
            ))
            return e

        # TC-MCC-06-01: 正常接收并执行API指令
        print("\n[TC-MCC-06-01] 正常接收并执行API指令")
        try:
            e = setup_engine()
            e.set_api_command_query(lambda: ApiCallCommand(
                command_id="T01", tool_name="test", parameters={}
            ))
            e.run_engine_cycle()
            assert e._total_calls == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as ex:
            print(f"   ❌ FAIL: {ex}")
            failed += 1

        # TC-MCC-06-02: 并发满时排队
        print("\n[TC-MCC-06-02] 并发满时排队")
        try:
            e = setup_engine()
            e._active_requests = {f"T{i}": {} for i in range(e.MAX_CONCURRENT)}
            e.set_api_command_query(lambda: ApiCallCommand(
                command_id="T02", tool_name="extra", parameters={}
            ))
            e.run_engine_cycle()
            assert len(e._waiting_queue) == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as ex:
            print(f"   ❌ FAIL: {ex}")
            failed += 1

        # TC-MCC-06-03: 端点配置不存在返回失败
        print("\n[TC-MCC-06-03] 端点配置不存在返回失败")
        try:
            e = setup_engine()
            e.set_endpoint_config_query(lambda tool_name: None)
            e.set_api_command_query(lambda: ApiCallCommand(
                command_id="T03", tool_name="no_config", parameters={}
            ))
            e.run_engine_cycle()
            assert e._total_calls == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as ex:
            print(f"   ❌ FAIL: {ex}")
            failed += 1

        # TC-MCC-06-04: 成功结果统计更新
        print("\n[TC-MCC-06-04] 成功结果统计更新")
        try:
            e = setup_engine()
            e.set_api_command_query(lambda: ApiCallCommand(
                command_id="T04", tool_name="test", parameters={}
            ))
            e.run_engine_cycle()
            assert e._success_count == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as ex:
            print(f"   ❌ FAIL: {ex}")
            failed += 1

        # TC-MCC-06-05: 队列中的任务在空闲时自动分发
        print("\n[TC-MCC-06-05] 队列中的任务自动分发")
        try:
            e = setup_engine()
            e._waiting_queue = [ApiCallCommand(command_id="Q01", tool_name="queued", parameters={})]
            e.run_engine_cycle()
            assert len(e._active_requests) == 1
            assert len(e._waiting_queue) == 0
            print("   ✅ PASS")
            passed += 1
        except Exception as ex:
            print(f"   ❌ FAIL: {ex}")
            failed += 1

        # TC-MCC-06-06: 紧急熔断
        print("\n[TC-MCC-06-06] 紧急熔断")
        try:
            e = setup_engine()
            e.emergency_shutdown()
            assert e.state == EngineState.SYSTEM_PAUSED
            assert len(e._waiting_queue) == 0
            assert len(e._active_requests) == 0
            print("   ✅ PASS")
            passed += 1
        except Exception as ex:
            print(f"   ❌ FAIL: {ex}")
            failed += 1

        print("\n" + "=" * 60)
        print(f"测试结果: {passed} PASS, {failed} FAIL")
        print("=" * 60)
    else:
        demo_main()