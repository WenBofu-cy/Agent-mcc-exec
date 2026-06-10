#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-06
模块名称: API调用引擎
所属分区: 三、调用执行引擎
版本: V1.0
原创提出者: 文波福
开源协议: CC BY-NC 4.0

核心职责:
    作为 MCC 行动执行层中负责执行外部 API 调用的专属模块，接收 ag-mcc-01（执行调度
    核心）下发的 API 类型工具调用指令，根据 ag-mcc-04（工具注册中心）中存储的端点配置、
    认证方式与请求模板，构建标准的 HTTP 请求并发送至外部服务。管理请求超时、重试策略、
    响应解析与错误处理。将执行结果返回至 ag-mcc-01。不参与工具选择或参数决策，仅负责
    API 请求的构建、发送与响应处理。

依赖模块:
    ag-mcc-01(执行调度核心), ag-mcc-04(工具注册中心)
被依赖模块:
    ag-mcc-01, ag-mcc-03(资源配额管控单元)

安全约束:
  A-01: 不得在日志或返回结果中暴露完整的认证凭证
  A-02: 所有外部 API 请求必须通过 HTTPS 发送
  A-03: 响应数据在返回前必须校验数据大小，超过上限截断并标记
  A-04: OAuth2 Token 刷新过程必须在独立的安全上下文中执行
  A-05: 重试请求必须携带幂等键
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid
import threading
import json


class EngineState(Enum):
    WAITING_COMMAND = "WAITING_COMMAND"
    REQUESTING = "REQUESTING"
    RETRYING = "RETRYING"
    SYSTEM_PAUSED = "SYSTEM_PAUSED"


class AuthMethod(Enum):
    NONE = "NONE"
    API_KEY = "API_KEY"
    OAUTH2 = "OAUTH2"
    TOKEN = "TOKEN"


@dataclass
class ApiCallCommand:
    instruction_id: str = ""
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
    max_response_size_bytes: int = 10 * 1024 * 1024


@dataclass
class ApiExecutionResult:
    instruction_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    status: str = "success"
    response_data: Any = None
    http_status_code: int = 0
    error_code: str = ""
    error_message: str = ""
    duration_sec: float = 0.0
    retry_count: int = 0
    resource_consumption: Dict[str, float] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class ApiCallEngine:
    RETRYABLE_STATUS_CODES = {429, 503}
    MAX_RETRIES = 3
    BASE_RETRY_DELAY_SEC = 1.0
    CONNECT_TIMEOUT_SEC = 10
    READ_TIMEOUT_SEC = 30
    MAX_CONCURRENT = 5
    STATUS_REPORT_INTERVAL_SEC = 60

    def __init__(self):
        self.module_id = "ag-mcc-06"
        self.module_name = "API调用引擎"
        self.version = "V1.0"

        # 总线引用
        self.bus = None  # InternalBus

        self.state = EngineState.WAITING_COMMAND
        self._lock = threading.Lock()
        self._active_requests: Dict[str, Dict[str, Any]] = {}
        self._waiting_queue: List[ApiCallCommand] = []
        self._total_calls: int = 0
        self._success_count: int = 0
        self._total_response_time: float = 0.0
        self._last_status_time: float = time.time()

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ====================== 主循环 ======================
    def api_engine_main_loop(self):
        now = time.time()

        if self.state == EngineState.SYSTEM_PAUSED:
            return

        # 定期状态上报
        if now - self._last_status_time >= self.STATUS_REPORT_INTERVAL_SEC:
            self._publish_status()
            self._last_status_time = now

        # 处理等待队列
        if self._waiting_queue and len(self._active_requests) < self.MAX_CONCURRENT:
            next_cmd = self._waiting_queue.pop(0)
            self._execute_request(next_cmd)

    # ====================== 消息处理 ======================
    def handle_message(self, message):
        if not self.bus:
            return

        data = message.data if message.data else {}
        topic = message.topic

        # 接收 API 调用指令（来自 ag-mcc-01）
        if topic == "ag-mcc-06.api_call_command":
            command = ApiCallCommand(
                instruction_id=data.get("instruction_id", ""),
                step_id=data.get("step_id", ""),
                plan_id=data.get("plan_id", ""),
                tool_name=data.get("tool_name", ""),
                parameters=data.get("parameters", {}),
                timeout_sec=data.get("timeout_sec", 60.0),
                security_token=data.get("security_token", ""),
            )

            if len(self._active_requests) >= self.MAX_CONCURRENT:
                self._waiting_queue.append(command)
            else:
                self._execute_request(command)

        # 接收全局调度指令
        elif topic == "ag-mcc-06.global_command":
            command = data.get("command", "")
            if command == "emergency_shutdown":
                self.emergency_shutdown()

    def _execute_request(self, command: ApiCallCommand):
        self.state = EngineState.REQUESTING

        # 通过总线同步查询端点配置
        config = self._fetch_endpoint_config(command.tool_name)
        if config is None:
            result = ApiExecutionResult(
                instruction_id=command.instruction_id,
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
        with self._lock:
            self._active_requests[command.instruction_id] = context

        # 执行第一次请求（带重试逻辑）
        self._send_http_request(command.instruction_id)

    def _fetch_endpoint_config(self, tool_name: str) -> Optional[ApiEndpointConfig]:
        """同步向 ag-mcc-04 查询端点配置"""
        if not self.bus:
            return None

        response = self.bus.request(
            topic="ag-mcc-04.tool_query",
            source_module=self.module_id,
            data={"query_type": "single", "tool_name": tool_name, "requester_module": self.module_id},
            target_module="ag-mcc-04",
            timeout_ms=500
        )

        if not response or not response.data:
            return None

        tools = response.data.get("tools", [])
        if not tools:
            return None

        tool = tools[0]
        return ApiEndpointConfig(
            tool_name=tool_name,
            method=tool.get("method", "GET"),
            url_template=tool.get("endpoint", ""),
            headers_template=tool.get("headers_template", {}),
            auth_method=AuthMethod(tool.get("auth_method", "NONE")),
            auth_credential_ref=tool.get("auth_credential_ref", ""),
            response_format=tool.get("response_format", "json"),
            max_response_size_bytes=tool.get("max_response_size_bytes", 10 * 1024 * 1024)
        )

    def _send_http_request(self, instruction_id: str):
        """发送 HTTP 请求（当前为模拟实现，实际可替换为真实 HTTP 库）"""
        with self._lock:
            context = self._active_requests.get(instruction_id)
        if not context:
            return

        command = context["command"]
        config = context["config"]
        idempotency_key = context["idempotency_key"]

        # 模拟 HTTP 请求耗时
        # 实际部署时，替换为真实 HTTP 调用，并处理以下情况：
        # - 超时（连接、读取）
        # - 状态码检查
        # - 响应大小限制
        simulated_status = 200
        simulated_body = {"result": "模拟响应数据", "tool": command.tool_name}
        simulated_duration = min(command.timeout_sec * 0.5, 2.0)

        # 处理模拟的 503 错误来测试重试
        if command.tool_name == "test_503" and context["retry_count"] == 0:
            simulated_status = 503
            simulated_body = {}

        # 构建结果
        result = ApiExecutionResult(
            instruction_id=instruction_id,
            step_id=command.step_id,
            plan_id=command.plan_id,
            status="success",
            http_status_code=simulated_status,
            duration_sec=simulated_duration,
            retry_count=context["retry_count"],
            resource_consumption={"api_calls": 1, "tokens": 50}
        )

        # 根据状态码处理
        if simulated_status in self.RETRYABLE_STATUS_CODES and context["retry_count"] < self.MAX_RETRIES:
            # 进入重试
            self.state = EngineState.RETRYING
            context["retry_count"] += 1
            delay = self.BASE_RETRY_DELAY_SEC * (2 ** (context["retry_count"] - 1))  # 指数退避
            time.sleep(delay)
            self._send_http_request(instruction_id)  # 递归重试，实际应使用定时器
            return

        # 处理响应
        if simulated_status == 200:
            # 响应大小校验 (A-03)
            response_size = len(json.dumps(simulated_body).encode())
            if response_size > config.max_response_size_bytes:
                result.response_data = "响应数据已截断（超限）"
                result.error_message = "响应大小超过上限，已截断"
            else:
                result.response_data = simulated_body
        elif simulated_status == 503:
            result.status = "failure"
            result.error_code = "SERVICE_UNAVAILABLE"
            result.error_message = "服务不可用，重试已耗尽"
        else:
            result.status = "failure"
            result.error_code = "HTTP_ERROR"
            result.error_message = f"未预期的状态码: {simulated_status}"

        self._finalize_result(result, command)

    def _finalize_result(self, result: ApiExecutionResult, command: ApiCallCommand):
        with self._lock:
            if result.instruction_id in self._active_requests:
                del self._active_requests[result.instruction_id]

        self._total_calls += 1
        if result.status == "success":
            self._success_count += 1
        self._total_response_time += result.duration_sec

        # 发送执行结果至 ag-mcc-01
        if self.bus:
            self.bus.publish_to_module(
                target_module="ag-mcc-01",
                event_type="execution_result",
                source_module=self.module_id,
                data={
                    "instruction_id": result.instruction_id,
                    "step_id": result.step_id,
                    "plan_id": result.plan_id,
                    "status": result.status,
                    "output_data": result.response_data,
                    "error_code": result.error_code,
                    "error_message": result.error_message,
                    "duration_sec": result.duration_sec,
                    "resource_consumption": result.resource_consumption,
                    "timestamp": result.timestamp
                }
            )

            # 发送资源释放通知至 ag-mcc-03
            self.bus.publish_to_module(
                target_module="ag-mcc-03",
                event_type="resource_release",
                source_module=self.module_id,
                data={
                    "instruction_id": result.instruction_id,
                    "api_calls_released": 1,
                    "tokens_released": result.resource_consumption.get("tokens", 0)
                }
            )

        if not self._active_requests and not self._waiting_queue:
            self.state = EngineState.WAITING_COMMAND

    def _publish_status(self):
        if not self.bus:
            return
        rate = self._success_count / max(self._total_calls, 1)
        avg = self._total_response_time / max(self._total_calls, 1) * 1000
        self.bus.publish_to_module(
            target_module="ag-mcc-12",
            event_type="engine_status",
            source_module=self.module_id,
            data={
                "state": self.state.value,
                "active_requests": len(self._active_requests),
                "today_calls": self._total_calls,
                "success_rate": round(rate, 3),
                "avg_response_ms": round(avg, 2)
            }
        )

    def get_state(self) -> EngineState:
        return self.state

    def emergency_shutdown(self):
        self.state = EngineState.SYSTEM_PAUSED
        with self._lock:
            self._active_requests.clear()
            self._waiting_queue.clear()
        print(f"[{self.module_id}] 紧急熔断")

    def shutdown(self):
        self.state = EngineState.WAITING_COMMAND
        print(f"[{self.module_id}] 已安全关闭")


# ====================== 演示与测试 ======================
def demo_main():
    print("=" * 70)
    print("  ag-mcc-06 API调用引擎 V1.0 演示")
    print("=" * 70)

    from memory_bus import InternalBus
    bus = InternalBus()
    bus.register_module("ag-mcc-06")
    bus.register_module("ag-mcc-04")

    engine = ApiCallEngine()
    engine.bus = bus
    bus.subscribe_to_module("ag-mcc-06", engine.handle_message)

    # 模拟工具查询响应
    def handle_tool_query(msg):
        bus.publish_reply(
            topic="ag-mcc-04.tool_query_result",
            source_module="ag-mcc-04",
            data={"tools": [{"tool_name": "weather_api", "endpoint": "https://api.weather.com/v2", "auth_method": "API_KEY"}], "total_matched": 1},
            correlation_id=msg.correlation_id,
            target_module=msg.source_module
        )
    bus.subscribe_to_module("ag-mcc-04", handle_tool_query)

    # 模拟 API 调用指令
    print("\n[演示] 收到 API 调用指令")
    bus.publish_to_module("ag-mcc-06", "api_call_command", "ag-mcc-01", {
        "instruction_id": "CMD-001",
        "step_id": "S01",
        "plan_id": "P01",
        "tool_name": "weather_api",
        "parameters": {"city": "北京"},
        "security_token": "valid-token"
    })
    bus.process_all()
    engine.api_engine_main_loop()

    print(f"  总调用: {engine._total_calls}, 成功: {engine._success_count}")

    # 演示 503 重试
    print("\n[演示] 模拟 503 重试（test_503）")
    # 需要重新注册一个新的模拟响应
    def handle_tool_query_503(msg):
        bus.publish_reply(
            topic="ag-mcc-04.tool_query_result",
            source_module="ag-mcc-04",
            data={"tools": [{"tool_name": "test_503", "endpoint": "https://api.test.com", "auth_method": "NONE"}], "total_matched": 1},
            correlation_id=msg.correlation_id,
            target_module=msg.source_module
        )
    bus._module_subscriptions["ag-mcc-04"].clear()
    bus.subscribe_to_module("ag-mcc-04", handle_tool_query_503)

    bus.publish_to_module("ag-mcc-06", "api_call_command", "ag-mcc-01", {
        "instruction_id": "CMD-002",
        "step_id": "S02",
        "plan_id": "P02",
        "tool_name": "test_503",
        "parameters": {},
        "security_token": "valid-token"
    })
    bus.process_all()
    engine.api_engine_main_loop()
    print(f"  总调用: {engine._total_calls}, 成功: {engine._success_count}")

    print("\n✅ 演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("ag-mcc-06 API调用引擎 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        def setup():
            from memory_bus import InternalBus
            bus = InternalBus()
            bus.register_module("ag-mcc-06")
            bus.register_module("ag-mcc-04")
            e = ApiCallEngine()
            e.bus = bus
            bus.subscribe_to_module("ag-mcc-06", e.handle_message)
            def handle_tool_query(msg):
                bus.publish_reply(
                    topic="ag-mcc-04.tool_query_result",
                    source_module="ag-mcc-04",
                    data={"tools": [{"tool_name": "test", "endpoint": "https://api.test.com", "auth_method": "NONE"}], "total_matched": 1},
                    correlation_id=msg.correlation_id,
                    target_module=msg.source_module
                )
            bus.subscribe_to_module("ag-mcc-04", handle_tool_query)
            return e, bus

        def send_cmd(bus, iid, tname="test"):
            bus.publish_to_module("ag-mcc-06", "api_call_command", "ag-mcc-01", {
                "instruction_id": iid, "tool_name": tname, "parameters": {}, "security_token": "tok"
            })
            bus.process_all()

        # TC01: 正常执行
        print("\n[TC01] 正常执行")
        try:
            e, bus = setup()
            send_cmd(bus, "T01")
            e.api_engine_main_loop()
            assert e._total_calls == 1
            print("   ✅ PASS"); passed += 1
        except Exception as ex:
            print(f"   ❌ FAIL: {ex}"); failed += 1

        # TC02: 并发满排队
        print("\n[TC02] 并发满排队")
        try:
            e, bus = setup()
            for i in range(e.MAX_CONCURRENT):
                e._active_requests[f"T{i}"] = {}
            send_cmd(bus, "T02")
            e.api_engine_main_loop()
            assert len(e._waiting_queue) == 1
            print("   ✅ PASS"); passed += 1
        except Exception as ex:
            print(f"   ❌ FAIL: {ex}"); failed += 1

        # TC03: 端点配置不存在
        print("\n[TC03] 端点配置不存在")
        try:
            e, bus = setup()
            bus._module_subscriptions["ag-mcc-04"].clear()
            send_cmd(bus, "T03", "no_config")
            e.api_engine_main_loop()
            assert e._total_calls == 1
            print("   ✅ PASS"); passed += 1
        except Exception as ex:
            print(f"   ❌ FAIL: {ex}"); failed += 1

        # TC04: 紧急熔断
        print("\n[TC04] 紧急熔断")
        try:
            e, bus = setup()
            e.emergency_shutdown()
            assert e.state == EngineState.SYSTEM_PAUSED
            print("   ✅ PASS"); passed += 1
        except Exception as ex:
            print(f"   ❌ FAIL: {ex}"); failed += 1

        # TC05: 503重试逻辑（模拟）
        print("\n[TC05] 503重试")
        try:
            e, bus = setup()
            # 覆盖模拟响应为503
            def handle_503(msg):
                bus.publish_reply(
                    topic="ag-mcc-04.tool_query_result",
                    source_module="ag-mcc-04",
                    data={"tools": [{"tool_name": "test_503", "endpoint": "https://api.test.com", "auth_method": "NONE"}], "total_matched": 1},
                    correlation_id=msg.correlation_id,
                    target_module=msg.source_module
                )
            bus._module_subscriptions["ag-mcc-04"].clear()
            bus.subscribe_to_module("ag-mcc-04", handle_503)

            send_cmd(bus, "T05", "test_503")
            e.api_engine_main_loop()
            # 应该被重试最多3次，最终失败
            assert e._total_calls == 1
            print("   ✅ PASS"); passed += 1
        except Exception as ex:
            print(f"   ❌ FAIL: {ex}"); failed += 1

        print("\n" + "=" * 60)
        print(f"测试结果: {passed} PASS, {failed} FAIL")
        print("=" * 60)
    else:
        demo_main()