#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-01
模块名称: 执行调度核心
所属分区: 一、执行中枢调度
版本: V1.0
原创提出者: 文波福
开源协议: CC BY-NC 4.0

核心职责:
    作为 Agent-mcc-exec 行动执行层的总调度入口，接收 ECC 认知大脑（通过
    CerebellumBus）下发的工具调用指令，统一分发至各执行模块（API调用引擎、
    代码执行沙箱、文件操作执行器等）。汇总各执行模块返回的结果，形成结构化
    闭环回执上报至 ECC。管理执行超时、并发控制与执行优先级。不参与任何任务
    决策，仅负责任务指令的接收、分发与结果汇总。

依赖模块:
    ag-ecc-12 (资源调度模块，下发工具调用指令)
    ag-mcc-02 (工具超时管理器)
    ag-mcc-04 (工具注册中心)
    ag-mcc-06 (API调用引擎)
    ag-mcc-07 (代码执行沙箱)
    ag-mcc-08 (文件操作执行器)

被依赖模块:
    ag-ecc-12 (接收执行回执)
    ag-mcc-02~12 (接收调度指令)

安全约束:
    X-01: 本模块为 MCC 行动执行层的唯一入口，所有来自 ECC 的指令必须经本模块接收与路由
    X-02: 本模块仅负责任务分发与结果汇总，不参与任何工具选择或参数决策
    X-03: 所有指令必须校验来源合法性，拒绝未携带有效安全令牌的指令
    X-04: 执行超时后自动中断并上报，不得无限期等待
"""

import time
import uuid
import threading
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


# ====================== 状态定义 ======================
class ExecutorState(Enum):
    IDLE = "IDLE"
    DISPATCHING = "DISPATCHING"
    WAITING_RESULTS = "WAITING_RESULTS"
    SYSTEM_PAUSED = "SYSTEM_PAUSED"


# ====================== 优先级常量（SPEC 对齐） ======================
PRIORITY_CRITICAL = "CRITICAL"
PRIORITY_HIGH = "HIGH"
PRIORITY_NORMAL = "NORMAL"
PRIORITY_LOW = "LOW"

PRIORITY_ORDER = {
    PRIORITY_CRITICAL: 0,
    PRIORITY_HIGH: 1,
    PRIORITY_NORMAL: 2,
    PRIORITY_LOW: 3,
}


# ====================== 数据结构 ======================
@dataclass
class ToolCallCommand:
    """工具调用指令（从 ECC 下发）"""
    instruction_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    tool_name: str = ""
    tool_type: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: str = PRIORITY_NORMAL
    timeout_sec: float = 60.0
    security_token: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class ExecutionResult:
    """执行回执（上报 ECC）"""
    instruction_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    status: str = "success"
    output_data: Any = None
    error_code: str = ""
    error_message: str = ""
    duration_sec: float = 0.0
    resource_consumption: Dict[str, float] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class ExecutionStatus:
    """执行状态（周期性上报）"""
    state: str = "IDLE"
    active_tasks: int = 0
    queue_depth: int = 0
    total_executed: int = 0
    success_rate: float = 0.0


class ExecutionCore:
    """
    MCC 行动执行层 执行调度核心 V1.0
    通过 CerebellumBus 接收 ECC 指令，通过 InternalBus 分发至执行模块
    """
    
    # 最大并发执行数
    MAX_CONCURRENT = 10
    # 队列最大长度
    MAX_QUEUE_SIZE = 100
    # 单任务最大超时（秒）
    MAX_TASK_TIMEOUT = 300
    # 状态上报间隔（秒）
    STATUS_REPORT_INTERVAL_SEC = 30

    def __init__(self):
        self.module_id = "ag-mcc-01"
        self.module_name = "执行调度核心"
        self.version = "V1.0"

        # 总线引用（由 agent_mcc_exec.py 注入）
        self.bus = None          # InternalBus（MCC 内部通信）
        self.external_bus = None  # CerebellumBus（与 ECC 通信）

        # 状态
        self.state: ExecutorState = ExecutorState.IDLE
        self._lock = threading.Lock()

        # 活跃任务表
        self._active_tasks: Dict[str, ToolCallCommand] = {}
        self._task_start_times: Dict[str, float] = {}

        # 指令队列（支持优先级排序）
        self._queue: List[ToolCallCommand] = []

        # 统计
        self._total_executed: int = 0
        self._success_count: int = 0
        self._last_status_time: float = time.time()

        # 待回传结果（已完成但尚未上报的任务）
        self._completed_results: Dict[str, ExecutionResult] = {}

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ====================== 主循环（SPEC 定义的标准方法名） ======================
    def execution_core_main_loop(self):
        """执行一个主循环周期"""
        if self.state == ExecutorState.SYSTEM_PAUSED:
            return

        now = time.time()

        # 1. 定期状态上报
        if now - self._last_status_time >= self.STATUS_REPORT_INTERVAL_SEC:
            self._publish_status()
            self._last_status_time = now

        # 2. 检查超时任务
        self._check_timeouts(now)

        # 3. 从队列中取下一个任务（如果并发数允许）
        if self._queue and len(self._active_tasks) < self.MAX_CONCURRENT:
            # 按优先级排序（高优先级的先出队）
            self._queue.sort(key=lambda c: PRIORITY_ORDER.get(c.priority, 2))
            next_cmd = self._queue.pop(0)
            self._dispatch_command(next_cmd)

        # 4. 如果所有任务完成且队列为空，恢复 IDLE
        if not self._active_tasks and not self._queue:
            if self.state == ExecutorState.WAITING_RESULTS:
                self.state = ExecutorState.IDLE

    # ====================== 外部指令接收（CerebellumBus 回调） ======================
    def handle_cerebellum_bus_message(self, message):
        """
        处理来自 CerebellumBus 的消息（由 agent_mcc_exec.py 绑定）
        预期接收消息：
            - topic: ag-mcc-01.tool_call_command
            - data: ToolCallCommand 结构
        """
        if not self.external_bus or not self.bus:
            return  # 总线未注入，忽略

        data = message.data
        if not data:
            return

        # 解析指令
        command = ToolCallCommand(
            instruction_id=data.get("instruction_id", ""),
            step_id=data.get("step_id", ""),
            plan_id=data.get("plan_id", ""),
            tool_name=data.get("tool_name", ""),
            tool_type=data.get("tool_type", ""),
            parameters=data.get("parameters", {}),
            priority=data.get("priority", PRIORITY_NORMAL),
            timeout_sec=data.get("timeout", 60.0),
            security_token=data.get("security_token", ""),
            timestamp=data.get("timestamp", time.time()),
        )

        # 1. 安全令牌校验
        if not command.security_token or len(command.security_token) < 8:
            self._send_reject(command, "INVALID_TOKEN", "安全令牌无效或缺失")
            return

        # 2. 重复指令检查
        if command.instruction_id in self._active_tasks:
            self._send_reject(command, "DUPLICATE_COMMAND", "指令重复")
            return

        # 3. 并发满载时排队
        if len(self._active_tasks) >= self.MAX_CONCURRENT:
            if len(self._queue) < self.MAX_QUEUE_SIZE:
                self._queue.append(command)
            else:
                self._send_reject(command, "QUEUE_FULL", "执行队列已满")
            return

        # 4. 直接分发
        self._dispatch_command(command)

    # ====================== 内部消息处理（InternalBus 回调） ======================
    def handle_message(self, message):
        """
        处理来自 InternalBus 的消息（由 agent_mcc_exec.py 绑定）
        预期接收消息：
            - topic: ag-mcc-01.execution_result
            - data: ExecutionResult 结构（来自 ag-mcc-06/07/08）
        """
        if not self.bus:
            return

        data = message.data
        if not data:
            return

        # 收集执行结果
        result = ExecutionResult(
            instruction_id=data.get("instruction_id", ""),
            step_id=data.get("step_id", ""),
            plan_id=data.get("plan_id", ""),
            status=data.get("status", "success"),
            output_data=data.get("output_data"),
            error_code=data.get("error_code", ""),
            error_message=data.get("error_message", ""),
            duration_sec=data.get("duration_sec", 0.0),
            resource_consumption=data.get("resource_consumption", {}),
            timestamp=data.get("timestamp", time.time()),
        )

        self._finalize_result(result)

    # ====================== 任务分发 ======================
    def _dispatch_command(self, command: ToolCallCommand):
        """将指令路由至对应执行模块"""
        self.state = ExecutorState.DISPATCHING

        with self._lock:
            self._active_tasks[command.instruction_id] = command
            self._task_start_times[command.instruction_id] = time.time()

        # 向 ag-mcc-02 注册超时监控
        if self.bus:
            self.bus.publish_to_module(
                target_module="ag-mcc-02",
                event_type="register_task",
                source_module="ag-mcc-01",
                data={
                    "instruction_id": command.instruction_id,
                    "tool_type": command.tool_type,
                    "start_time": time.time(),
                    "timeout_sec": command.timeout_sec,
                },
                priority=PRIORITY_NORMAL,
            )

        # 按工具类型路由
        if command.tool_type == "API":
            if self.bus:
                self.bus.publish_to_module(
                    target_module="ag-mcc-06",
                    event_type="api_call",
                    source_module="ag-mcc-01",
                    data={
                        "instruction_id": command.instruction_id,
                        "tool_name": command.tool_name,
                        "parameters": command.parameters,
                        "timeout_sec": command.timeout_sec,
                        "security_token": command.security_token,
                    },
                    priority=PRIORITY_NORMAL,
                )
        elif command.tool_type == "CODE":
            if self.bus:
                self.bus.publish_to_module(
                    target_module="ag-mcc-07",
                    event_type="code_exec",
                    source_module="ag-mcc-01",
                    data={
                        "instruction_id": command.instruction_id,
                        "code": command.parameters.get("code", ""),
                        "language": command.parameters.get("language", "python"),
                        "timeout_sec": command.timeout_sec,
                        "security_token": command.security_token,
                    },
                    priority=PRIORITY_NORMAL,
                )
        elif command.tool_type == "FILE":
            if self.bus:
                self.bus.publish_to_module(
                    target_module="ag-mcc-08",
                    event_type="file_operation",
                    source_module="ag-mcc-01",
                    data={
                        "instruction_id": command.instruction_id,
                        "operation": command.parameters.get("operation", "READ"),
                        "path": command.parameters.get("path", ""),
                        "data": command.parameters.get("data"),
                        "security_token": command.security_token,
                    },
                    priority=PRIORITY_NORMAL,
                )
        else:
            # 未知类型，直接返回错误
            failed_result = ExecutionResult(
                instruction_id=command.instruction_id,
                step_id=command.step_id,
                plan_id=command.plan_id,
                status="failure",
                error_code="UNKNOWN_TOOL_TYPE",
                error_message=f"未知工具类型: {command.tool_type}",
                duration_sec=0.0,
            )
            self._finalize_result(failed_result)
            return

        self.state = ExecutorState.WAITING_RESULTS

    # ====================== 结果汇总 ======================
    def _finalize_result(self, result: ExecutionResult):
        """汇总执行结果，上报 ECC"""
        with self._lock:
            cmd = self._active_tasks.pop(result.instruction_id, None)
            self._task_start_times.pop(result.instruction_id, None)

        if cmd:
            result.step_id = result.step_id or cmd.step_id
            result.plan_id = result.plan_id or cmd.plan_id

        self._total_executed += 1
        if result.status == "success":
            self._success_count += 1

        # 通过 CerebellumBus 上报回执
        if self.external_bus:
            self.external_bus.publish_to_module(
                target_module="ag-ecc-12",
                event_type="execution_result",
                source_module="ag-mcc-01",
                data={
                    "instruction_id": result.instruction_id,
                    "step_id": result.step_id,
                    "plan_id": result.plan_id,
                    "status": result.status,
                    "output_data": result.output_data,
                    "error_code": result.error_code,
                    "error_message": result.error_message,
                    "duration_sec": result.duration_sec,
                    "resource_consumption": result.resource_consumption,
                    "timestamp": result.timestamp,
                },
                priority=PRIORITY_HIGH,
            )

    # ====================== 超时检查 ======================
    def _check_timeouts(self, now: float):
        """检查活跃任务是否超时"""
        with self._lock:
            for instruction_id, start_time in list(self._task_start_times.items()):
                cmd = self._active_tasks.get(instruction_id)
                if not cmd:
                    continue

                elapsed = now - start_time
                timeout_limit = min(cmd.timeout_sec, self.MAX_TASK_TIMEOUT)

                if elapsed >= timeout_limit:
                    # 超时，生成超时结果
                    failed_result = ExecutionResult(
                        instruction_id=instruction_id,
                        step_id=cmd.step_id,
                        plan_id=cmd.plan_id,
                        status="timeout",
                        error_code="EXECUTION_TIMEOUT",
                        error_message=f"执行超时 (已执行 {elapsed:.1f}s，超时阈值 {timeout_limit}s)",
                        duration_sec=elapsed,
                    )
                    self._finalize_result(failed_result)

    # ====================== 状态上报 ======================
    def _publish_status(self):
        """周期性状态上报（通过 InternalBus 广播）"""
        if not self.bus:
            return

        rate = self._success_count / max(self._total_executed, 1)
        status = ExecutionStatus(
            state=self.state.value,
            active_tasks=len(self._active_tasks),
            queue_depth=len(self._queue),
            total_executed=self._total_executed,
            success_rate=round(rate, 3),
        )

        self.bus.publish(
            topic="ag-mcc-01.status_report",
            source_module="ag-mcc-01",
            data={
                "state": status.state,
                "active_tasks": status.active_tasks,
                "queue_depth": status.queue_depth,
                "total_executed": status.total_executed,
                "success_rate": status.success_rate,
            },
            priority=PRIORITY_LOW,
        )

    # ====================== 辅助方法 ======================
    def _send_reject(self, command: ToolCallCommand, error_code: str, error_message: str):
        """向 ECC 发送拒绝回执"""
        result = ExecutionResult(
            instruction_id=command.instruction_id,
            step_id=command.step_id,
            plan_id=command.plan_id,
            status="failure",
            error_code=error_code,
            error_message=error_message,
            duration_sec=0.0,
        )
        self._finalize_result(result)

    def get_state(self) -> ExecutorState:
        return self.state

    def emergency_shutdown(self):
        """紧急熔断"""
        self.state = ExecutorState.SYSTEM_PAUSED
        with self._lock:
            self._queue.clear()
            self._active_tasks.clear()
            self._task_start_times.clear()
        print(f"[{self.module_id}] 紧急熔断完成，所有任务已清除")

    def shutdown(self):
        """安全关闭（由 agent_mcc_exec.py 调用）"""
        self.state = ExecutorState.IDLE
        print(f"[{self.module_id}] 已安全关闭")


# ====================== 演示与测试 ======================
def print_separator(title: str):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def demo_main():
    print("=" * 60)
    print("  ag-mcc-01 执行调度核心 V1.0 演示")
    print("  原创提出者：文波福")
    print("=" * 60)

    core = ExecutionCore()
    
    # 注入模拟总线
    from memory_bus import InternalBus, CerebellumBus
    internal_bus = InternalBus()
    external_bus = CerebellumBus()
    
    core.bus = internal_bus
    core.external_bus = external_bus
    
    # 注册模块到总线
    internal_bus.register_module("ag-mcc-01")
    internal_bus.register_module("ag-mcc-02")
    internal_bus.register_module("ag-mcc-06")
    external_bus.register_module("ag-mcc-01")
    external_bus.register_module("ag-ecc-12")
    
    # 绑定回调
    internal_bus.subscribe_to_module("ag-mcc-01", core.handle_message)
    external_bus.subscribe_to_module("ag-mcc-01", core.handle_cerebellum_bus_message)

    print_separator("STEP 1: 模拟 ECC 下发 API 调用指令")
    external_bus.publish_to_module(
        target_module="ag-mcc-01",
        event_type="tool_call_command",
        source_module="ag-ecc-12",
        data={
            "instruction_id": "CMD-001",
            "step_id": "S01",
            "plan_id": "P01",
            "tool_name": "weather_api",
            "tool_type": "API",
            "parameters": {"city": "Beijing"},
            "priority": PRIORITY_NORMAL,
            "timeout": 30,
            "security_token": "valid-token-12345",
        },
    )

    # 处理消息
    external_bus.process_all()
    core.execution_core_main_loop()
    internal_bus.process_all()
    
    print(f"  活跃任务数: {len(core._active_tasks)}")
    print(f"  当前状态: {core.state.value}")

    print_separator("STEP 2: 并发满载时排队")
    for i in range(core.MAX_CONCURRENT):
        core._active_tasks[f"T{i}"] = ToolCallCommand(
            instruction_id=f"T{i}", tool_name="test", tool_type="API",
            security_token="valid-token"
        )

    external_bus.publish_to_module(
        target_module="ag-mcc-01",
        event_type="tool_call_command",
        source_module="ag-ecc-12",
        data={
            "instruction_id": "CMD-002",
            "tool_name": "search_engine",
            "tool_type": "API",
            "security_token": "valid-token",
        },
    )
    external_bus.process_all()
    core.execution_core_main_loop()
    print(f"  队列深度: {len(core._queue)}")

    print_separator("STEP 3: 安全令牌无效拒绝")
    core._active_tasks.clear()
    core._queue.clear()
    
    external_bus.publish_to_module(
        target_module="ag-mcc-01",
        event_type="tool_call_command",
        source_module="ag-ecc-12",
        data={
            "instruction_id": "CMD-004",
            "tool_name": "risky_tool",
            "tool_type": "API",
            "security_token": "",  # 空令牌
        },
    )
    external_bus.process_all()
    core.execution_core_main_loop()
    print(f"  总执行数: {core._total_executed}")
    print(f"  成功数: {core._success_count}")

    print("\n✅ 执行调度核心演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("ag-mcc-01 执行调度核心 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        def setup_core():
            """创建测试环境"""
            core = ExecutionCore()
            from memory_bus import InternalBus, CerebellumBus
            internal_bus = InternalBus()
            external_bus = CerebellumBus()
            core.bus = internal_bus
            core.external_bus = external_bus
            internal_bus.register_module("ag-mcc-01")
            internal_bus.register_module("ag-mcc-02")
            internal_bus.register_module("ag-mcc-06")
            external_bus.register_module("ag-mcc-01")
            external_bus.register_module("ag-ecc-12")
            internal_bus.subscribe_to_module("ag-mcc-01", core.handle_message)
            external_bus.subscribe_to_module("ag-mcc-01", core.handle_cerebellum_bus_message)
            return core, internal_bus, external_bus

        # TC-MCC-01: 正常接收并分发API指令
        print("\n[TC-MCC-01] 正常接收并分发API指令")
        try:
            c, ib, eb = setup_core()
            eb.publish_to_module(
                target_module="ag-mcc-01",
                event_type="tool_call_command",
                source_module="ag-ecc-12",
                data={
                    "instruction_id": "T01",
                    "tool_name": "test",
                    "tool_type": "API",
                    "security_token": "valid-token-12345",
                },
            )
            eb.process_all()
            c.execution_core_main_loop()
            ib.process_all()
            assert len(c._active_tasks) == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-02: 并发满载时排队
        print("\n[TC-MCC-02] 并发满载时排队")
        try:
            c, ib, eb = setup_core()
            for i in range(c.MAX_CONCURRENT):
                c._active_tasks[f"T{i}"] = ToolCallCommand(
                    instruction_id=f"T{i}", tool_name="test", tool_type="API",
                    security_token="valid-token"
                )
            eb.publish_to_module(
                target_module="ag-mcc-01",
                event_type="tool_call_command",
                source_module="ag-ecc-12",
                data={
                    "instruction_id": "T02",
                    "tool_name": "test",
                    "tool_type": "API",
                    "security_token": "valid-token",
                },
            )
            eb.process_all()
            c.execution_core_main_loop()
            assert len(c._queue) == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-03: 未知工具类型返回错误
        print("\n[TC-MCC-03] 未知工具类型返回错误")
        try:
            c, ib, eb = setup_core()
            eb.publish_to_module(
                target_module="ag-mcc-01",
                event_type="tool_call_command",
                source_module="ag-ecc-12",
                data={
                    "instruction_id": "T03",
                    "tool_name": "test",
                    "tool_type": "UNKNOWN",
                    "security_token": "valid-token",
                },
            )
            eb.process_all()
            c.execution_core_main_loop()
            assert c._total_executed == 1
            assert c._success_count == 0
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-04: 成功结果统计更新
        print("\n[TC-MCC-04] 成功结果统计更新")
        try:
            c, ib, eb = setup_core()
            c._active_tasks["T04"] = ToolCallCommand(
                instruction_id="T04", tool_name="test", tool_type="API",
                security_token="valid-token"
            )
            c._task_start_times["T04"] = time.time()
            ib.publish(
                topic="ag-mcc-01.execution_result",
                source_module="ag-mcc-06",
                data={
                    "instruction_id": "T04",
                    "status": "success",
                    "duration_sec": 1.5,
                },
                target_module="ag-mcc-01",
            )
            ib.process_all()
            assert c._total_executed == 1
            assert c._success_count == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-05: 队列中的任务在空闲时自动分发
        print("\n[TC-MCC-05] 队列中的任务在空闲时自动分发")
        try:
            c, ib, eb = setup_core()
            c._queue = [ToolCallCommand(
                instruction_id="Q01", tool_name="test", tool_type="API",
                security_token="valid-token"
            )]
            c.execution_core_main_loop()
            assert len(c._active_tasks) == 1
            assert len(c._queue) == 0
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-06: 安全令牌无效拒绝
        print("\n[TC-MCC-06] 安全令牌无效拒绝")
        try:
            c, ib, eb = setup_core()
            eb.publish_to_module(
                target_module="ag-mcc-01",
                event_type="tool_call_command",
                source_module="ag-ecc-12",
                data={
                    "instruction_id": "T06",
                    "tool_name": "risky",
                    "tool_type": "API",
                    "security_token": "",
                },
            )
            eb.process_all()
            c.execution_core_main_loop()
            assert c._total_executed == 1
            assert c._success_count == 0
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-07: 重复指令检查
        print("\n[TC-MCC-07] 重复指令检查")
        try:
            c, ib, eb = setup_core()
            c._active_tasks["T07"] = ToolCallCommand(
                instruction_id="T07", tool_name="test", tool_type="API",
                security_token="valid-token"
            )
            eb.publish_to_module(
                target_module="ag-mcc-01",
                event_type="tool_call_command",
                source_module="ag-ecc-12",
                data={
                    "instruction_id": "T07",
                    "tool_name": "test",
                    "tool_type": "API",
                    "security_token": "valid-token",
                },
            )
            eb.process_all()
            c.execution_core_main_loop()
            assert c._total_executed == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-08: 队列满时拒绝
        print("\n[TC-MCC-08] 队列满时拒绝")
        try:
            c, ib, eb = setup_core()
            for i in range(c.MAX_CONCURRENT):
                c._active_tasks[f"T{i}"] = ToolCallCommand(
                    instruction_id=f"T{i}", tool_name="test", tool_type="API",
                    security_token="valid-token"
                )
            for i in range(c.MAX_QUEUE_SIZE):
                c._queue.append(ToolCallCommand(
                    instruction_id=f"Q{i}", tool_name="test", tool_type="API",
                    security_token="valid-token"
                ))
            eb.publish_to_module(
                target_module="ag-mcc-01",
                event_type="tool_call_command",
                source_module="ag-ecc-12",
                data={
                    "instruction_id": "T08",
                    "tool_name": "test",
                    "tool_type": "API",
                    "security_token": "valid-token",
                },
            )
            eb.process_all()
            c.execution_core_main_loop()
            assert len(c._queue) == c.MAX_QUEUE_SIZE
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-09: 超时任务自动清理
        print("\n[TC-MCC-09] 超时任务自动清理")
        try:
            c, ib, eb = setup_core()
            c._active_tasks["T09"] = ToolCallCommand(
                instruction_id="T09", tool_name="test", tool_type="API",
                security_token="valid-token", timeout_sec=1
            )
            c._task_start_times["T09"] = time.time() - 2  # 已经超时
            c.execution_core_main_loop()
            assert c._total_executed == 1
            assert c._success_count == 0
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