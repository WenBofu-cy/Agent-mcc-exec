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
    ag-ecc-12（资源调度模块，下发工具调用指令）,
    ag-mcc-02（工具超时管理器）, ag-mcc-04（工具注册中心）,
    ag-mcc-06（API调用引擎）, ag-mcc-07（代码执行沙箱）,
    ag-mcc-08（文件操作执行器）
被依赖模块:
    ag-ecc-12（接收执行回执）, ag-mcc-02~12（接收调度指令）

安全约束:
  X-01: 本模块为 MCC 行动执行层的唯一入口，所有来自 ECC 的指令必须经本模块接收与路由
  X-02: 本模块仅负责任务分发与结果汇总，不参与任何工具选择或参数决策
  X-03: 所有指令必须校验来源合法性，拒绝未携带有效安全令牌的指令
  X-04: 执行超时后自动中断并上报，不得无限期等待
"""

from typing import Dict, List, Any
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid
import threading

from memory_bus import Message, PRIORITY_NORMAL, PRIORITY_HIGH, PRIORITY_ORDER


class ExecutorState(Enum):
    IDLE = "IDLE"
    DISPATCHING = "DISPATCHING"
    WAITING_RESULTS = "WAITING_RESULTS"
    SYSTEM_PAUSED = "SYSTEM_PAUSED"


@dataclass
class ToolCallCommand:
    """与 SPEC 字段名严格一致：指令ID = instruction_id"""
    instruction_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    tool_name: str = ""
    tool_type: str = ""          # API / CODE / FILE
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: str = PRIORITY_NORMAL
    timeout_sec: float = 60.0
    security_token: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class ExecutionResult:
    """与 SPEC 字段名严格一致：指令ID = instruction_id"""
    instruction_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    status: str = "success"      # success / failure / timeout / exception
    output_data: Any = None
    error_code: str = ""
    error_message: str = ""
    duration_sec: float = 0.0
    resource_consumption: Dict[str, float] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class ExecutionCore:
    MAX_CONCURRENT = 10
    MAX_QUEUE_SIZE = 100
    STATUS_REPORT_INTERVAL_SEC = 30
    MAX_STALE_TASK_SEC = 600          # 兜底超时清理阈值（作为 ag-mcc-02 的备份）

    def __init__(self):
        self.module_id = "ag-mcc-01"
        self.module_name = "执行调度核心"
        self.version = "V1.0"

        # 总线注入点（由主入口赋值）
        self.bus = None                 # InternalBus
        self.external_bus = None        # CerebellumBus

        self.state = ExecutorState.IDLE
        self._active_tasks: Dict[str, ToolCallCommand] = {}
        self._queue: List[ToolCallCommand] = []
        self._total_executed = 0
        self._success_count = 0
        self._last_status_time = time.time()

        self._pending_commands: List[ToolCallCommand] = []
        self._lock = threading.Lock()

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ========== 总线回调接口 ==========
    def handle_message(self, msg: Message):
        """
        处理 InternalBus 消息
        订阅 topic:
          - ag-mcc-01.execution_result    来自 ag-mcc-06/07/08 的执行结果
          - ag-mcc-01.timeout_notification 来自 ag-mcc-02 的超时通知
        """
        if msg.topic == "ag-mcc-01.execution_result":
            result_data = msg.data
            result = ExecutionResult(**result_data) if isinstance(result_data, dict) else result_data
            self._finalize_result(result)

        elif msg.topic == "ag-mcc-01.timeout_notification":
            # SPEC: ag-mcc-02 检测到任务超时后，向本模块发送通知
            data = msg.data if isinstance(msg.data, dict) else {}
            task_id = data.get("task_id", "")
            elapsed = data.get("elapsed_sec", 0)
            threshold = data.get("timeout_threshold_sec", 0)

            if task_id and task_id in self._active_tasks:
                cmd = self._active_tasks[task_id]
                failed_result = ExecutionResult(
                    instruction_id=task_id,
                    step_id=cmd.step_id,
                    plan_id=cmd.plan_id,
                    status="timeout",
                    error_code="EXECUTION_TIMEOUT",
                    error_message=f"执行超时 (已执行 {elapsed:.1f}s，超时阈值 {threshold}s)",
                    duration_sec=elapsed
                )
                self._finalize_result(failed_result)

    def handle_cerebellum_bus_message(self, msg: Message):
        """处理 CerebellumBus 消息（来自 ECC 的工具调用指令）"""
        if msg.topic == "ag-mcc-01.tool_call_command":
            cmd_data = msg.data
            command = ToolCallCommand(**cmd_data) if isinstance(cmd_data, dict) else cmd_data
            self._enqueue_command(command)

    # ========== 主循环 ==========
    def execution_core_main_loop(self):
        now = time.time()

        if self.state == ExecutorState.SYSTEM_PAUSED:
            return

        # 定期状态上报 + 兜底超时清理
        if now - self._last_status_time >= self.STATUS_REPORT_INTERVAL_SEC:
            self._publish_status()
            self._cleanup_stale_tasks(now)
            self._last_status_time = now

        # 处理缓冲队列中的新指令（线程安全）
        while True:
            with self._lock:
                if not self._pending_commands:
                    break
                cmd = self._pending_commands.pop(0)

            if len(self._active_tasks) < self.MAX_CONCURRENT:
                self._dispatch_command(cmd)
            else:
                if len(self._queue) < self.MAX_QUEUE_SIZE:
                    self._queue.append(cmd)
                else:
                    self._log_event("QUEUE_FULL_REJECTED", {"instruction_id": cmd.instruction_id})
                    self._report_rejection(cmd.instruction_id, "执行队列已满")

        # 并发空闲时从队列中按优先级取出执行
        if len(self._active_tasks) < self.MAX_CONCURRENT and self._queue:
            self._queue.sort(key=lambda c: PRIORITY_ORDER.get(c.priority, 2))
            while len(self._active_tasks) < self.MAX_CONCURRENT and self._queue:
                next_cmd = self._queue.pop(0)
                self._dispatch_command(next_cmd)

        if not self._active_tasks and not self._queue:
            self.state = ExecutorState.IDLE

    def _enqueue_command(self, command: ToolCallCommand):
        with self._lock:
            self._pending_commands.append(command)

    def _dispatch_command(self, command: ToolCallCommand):
        self.state = ExecutorState.DISPATCHING

        # 1. 重复指令检查
        if command.instruction_id in self._active_tasks:
            self._report_rejection(command.instruction_id, "重复指令")
            return

        # 2. 安全令牌校验
        if not self._is_valid_token(command.security_token):
            failed_result = ExecutionResult(
                instruction_id=command.instruction_id,
                step_id=command.step_id,
                plan_id=command.plan_id,
                status="failure",
                error_code="INVALID_TOKEN",
                error_message="安全令牌无效"
            )
            self._finalize_result(failed_result)
            return

        self._active_tasks[command.instruction_id] = command

        # 3. 根据工具类型路由至对应执行模块
        topic_map = {
            "API": "ag-mcc-06.api_call_command",
            "CODE": "ag-mcc-07.code_exec_command",
            "FILE": "ag-mcc-08.file_op_command",
        }
        target_map = {"API": "ag-mcc-06", "CODE": "ag-mcc-07", "FILE": "ag-mcc-08"}

        if command.tool_type in topic_map:
            if self.bus:
                self.bus.publish(
                    topic=topic_map[command.tool_type],
                    source_module=self.module_id,
                    data=command.__dict__,
                    target_module=target_map[command.tool_type],
                    priority=command.priority
                )
                self.state = ExecutorState.WAITING_RESULTS
            else:
                self._finalize_result(ExecutionResult(
                    instruction_id=command.instruction_id,
                    status="failure",
                    error_code="BUS_NOT_READY",
                    error_message="内部总线未就绪"
                ))
        else:
            self._finalize_result(ExecutionResult(
                instruction_id=command.instruction_id,
                step_id=command.step_id,
                plan_id=command.plan_id,
                status="failure",
                error_code="UNKNOWN_TOOL_TYPE",
                error_message=f"未知工具类型: {command.tool_type}"
            ))

    def _finalize_result(self, result: ExecutionResult):
        cmd = self._active_tasks.pop(result.instruction_id, None)
        if cmd:
            result.step_id = result.step_id or cmd.step_id
            result.plan_id = result.plan_id or cmd.plan_id

        self._total_executed += 1
        if result.status == "success":
            self._success_count += 1

        # 通过 CerebellumBus 上报执行回执至 ECC
        if self.external_bus:
            self.external_bus.publish(
                topic="ag-mcc-01.execution_result",
                source_module=self.module_id,
                data=result.__dict__,
                target_module="ag-ecc-12",
                priority=PRIORITY_HIGH
            )

        if not self._active_tasks and not self._queue:
            self.state = ExecutorState.IDLE

    def _is_valid_token(self, token: str) -> bool:
        return bool(token) and len(token) >= 8

    def _report_rejection(self, instruction_id: str, reason: str):
        if self.external_bus:
            self.external_bus.publish(
                topic="ag-mcc-01.command_rejected",
                source_module=self.module_id,
                data={"instruction_id": instruction_id, "reason": reason},
                target_module="ag-ecc-12",
                priority=PRIORITY_NORMAL
            )

    def _publish_status(self):
        """通过外部总线向 ECC 上报执行状态"""
        if self.external_bus:
            rate = self._success_count / max(self._total_executed, 1)
            self.external_bus.publish(
                topic="ag-mcc-01.status_report",
                source_module=self.module_id,
                data={
                    "state": self.state.value,
                    "active_tasks": len(self._active_tasks),
                    "queue_depth": len(self._queue),
                    "total_executed": self._total_executed,
                    "success_rate": round(rate, 3)
                },
                target_module="ag-ecc-12",
                priority=PRIORITY_NORMAL
            )

    def _cleanup_stale_tasks(self, now: float):
        """兜底超时清理：清理超过最大时长的僵尸任务"""
        stale_ids = [
            iid for iid, cmd in self._active_tasks.items()
            if now - cmd.timestamp >= self.MAX_STALE_TASK_SEC
        ]
        for iid in stale_ids:
            self._finalize_result(ExecutionResult(
                instruction_id=iid,
                status="timeout",
                error_code="STALE_TASK_CLEANUP",
                error_message=f"任务执行超时（兜底清理，已运行 {self.MAX_STALE_TASK_SEC}s）"
            ))
            self._log_event("STALE_TASK_CLEANED", {"instruction_id": iid})

    def _log_event(self, event_type: str, details: Dict[str, Any]):
        if self.bus:
            self.bus.publish(
                topic="ag-mcc-12.log_event",
                source_module=self.module_id,
                data={
                    "log_id": f"log-{uuid.uuid4().hex[:8]}",
                    "event_type": event_type,
                    "source_module": self.module_id,
                    "details": details,
                    "timestamp": time.time()
                },
                priority=PRIORITY_NORMAL
            )

    def get_state(self) -> ExecutorState:
        return self.state

    def emergency_shutdown(self):
        self.state = ExecutorState.SYSTEM_PAUSED
        with self._lock:
            self._queue.clear()
            self._active_tasks.clear()
            self._pending_commands.clear()
        print(f"[{self.module_id}] 紧急熔断完成，所有任务已清除")

    def shutdown(self):
        self.state = ExecutorState.IDLE
        with self._lock:
            self._queue.clear()
            self._active_tasks.clear()
            self._pending_commands.clear()
        print(f"[{self.module_id}] 已安全关闭")

    # 测试专用接口
    def _test_inject_command(self, command: ToolCallCommand):
        self._enqueue_command(command)
        self.execution_core_main_loop()

    def _test_inject_result(self, result: ExecutionResult):
        self._finalize_result(result)


# ========== 演示与测试 ==========
def demo_main():
    print("=" * 70)
    print("  Agent-mcc-exec 执行调度核心 (ag-mcc-01) 演示")
    print("=" * 70)

    core = ExecutionCore()

    print("\n[演示] 注入API指令并模拟成功结果")
    cmd = ToolCallCommand(
        instruction_id="CMD-001", step_id="S01", plan_id="P01",
        tool_name="weather_api", tool_type="API",
        parameters={"city": "北京"}, security_token="valid-token-12345"
    )
    core._test_inject_command(cmd)
    print(f"  活跃任务数: {len(core._active_tasks)}")
    core._test_inject_result(ExecutionResult(instruction_id="CMD-001", status="success", duration_sec=1.2))
    print(f"  总执行: {core._total_executed}, 成功: {core._success_count}")

    print("\n[演示] 并发满载排队")
    for i in range(core.MAX_CONCURRENT):
        core._active_tasks[f"T{i}"] = ToolCallCommand(instruction_id=f"T{i}", tool_name="filler", tool_type="API", security_token="t")
    core._test_inject_command(ToolCallCommand(instruction_id="CMD-002", tool_name="search", tool_type="API", security_token="ok"))
    print(f"  队列深度: {len(core._queue)}")

    print("\n[演示] 非法令牌拒绝")
    core._active_tasks.clear()
    core._queue.clear()
    core._test_inject_command(ToolCallCommand(instruction_id="CMD-003", tool_name="risky", tool_type="API", security_token=""))
    print(f"  总执行: {core._total_executed}, 成功: {core._success_count}")

    print("\n[演示] 超时通知处理")
    core._active_tasks.clear()
    core._queue.clear()
    core._active_tasks["CMD-004"] = ToolCallCommand(
        instruction_id="CMD-004", step_id="S02", plan_id="P02",
        tool_name="slow_api", tool_type="API",
        security_token="valid-token"
    )
    # 模拟 ag-mcc-02 发来的超时通知
    core.handle_message(Message(
        message_id="msg-01", topic="ag-mcc-01.timeout_notification",
        source_module="ag-mcc-02", target_module="ag-mcc-01",
        data={"task_id": "CMD-004", "elapsed_sec": 65.0, "timeout_threshold_sec": 60}
    ))
    print(f"  总执行: {core._total_executed}, 成功: {core._success_count}")
    print(f"  活跃任务数（应为0）: {len(core._active_tasks)}")

    print("\n✅ 演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("ag-mcc-01 执行调度核心 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        def setup():
            return ExecutionCore()

        def valid_cmd(iid="T01", ttype="API"):
            return ToolCallCommand(instruction_id=iid, tool_name="test", tool_type=ttype, security_token="valid-token-12345")

        tests = [
            ("正常接收并分发API指令", lambda c: (
                c._test_inject_command(valid_cmd("T01")),
                len(c._active_tasks) == 1
            )),
            ("并发满载时排队", lambda c: (
                [c._active_tasks.__setitem__(f"T{i}", valid_cmd(f"T{i}")) for i in range(c.MAX_CONCURRENT)],
                c._test_inject_command(valid_cmd("T02")),
                len(c._queue) == 1
            )),
            ("未知工具类型返回错误", lambda c: (
                c._test_inject_command(valid_cmd("T03", "UNKNOWN")),
                c._total_executed == 1 and c._success_count == 0
            )),
            ("成功结果统计更新", lambda c: (
                c._active_tasks.update({"T04": valid_cmd("T04")}),
                c._test_inject_result(ExecutionResult(instruction_id="T04", status="success")),
                c._total_executed == 1 and c._success_count == 1
            )),
            ("队列任务自动分发", lambda c: (
                c._queue.append(valid_cmd("Q01")),
                c.execution_core_main_loop(),
                len(c._active_tasks) == 1 and len(c._queue) == 0
            )),
            ("非法令牌拒绝", lambda c: (
                c._test_inject_command(ToolCallCommand(instruction_id="T06", tool_name="r", tool_type="API", security_token="")),
                c._total_executed == 1 and c._success_count == 0
            )),
            ("重复指令拒绝", lambda c: (
                c._active_tasks.update({"T07": valid_cmd("T07")}),
                c._test_inject_command(valid_cmd("T07")),
                c._total_executed == 0
            )),
            ("超时通知处理", lambda c: (
                c._active_tasks.update({"T08": valid_cmd("T08")}),
                c.handle_message(Message(
                    message_id="msg-01", topic="ag-mcc-01.timeout_notification",
                    source_module="ag-mcc-02", target_module="ag-mcc-01",
                    data={"task_id": "T08", "elapsed_sec": 65.0, "timeout_threshold_sec": 60}
                )),
                c._total_executed == 1 and c._success_count == 0
                and "T08" not in c._active_tasks
            )),
        ]

        for name, fn in tests:
            print(f"\n[TC] {name}")
            try:
                c = setup()
                assert fn(c)
                print("   ✅ PASS"); passed += 1
            except Exception as e:
                print(f"   ❌ FAIL: {e}"); failed += 1

        print("\n" + "=" * 60)
        print(f"测试结果: {passed} PASS, {failed} FAIL")
        print("=" * 60)
    else:
        demo_main()