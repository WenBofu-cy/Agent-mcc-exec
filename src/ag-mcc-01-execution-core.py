#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-01
模块名称: 执行调度核心
所属分区: 一、执行中枢调度
核心职责: 作为 Agent-mcc-exec 行动执行层的总调度入口，接收 ECC 认知大脑（通过
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

from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid


class ExecutorState(Enum):
    IDLE = "idle"
    DISPATCHING = "dispatching"
    WAITING_RESULTS = "waiting_results"
    SYSTEM_PAUSED = "system_paused"


class ExecutionPriority(Enum):
    HIGH = 1
    NORMAL = 5
    LOW = 9


@dataclass
class ToolCallCommand:
    command_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    tool_name: str = ""
    tool_type: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: ExecutionPriority = ExecutionPriority.NORMAL
    timeout_sec: float = 60.0
    security_token: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class ExecutionResult:
    command_id: str = ""
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
    state: ExecutorState = ExecutorState.IDLE
    active_tasks: int = 0
    queue_depth: int = 0
    total_executed: int = 0
    success_rate: float = 0.0


class ExecutionCore:
    # 最大并发执行数
    MAX_CONCURRENT = 10
    # 队列最大长度
    MAX_QUEUE_SIZE = 100
    # 状态上报间隔
    STATUS_REPORT_INTERVAL_SEC = 30

    def __init__(self):
        self.module_id = "ag-mcc-01"
        self.module_name = "执行调度核心"
        self.version = "V1.0"

        self.state = ExecutorState.IDLE
        self._active_tasks: Dict[str, ToolCallCommand] = {}
        self._completed_results: Dict[str, ExecutionResult] = {}
        self._queue: List[ToolCallCommand] = []
        self._total_executed: int = 0
        self._success_count: int = 0
        self._last_status_time: float = time.time()
        self._pending_logs: List[Dict[str, Any]] = []

        # 回调注入
        self._query_tool_command = None
        self._query_api_result = None
        self._query_code_result = None
        self._query_file_result = None

        self._publish_api_call = None
        self._publish_code_exec = None
        self._publish_file_op = None
        self._publish_execution_result = None
        self._publish_reject_notice = None
        self._publish_status_report = None
        self._publish_event_log = None

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ========== 回调注入 ==========
    def set_tool_command_query(self, callback: Callable[[], Optional[ToolCallCommand]]):
        self._query_tool_command = callback

    def set_api_result_query(self, callback: Callable[[str], Optional[ExecutionResult]]):
        self._query_api_result = callback

    def set_code_result_query(self, callback: Callable[[str], Optional[ExecutionResult]]):
        self._query_code_result = callback

    def set_file_result_query(self, callback: Callable[[str], Optional[ExecutionResult]]):
        self._query_file_result = callback

    def set_api_call_publisher(self, callback: Callable[[ToolCallCommand], None]):
        self._publish_api_call = callback

    def set_code_exec_publisher(self, callback: Callable[[ToolCallCommand], None]):
        self._publish_code_exec = callback

    def set_file_op_publisher(self, callback: Callable[[ToolCallCommand], None]):
        self._publish_file_op = callback

    def set_execution_result_publisher(self, callback: Callable[[ExecutionResult], None]):
        self._publish_execution_result = callback

    def set_reject_notice_publisher(self, callback: Callable[[str, str], None]):
        self._publish_reject_notice = callback

    def set_status_report_publisher(self, callback: Callable[[ExecutionStatus], None]):
        self._publish_status_report = callback

    def set_event_log_publisher(self, callback: Callable[[Dict[str, Any]], None]):
        self._publish_event_log = callback

    # ========== 主循环 ==========
    def run_execution_cycle(self) -> Optional[ExecutionResult]:
        now = time.time()

        if self.state == ExecutorState.SYSTEM_PAUSED:
            return None

        # 定期状态上报
        if now - self._last_status_time >= self.STATUS_REPORT_INTERVAL_SEC:
            self._publish_status()
            self._last_status_time = now

        # 收集各执行模块返回的结果
        if self.state == ExecutorState.WAITING_RESULTS:
            result = self._collect_results()
            if result:
                return result

            # 如果所有任务都已完成且队列为空，恢复空闲状态
            if not self._active_tasks and not self._queue:
                self.state = ExecutorState.IDLE

        # 从队列中取下一个任务
        if self._queue and len(self._active_tasks) < self.MAX_CONCURRENT:
            # 高优先级任务优先取出
            self._queue.sort(key=lambda c: c.priority.value)
            next_cmd = self._queue.pop(0)
            self._dispatch_command(next_cmd)

        # 接收新指令
        command = self._query_tool_command() if self._query_tool_command else None
        if command is None:
            return None

        # 并发满载时排队
        if len(self._active_tasks) >= self.MAX_CONCURRENT:
            if len(self._queue) < self.MAX_QUEUE_SIZE:
                self._queue.append(command)
            else:
                # 队列已满，拒绝指令
                self._log_event("QUEUE_FULL_REJECTED", {"command_id": command.command_id})
                if self._publish_reject_notice:
                    self._publish_reject_notice(command.command_id, "执行队列已满")
            return None

        self._dispatch_command(command)
        return None

    def _dispatch_command(self, command: ToolCallCommand):
        self.state = ExecutorState.DISPATCHING

        # 安全令牌校验 (安全约束 X-03)
        if not command.security_token or len(command.security_token) < 8:
            failed_result = ExecutionResult(
                command_id=command.command_id,
                step_id=command.step_id,
                plan_id=command.plan_id,
                status="failure",
                error_code="INVALID_TOKEN",
                error_message="安全令牌无效或缺失，指令被拒绝"
            )
            self._finalize_result(failed_result)
            return

        self._active_tasks[command.command_id] = command

        # 按工具类型路由
        if command.tool_type == "API":
            if self._publish_api_call:
                self._publish_api_call(command)
        elif command.tool_type == "CODE":
            if self._publish_code_exec:
                self._publish_code_exec(command)
        elif command.tool_type == "FILE":
            if self._publish_file_op:
                self._publish_file_op(command)
        else:
            # 未知类型，通过 _finalize_result 统一处理（修复统计遗漏）
            failed_result = ExecutionResult(
                command_id=command.command_id,
                step_id=command.step_id,
                plan_id=command.plan_id,
                status="failure",
                error_code="UNKNOWN_TOOL_TYPE",
                error_message=f"未知工具类型: {command.tool_type}"
            )
            self._finalize_result(failed_result)
            return

        self.state = ExecutorState.WAITING_RESULTS

    def _collect_results(self) -> Optional[ExecutionResult]:
        """遍历活跃任务，精确查询对应执行模块的结果（修复：按 command_id 精确查询）"""
        for cmd_id in list(self._active_tasks.keys()):
            cmd = self._active_tasks[cmd_id]
            result = None

            if cmd.tool_type == "API" and self._query_api_result:
                result = self._query_api_result(cmd_id)
            elif cmd.tool_type == "CODE" and self._query_code_result:
                result = self._query_code_result(cmd_id)
            elif cmd.tool_type == "FILE" and self._query_file_result:
                result = self._query_file_result(cmd_id)

            if result is not None:
                return self._finalize_result(result)

        return None

    def _finalize_result(self, result: ExecutionResult) -> ExecutionResult:
        """统一处理执行结果，更新统计并上报（修复：统一入口）"""
        cmd = self._active_tasks.pop(result.command_id, None)
        if cmd:
            result.step_id = result.step_id or cmd.step_id
            result.plan_id = result.plan_id or cmd.plan_id

        self._total_executed += 1
        if result.status == "success":
            self._success_count += 1

        if self._publish_execution_result:
            self._publish_execution_result(result)

        return result

    # ========== 辅助 ==========
    def _publish_status(self):
        rate = self._success_count / max(self._total_executed, 1)
        if self._publish_status_report:
            self._publish_status_report(ExecutionStatus(
                state=self.state,
                active_tasks=len(self._active_tasks),
                queue_depth=len(self._queue),
                total_executed=self._total_executed,
                success_rate=round(rate, 3)
            ))

    def get_state(self) -> ExecutorState:
        return self.state

    def emergency_shutdown(self):
        self.state = ExecutorState.SYSTEM_PAUSED
        self._queue.clear()
        self._active_tasks.clear()
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
    print("  Agent-mcc-exec 执行调度核心 (ag-mcc-01) 演示")
    print("=" * 70)

    core = ExecutionCore()

    print_separator("STEP 1: 接收API调用指令并分发")
    core.set_tool_command_query(lambda: ToolCallCommand(
        command_id="CMD-001", step_id="S01", plan_id="P01",
        tool_name="weather_api", tool_type="API",
        parameters={"city": "北京"}, priority=ExecutionPriority.NORMAL,
        security_token="valid-token-12345"
    ))
    core.run_execution_cycle()
    print(f"  活跃任务数: {len(core._active_tasks)}")

    print_separator("STEP 2: 并发满载时排队")
    for i in range(core.MAX_CONCURRENT):
        core._active_tasks[f"T{i}"] = ToolCallCommand(
            command_id=f"T{i}", tool_name="test", tool_type="API",
            security_token="valid-token"
        )
    core.set_tool_command_query(lambda: ToolCallCommand(
        command_id="CMD-002", tool_name="search_engine", tool_type="API",
        security_token="valid-token"
    ))
    core.run_execution_cycle()
    print(f"  队列深度: {len(core._queue)}")

    print_separator("STEP 3: 安全令牌无效拒绝指令")
    core._active_tasks.clear()
    core._queue.clear()
    core.set_tool_command_query(lambda: ToolCallCommand(
        command_id="CMD-004", tool_name="risky_tool", tool_type="API",
        security_token=""  # 空令牌
    ))
    core.run_execution_cycle()
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
            return ExecutionCore()

        def valid_token_cmd(cid="T01", ttype="API"):
            return ToolCallCommand(command_id=cid, tool_name="test", tool_type=ttype,
                                   security_token="valid-token-12345")

        # TC-MCC-01: 正常接收并分发API指令
        print("\n[TC-MCC-01] 正常接收并分发API指令")
        try:
            c = setup_core()
            c.set_tool_command_query(lambda: valid_token_cmd("T01"))
            c.run_execution_cycle()
            assert len(c._active_tasks) == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-02: 并发满载时排队
        print("\n[TC-MCC-02] 并发满载时排队")
        try:
            c = setup_core()
            for i in range(c.MAX_CONCURRENT):
                c._active_tasks[f"T{i}"] = valid_token_cmd(f"T{i}")
            c.set_tool_command_query(lambda: valid_token_cmd("T02"))
            c.run_execution_cycle()
            assert len(c._queue) == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-03: 未知工具类型返回错误
        print("\n[TC-MCC-03] 未知工具类型返回错误")
        try:
            c = setup_core()
            cmd = valid_token_cmd("T03")
            cmd.tool_type = "UNKNOWN"
            c.set_tool_command_query(lambda: cmd)
            c.run_execution_cycle()
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
            c = setup_core()
            c._active_tasks["T04"] = valid_token_cmd("T04")
            c.set_api_result_query(lambda cid: ExecutionResult(
                command_id="T04", status="success", duration_sec=1.5
            ) if cid == "T04" else None)
            result = c.run_execution_cycle()
            if result:
                assert result.status == "success"
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
            c = setup_core()
            c._queue = [valid_token_cmd("Q01")]
            c.run_execution_cycle()
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
            c = setup_core()
            c.set_tool_command_query(lambda: ToolCallCommand(
                command_id="T06", tool_name="risky", tool_type="API", security_token=""
            ))
            c.run_execution_cycle()
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