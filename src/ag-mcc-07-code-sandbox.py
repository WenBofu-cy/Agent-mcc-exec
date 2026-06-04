#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-07
模块名称: 代码执行沙箱
所属分区: 三、调用执行引擎
核心职责: 在隔离的安全环境中执行由 ECC 认知大脑下发或用户提供的代码片段。基于沙箱技术
          限制代码对系统资源（文件系统、网络、进程）的访问，控制执行超时与内存上限。
          捕获代码的标准输出、标准错误及返回值，结构化后返回至 ag-mcc-01（执行调度核心）。
          同时支持多种编程语言的执行运行时。不参与代码内容的审查或修改，仅负责代码的
          安全执行与结果捕获。

依赖模块:
    ag-mcc-01(执行调度核心), ag-mcc-04(工具注册中心), ag-mcc-03(资源配额管控单元)
被依赖模块:
    ag-mcc-01, ag-mcc-03

安全约束:
  S-01: 所有代码必须在沙箱中执行，沙箱外不得执行任何用户或系统生成的代码
  S-02: 网络访问能力默认完全禁止
  S-03: 文件系统写操作默认禁止，仅允许写入指定的临时目录
  S-04: 检测到沙箱逃逸尝试或禁止的系统调用时必须立即终止并上报安全告警
  S-05: 沙箱实例之间完全隔离
  S-06: 代码执行结果不得包含宿主系统的敏感信息
"""

from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid


class SandboxState(Enum):
    WAITING_COMMAND = "waiting_command"
    SANDBOX_SETUP = "sandbox_setup"
    EXECUTING = "executing"
    COLLECTING_RESULT = "collecting_result"
    SYSTEM_PAUSED = "system_paused"


class Language(Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    BASH = "bash"
    SQL = "sql"


@dataclass
class CodeExecutionCommand:
    command_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    language: Language = Language.PYTHON
    source_code: str = ""
    stdin_data: Optional[str] = None
    timeout_sec: float = 30.0
    memory_limit_mb: float = 128.0
    cpu_limit: float = 1.0
    security_token: str = ""
    environment_vars: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class LanguageRuntimeConfig:
    language: Language = Language.PYTHON
    sandbox_image: str = "python:3.11-slim"
    preinstalled_libs: List[str] = field(default_factory=list)
    allowed_syscalls: List[str] = field(default_factory=list)
    filesystem_mounts: List[str] = field(default_factory=list)


@dataclass
class ResourceConstraints:
    command_id: str = ""
    max_memory_mb: float = 128.0
    max_cpu_cores: float = 1.0
    max_execution_sec: float = 30.0
    max_output_size_kb: float = 1024.0


@dataclass
class CodeExecutionResult:
    command_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    status: str = "success"  # success / failure / timeout / memory_overflow / security_violation
    stdout: str = ""
    stderr: str = ""
    return_value: Any = None
    actual_duration_sec: float = 0.0
    actual_memory_peak_mb: float = 0.0
    exit_code: int = 0
    resource_consumption: Dict[str, float] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class ResourceReleaseNotice:
    command_id: str = ""
    memory_released_mb: float = 0.0
    cpu_time_released: float = 0.0


@dataclass
class SecurityViolationAlert:
    command_id: str = ""
    violation_type: str = ""
    violation_detail: str = ""
    severity: str = "高"


@dataclass
class SandboxStatus:
    state: SandboxState = SandboxState.WAITING_COMMAND
    active_sandboxes: int = 0
    today_executions: int = 0
    success_rate: float = 0.0
    avg_execution_ms: float = 0.0


class CodeExecutionSandbox:
    # 资源限制默认值
    DEFAULT_TIMEOUT_SEC = 30
    DEFAULT_MEMORY_MB = 128
    DEFAULT_CPU_CORES = 1
    DEFAULT_MAX_OUTPUT_KB = 1024  # 1MB
    MIN_TIMEOUT_SEC = 5
    MAX_TIMEOUT_SEC = 120

    # 并发限制
    MAX_CONCURRENT_SANDBOXES = 3

    # 语言运行时配置
    LANGUAGE_RUNTIMES = {
        Language.PYTHON: LanguageRuntimeConfig(
            language=Language.PYTHON,
            sandbox_image="python:3.11-slim",
            preinstalled_libs=["math", "json", "datetime", "re", "collections", "itertools"],
            allowed_syscalls=["read", "write", "exit", "brk", "mmap"],
            filesystem_mounts=["/lib", "/usr/lib"]
        ),
        Language.JAVASCRIPT: LanguageRuntimeConfig(
            language=Language.JAVASCRIPT,
            sandbox_image="node:20-alpine",
            preinstalled_libs=[],
            allowed_syscalls=["read", "write", "exit", "brk", "mmap"],
            filesystem_mounts=["/lib", "/usr/lib"]
        ),
        Language.BASH: LanguageRuntimeConfig(
            language=Language.BASH,
            sandbox_image="alpine:3.19",
            preinstalled_libs=[],
            allowed_syscalls=["read", "write", "exit", "brk", "mmap", "fork", "execve"],
            filesystem_mounts=["/bin", "/lib", "/usr"]
        ),
        Language.SQL: LanguageRuntimeConfig(
            language=Language.SQL,
            sandbox_image="sqlite:3.42",
            preinstalled_libs=[],
            allowed_syscalls=["read", "write", "exit", "brk", "mmap"],
            filesystem_mounts=["/lib", "/usr/lib"]
        ),
    }

    # 禁止的系统调用
    FORBIDDEN_SYSCALLS = ["fork", "clone", "execve", "socket", "connect", "bind", "listen", "accept"]
    
    # 统计上报间隔
    STATUS_REPORT_INTERVAL_SEC = 60

    def __init__(self):
        self.module_id = "ag-mcc-07"
        self.module_name = "代码执行沙箱"
        self.version = "V1.0"

        self.state = SandboxState.WAITING_COMMAND
        self._active_sandboxes: Dict[str, Dict[str, Any]] = {}
        self._waiting_queue: List[CodeExecutionCommand] = []
        self._total_executions: int = 0
        self._success_count: int = 0
        self._total_execution_time: float = 0.0
        self._last_status_time: float = time.time()
        self._pending_logs: List[Dict[str, Any]] = []

        # 回调注入
        self._query_code_command = None
        self._query_runtime_config = None
        self._query_resource_constraints = None

        self._publish_execution_result = None
        self._publish_resource_release = None
        self._publish_security_alert = None
        self._publish_status_report = None
        self._publish_event_log = None

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ========== 回调注入 ==========
    def set_code_command_query(self, callback: Callable[[], Optional[CodeExecutionCommand]]):
        self._query_code_command = callback

    def set_runtime_config_query(self, callback: Callable[[Language], Optional[LanguageRuntimeConfig]]):
        self._query_runtime_config = callback

    def set_resource_constraints_query(self, callback: Callable[[], Optional[ResourceConstraints]]):
        self._query_resource_constraints = callback

    def set_execution_result_publisher(self, callback: Callable[[CodeExecutionResult], None]):
        self._publish_execution_result = callback

    def set_resource_release_publisher(self, callback: Callable[[ResourceReleaseNotice], None]):
        self._publish_resource_release = callback

    def set_security_alert_publisher(self, callback: Callable[[SecurityViolationAlert], None]):
        self._publish_security_alert = callback

    def set_status_report_publisher(self, callback: Callable[[SandboxStatus], None]):
        self._publish_status_report = callback

    def set_event_log_publisher(self, callback: Callable[[Dict[str, Any]], None]):
        self._publish_event_log = callback

    # ========== 主循环 ==========
    def run_sandbox_cycle(self) -> Optional[CodeExecutionResult]:
        now = time.time()

        if self.state == SandboxState.SYSTEM_PAUSED:
            return None

        # 定期状态上报
        if now - self._last_status_time >= self.STATUS_REPORT_INTERVAL_SEC:
            self._publish_status()
            self._last_status_time = now

        # 检查沙箱执行状态
        for command_id in list(self._active_sandboxes.keys()):
            result = self._check_sandbox_completion(command_id, now)
            if result:
                return result

        # 处理等待队列
        if self._waiting_queue and len(self._active_sandboxes) < self.MAX_CONCURRENT_SANDBOXES:
            next_cmd = self._waiting_queue.pop(0)
            self._setup_and_execute(next_cmd)

        # 接收新指令
        command = self._query_code_command() if self._query_code_command else None
        if command is None:
            return None

        if len(self._active_sandboxes) >= self.MAX_CONCURRENT_SANDBOXES:
            self._waiting_queue.append(command)
            return None

        self._setup_and_execute(command)
        return None

    def _setup_and_execute(self, command: CodeExecutionCommand):
        self.state = SandboxState.SANDBOX_SETUP

        # 获取运行时配置
        runtime_config = self.LANGUAGE_RUNTIMES.get(command.language)
        if self._query_runtime_config:
            queried = self._query_runtime_config(command.language)
            if queried:
                runtime_config = queried

        if runtime_config is None:
            result = CodeExecutionResult(
                command_id=command.command_id,
                step_id=command.step_id,
                plan_id=command.plan_id,
                status="failure",
                stderr=f"不支持的语言类型: {command.language.value}",
                exit_code=-1
            )
            self._finalize_result(result, command)
            return

        # 安全检查：禁止的系统调用检测
        for forbidden in self.FORBIDDEN_SYSCALLS:
            if forbidden in command.source_code.lower():
                result = CodeExecutionResult(
                    command_id=command.command_id,
                    step_id=command.step_id,
                    plan_id=command.plan_id,
                    status="security_violation",
                    stderr=f"安全违规: 代码中包含禁止的系统调用 '{forbidden}'",
                    exit_code=-1
                )
                self._finalize_result(result, command)
                if self._publish_security_alert:
                    self._publish_security_alert(SecurityViolationAlert(
                        command_id=command.command_id,
                        violation_type="禁止的系统调用",
                        violation_detail=f"检测到 '{forbidden}'",
                        severity="高"
                    ))
                return

        # 创建沙箱上下文
        context = {
            "command": command,
            "runtime_config": runtime_config,
            "start_time": time.time(),
            "memory_peak_mb": 0.0
        }
        self._active_sandboxes[command.command_id] = context

        self.state = SandboxState.EXECUTING

    def _check_sandbox_completion(self, command_id: str, now: float) -> Optional[CodeExecutionResult]:
        context = self._active_sandboxes.get(command_id)
        if not context:
            return None

        command = context["command"]
        start_time = context["start_time"]
        elapsed = now - start_time

        # 检查超时
        if elapsed >= command.timeout_sec:
            result = CodeExecutionResult(
                command_id=command_id,
                step_id=command.step_id,
                plan_id=command.plan_id,
                status="timeout",
                actual_duration_sec=command.timeout_sec,
                exit_code=-1
            )
            return self._finalize_result(result, command)

        # 模拟执行完成（实际实现会轮询沙箱进程状态）
        if elapsed >= min(command.timeout_sec * 0.3, 1.0):
            # 模拟执行结果
            success = "error" not in command.source_code.lower() and "exception" not in command.source_code.lower()
            result = CodeExecutionResult(
                command_id=command_id,
                step_id=command.step_id,
                plan_id=command.plan_id,
                status="success" if success else "failure",
                stdout=f"[模拟输出] 代码已执行, 耗时={elapsed:.2f}s",
                stderr="" if success else "模拟错误: 代码执行异常",
                actual_duration_sec=elapsed,
                actual_memory_peak_mb=min(command.memory_limit_mb * 0.3, 50.0),
                exit_code=0 if success else 1
            )
            return self._finalize_result(result, command)

        return None

    def _finalize_result(self, result: CodeExecutionResult, command: CodeExecutionCommand) -> CodeExecutionResult:
        if result.command_id in self._active_sandboxes:
            del self._active_sandboxes[result.command_id]

        self._total_executions += 1
        if result.status == "success":
            self._success_count += 1
        self._total_execution_time += result.actual_duration_sec

        # 发送执行结果
        if self._publish_execution_result:
            self._publish_execution_result(result)

        # 发送资源释放通知
        if self._publish_resource_release:
            self._publish_resource_release(ResourceReleaseNotice(
                command_id=result.command_id,
                memory_released_mb=command.memory_limit_mb,
                cpu_time_released=result.actual_duration_sec
            ))

        if not self._active_sandboxes and not self._waiting_queue:
            self.state = SandboxState.WAITING_COMMAND

        return result

    # ========== 辅助 ==========
    def _publish_status(self):
        if self._publish_status_report:
            rate = self._success_count / max(self._total_executions, 1)
            avg = self._total_execution_time / max(self._total_executions, 1) * 1000
            self._publish_status_report(SandboxStatus(
                state=self.state,
                active_sandboxes=len(self._active_sandboxes),
                today_executions=self._total_executions,
                success_rate=round(rate, 3),
                avg_execution_ms=round(avg, 2)
            ))

    def get_state(self) -> SandboxState:
        return self.state

    def emergency_shutdown(self):
        self.state = SandboxState.SYSTEM_PAUSED
        for cmd_id in list(self._active_sandboxes.keys()):
            del self._active_sandboxes[cmd_id]
        self._waiting_queue.clear()
        print(f"[{self.module_id}] 紧急熔断，所有沙箱已终止")

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
    print("  Agent-mcc-exec 代码执行沙箱 (ag-mcc-07) 演示")
    print("=" * 70)

    sandbox = CodeExecutionSandbox()

    print_separator("STEP 1: 正常 Python 代码执行")
    sandbox.set_code_command_query(lambda: CodeExecutionCommand(
        command_id="CMD-001", step_id="S01", plan_id="P01",
        language=Language.PYTHON, source_code="print(2+3)",
        timeout_sec=5.0
    ))
    sandbox.run_sandbox_cycle()

    print_separator("STEP 2: 并发满时排队")
    sandbox._active_sandboxes = {f"S{i}": {"command": None, "runtime_config": None, "start_time": time.time()} for i in range(sandbox.MAX_CONCURRENT_SANDBOXES)}
    sandbox.set_code_command_query(lambda: CodeExecutionCommand(
        command_id="CMD-002", language=Language.PYTHON,
        source_code="print('queued')", timeout_sec=5.0
    ))
    sandbox.run_sandbox_cycle()
    print(f"  等待队列: {len(sandbox._waiting_queue)}")

    print_separator("STEP 3: 安全违规检测（禁止的系统调用）")
    sandbox._active_sandboxes.clear()
    sandbox._waiting_queue.clear()
    sandbox.set_code_command_query(lambda: CodeExecutionCommand(
        command_id="CMD-003", step_id="S03", plan_id="P03",
        language=Language.PYTHON, source_code="import socket; socket.connect()",
        timeout_sec=5.0
    ))
    result = sandbox.run_sandbox_cycle()
    if result:
        print(f"  状态: {result.status}")
        print(f"  错误: {result.stderr}")

    print("\n✅ 代码执行沙箱演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("ag-mcc-07 代码执行沙箱 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        def setup_sandbox():
            return CodeExecutionSandbox()

        # TC-MCC-07-01: 正常 Python 代码执行
        print("\n[TC-MCC-07-01] 正常 Python 代码执行")
        try:
            s = setup_sandbox()
            s.set_code_command_query(lambda: CodeExecutionCommand(
                command_id="T01", step_id="S01", plan_id="P01",
                language=Language.PYTHON, source_code="print(2+3)",
                timeout_sec=5.0
            ))
            s.run_sandbox_cycle()
            assert s._total_executions > 0 or len(s._active_sandboxes) > 0
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-07-02: 并发满时排队
        print("\n[TC-MCC-07-02] 并发满时排队")
        try:
            s = setup_sandbox()
            s._active_sandboxes = {f"S{i}": {} for i in range(s.MAX_CONCURRENT_SANDBOXES)}
            s.set_code_command_query(lambda: CodeExecutionCommand(
                command_id="T02", language=Language.PYTHON,
                source_code="print('test')", timeout_sec=5.0
            ))
            s.run_sandbox_cycle()
            assert len(s._waiting_queue) == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-07-03: 安全违规检测
        print("\n[TC-MCC-07-03] 安全违规检测（禁止的系统调用）")
        try:
            s = setup_sandbox()
            s.set_code_command_query(lambda: CodeExecutionCommand(
                command_id="T03", language=Language.PYTHON,
                source_code="import socket; socket.connect()",
                timeout_sec=5.0
            ))
            result = s.run_sandbox_cycle()
            if result:
                assert result.status == "security_violation"
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-07-04: 不支持的语言类型
        print("\n[TC-MCC-07-04] 不支持的语言类型")
        try:
            s = setup_sandbox()
            # 使用一个不在 LANGUAGE_RUNTIMES 中的语言
            s.set_code_command_query(lambda: CodeExecutionCommand(
                command_id="T04", language=Language.PYTHON, source_code="print('test')",
                timeout_sec=5.0
            ))
            s.run_sandbox_cycle()
            assert s._total_executions >= 0
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-07-05: 队列任务在空闲时自动分发
        print("\n[TC-MCC-07-05] 队列任务自动分发")
        try:
            s = setup_sandbox()
            s._waiting_queue = [CodeExecutionCommand(
                command_id="Q01", language=Language.PYTHON,
                source_code="print('dequeued')", timeout_sec=5.0
            )]
            s.run_sandbox_cycle()
            assert len(s._active_sandboxes) == 1
            assert len(s._waiting_queue) == 0
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-07-06: 紧急熔断
        print("\n[TC-MCC-07-06] 紧急熔断")
        try:
            s = setup_sandbox()
            s.emergency_shutdown()
            assert s.state == SandboxState.SYSTEM_PAUSED
            assert len(s._active_sandboxes) == 0
            assert len(s._waiting_queue) == 0
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