#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-07
模块名称: 代码执行沙箱
所属分区: 三、调用执行引擎
版本: V1.0
原创提出者: 文波福
开源协议: CC BY-NC 4.0

核心职责:
    在隔离的安全环境中执行由 ECC 认知大脑下发或用户提供的代码片段。基于沙箱技术
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

import time
import threading
import re
import ast
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import uuid
from concurrent.futures import ThreadPoolExecutor

# 全局线程池，托管沙箱执行任务，解耦主循环
EXECUTOR_POOL = ThreadPoolExecutor(max_workers=10, thread_name_prefix="sandbox-worker")

class SandboxState(Enum):
    WAITING_COMMAND = "WAITING_COMMAND"
    SANDBOX_SETUP = "SANDBOX_SETUP"
    EXECUTING = "EXECUTING"
    COLLECTING_RESULT = "COLLECTING_RESULT"
    SYSTEM_PAUSED = "SYSTEM_PAUSED"


class Language(Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    BASH = "bash"
    SQL = "sql"


@dataclass
class CodeExecutionCommand:
    instruction_id: str = ""
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
    read_only_fs: bool = True       # S-03 默认文件系统只读
    allow_network: bool = False     # S-02 默认禁止网络


@dataclass
class CodeExecutionResult:
    instruction_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    status: str = "success"
    stdout: str = ""
    stderr: str = ""
    return_value: Any = None
    actual_duration_sec: float = 0.0
    actual_memory_peak_mb: float = 0.0
    exit_code: int = 0
    resource_consumption: Dict[str, float] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class CodeExecutionSandbox:
    # 全局阈值配置
    DEFAULT_TIMEOUT_SEC = 30
    DEFAULT_MEMORY_MB = 128
    DEFAULT_CPU_CORES = 1
    DEFAULT_MAX_OUTPUT_KB = 1024
    MIN_TIMEOUT_SEC = 5
    MAX_TIMEOUT_SEC = 120
    MAX_CONCURRENT_SANDBOXES = 3
    STATUS_REPORT_INTERVAL_SEC = 60

    # 高危系统调用/关键字（网络、进程、文件写、逃逸）
    FORBIDDEN_KEYWORDS = {
        "socket", "connect", "bind", "listen", "accept", "requests", "urllib",
        "subprocess", "os.fork", "os.popen", "eval", "exec", "__import__",
        "open", "write", "mkdir", "rmdir", "chmod", "chown"
    }
    # 正则匹配高危代码片段
    FORBIDDEN_PATTERNS = [
        re.compile(r"os\.(system|popen|fork|execv)"),
        re.compile(r"import\s+(socket|requests|urllib)"),
        re.compile(r"__class__|__bases__|__subclasses__")  # 沙箱逃逸特征
    ]
    # 环境变量白名单
    ALLOWED_ENV_VARS = {"PATH", "LANG", "TZ", "USER"}

    # 多语言运行时配置
    LANGUAGE_RUNTIMES = {
        Language.PYTHON: LanguageRuntimeConfig(
            language=Language.PYTHON,
            sandbox_image="python:3.11-slim",
            preinstalled_libs=["math", "json", "datetime", "re", "collections", "itertools"],
            read_only_fs=True,
            allow_network=False
        ),
        Language.JAVASCRIPT: LanguageRuntimeConfig(
            language=Language.JAVASCRIPT,
            sandbox_image="node:20-alpine",
            read_only_fs=True,
            allow_network=False
        ),
        Language.BASH: LanguageRuntimeConfig(
            language=Language.BASH,
            sandbox_image="alpine:3.19",
            read_only_fs=True,
            allow_network=False
        ),
        Language.SQL: LanguageRuntimeConfig(
            language=Language.SQL,
            sandbox_image="sqlite:3.42",
            read_only_fs=True,
            allow_network=False
        ),
    }

    def __init__(self):
        self.module_id = "ag-mcc-07"
        self.module_name = "代码执行沙箱"
        self.version = "V1.0"

        # 总线引用
        self.bus = None

        self.state = SandboxState.WAITING_COMMAND
        self._lock = threading.Lock()
        self._active_sandboxes: Dict[str, Dict[str, Any]] = {}
        self._waiting_queue: List[CodeExecutionCommand] = []
        self._total_executions: int = 0
        self._success_count: int = 0
        self._total_execution_time: float = 0.0
        self._last_status_time: float = time.time()

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ====================== 主循环（SPEC 标准方法名） ======================
    def sandbox_main_loop(self):
        now = time.time()

        if self.state == SandboxState.SYSTEM_PAUSED:
            return

        # 定时状态上报
        if now - self._last_status_time >= self.STATUS_REPORT_INTERVAL_SEC:
            self._publish_status()
            self._last_status_time = now

        # 轮询沙箱任务状态
        for instruction_id in list(self._active_sandboxes.keys()):
            self._check_sandbox_completion(instruction_id, now)

        # 消费等待队列
        if self._waiting_queue and len(self._active_sandboxes) < self.MAX_CONCURRENT_SANDBOXES:
            next_cmd = self._waiting_queue.pop(0)
            self._setup_and_execute(next_cmd)

    # ====================== 消息处理（InternalBus） ======================
    def handle_message(self, message):
        if not self.bus:
            return

        data = message.data if message.data else {}
        topic = message.topic

        # 接收代码执行指令
        if topic == "ag-mcc-07.code_exec_command":
            cmd_lang = data.get("language", "python")
            command = CodeExecutionCommand(
                instruction_id=data.get("instruction_id", ""),
                step_id=data.get("step_id", ""),
                plan_id=data.get("plan_id", ""),
                language=Language(cmd_lang),
                source_code=data.get("code", ""),
                stdin_data=data.get("stdin_data"),
                timeout_sec=max(self.MIN_TIMEOUT_SEC, min(float(data.get("timeout_sec", 30.0)), self.MAX_TIMEOUT_SEC)),
                memory_limit_mb=float(data.get("memory_limit_mb", self.DEFAULT_MEMORY_MB)),
                cpu_limit=float(data.get("cpu_limit", self.DEFAULT_CPU_CORES)),
                security_token=data.get("security_token", ""),
                environment_vars=data.get("environment_vars", {})
            )

            if len(self._active_sandboxes) >= self.MAX_CONCURRENT_SANDBOXES:
                self._waiting_queue.append(command)
            else:
                self._setup_and_execute(command)

        # 全局调度指令
        elif topic == "ag-mcc-07.global_command":
            cmd = data.get("command", "")
            if cmd == "emergency_shutdown":
                self.emergency_shutdown()

    # ====================== 沙箱初始化 & 安全校验 ======================
    def _setup_and_execute(self, command: CodeExecutionCommand):
        self.state = SandboxState.SANDBOX_SETUP

        # 1. 校验运行时
        runtime_config = self.LANGUAGE_RUNTIMES.get(command.language)
        if runtime_config is None:
            result = CodeExecutionResult(
                instruction_id=command.instruction_id,
                step_id=command.step_id,
                plan_id=command.plan_id,
                status="failure",
                stderr=f"不支持的语言类型: {command.language.value}",
                exit_code=-1
            )
            self._finalize_result(result, command)
            return

        # 2. 环境变量白名单校验（加固安全）
        filtered_env = {}
        for k, v in command.environment_vars.items():
            if k in self.ALLOWED_ENV_VARS:
                filtered_env[k] = v
        command.environment_vars = filtered_env

        # 3. 静态代码安全检测（关键字 + 正则 + AST语法树）
        security_check = self._static_security_scan(command.source_code)
        if not security_check["pass"]:
            result = CodeExecutionResult(
                instruction_id=command.instruction_id,
                step_id=command.step_id,
                plan_id=command.plan_id,
                status="security_violation",
                stderr=f"安全拦截: {security_check['reason']}",
                exit_code=-1
            )
            self._finalize_result(result, command)
            # 推送安全告警
            self._send_security_alert(command.instruction_id, security_check["reason"])
            return

        # 4. 创建沙箱上下文
        context = {
            "command": command,
            "runtime_config": runtime_config,
            "start_time": time.time(),
            "memory_peak_mb": 0.0,
            "future": None
        }
        with self._lock:
            self._active_sandboxes[command.instruction_id] = context

        self.state = SandboxState.EXECUTING
        # 异步线程池执行代码，不阻塞主循环
        future = EXECUTOR_POOL.submit(self._sandbox_run_task, context)
        context["future"] = future

    def _static_security_scan(self, code: str) -> Dict[str, Any]:
        """多层静态安全扫描：关键字 + 正则 + AST语法树检测"""
        # 1. 关键字检测
        code_lower = code.lower()
        for keyword in self.FORBIDDEN_KEYWORDS:
            if keyword in code_lower:
                return {"pass": False, "reason": f"代码包含禁止关键字: {keyword}"}

        # 2. 正则匹配高危片段
        for pattern in self.FORBIDDEN_PATTERNS:
            if pattern.search(code):
                return {"pass": False, "reason": "检测到沙箱逃逸/高危系统调用代码"}

        # 3. Python AST 语法树深度检测（仅针对Python）
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                # 拦截危险导入、执行函数
                if isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
                    for name in node.names:
                        if name.name in ("socket", "subprocess", "requests"):
                            return {"pass": False, "reason": f"禁止导入模块: {name.name}"}
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                        return {"pass": False, "reason": "禁止使用 eval/exec 动态执行代码"}
        except SyntaxError:
            # 语法错误不属于安全违规，放行交由执行阶段处理
            pass

        return {"pass": True, "reason": ""}

    def _send_security_alert(self, instruction_id: str, detail: str):
        """发送安全告警至 ag-mcc-01"""
        if not self.bus:
            return
        self.bus.publish_to_module(
            target_module="ag-mcc-01",
            event_type="security_alert",
            source_module=self.module_id,
            data={
                "instruction_id": instruction_id,
                "violation_type": "沙箱安全违规",
                "violation_detail": detail,
                "severity": "高"
            }
        )

    # ====================== 沙箱异步执行任务 ======================
    def _sandbox_run_task(self, context: Dict[str, Any]) -> CodeExecutionResult:
        """子线程中模拟沙箱执行，生产环境替换为 docker/nsjail 真实沙箱"""
        command = context["command"]
        runtime = context["runtime_config"]
        start_time = context["start_time"]

        # 模拟代码执行
        time.sleep(min(command.timeout_sec * 0.3, 1.0))
        elapsed = time.time() - start_time

        # 模拟执行结果
        has_error = "error" in command.source_code.lower() or "exception" in command.source_code.lower()
        raw_stdout = f"[沙箱输出] 代码执行完成，耗时={elapsed:.2f}s"
        raw_stderr = "模拟运行异常" if has_error else ""

        # 输出大小截断（S-06 + 防溢出）
        max_bytes = self.DEFAULT_MAX_OUTPUT_KB * 1024
        stdout = self._truncate_output(raw_stdout, max_bytes)
        stderr = self._truncate_output(raw_stderr, max_bytes)

        # 模拟内存峰值
        mem_peak = min(command.memory_limit_mb * 0.3, 50.0)

        return CodeExecutionResult(
            instruction_id=command.instruction_id,
            step_id=command.step_id,
            plan_id=command.plan_id,
            status="failure" if has_error else "success",
            stdout=stdout,
            stderr=stderr,
            actual_duration_sec=elapsed,
            actual_memory_peak_mb=mem_peak,
            exit_code=1 if has_error else 0,
            resource_consumption={
                "memory_mb": mem_peak,
                "cpu_usage": command.cpu_limit
            }
        )

    def _truncate_output(self, content: str, max_bytes: int) -> str:
        """输出内容截断，避免超大输出"""
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > max_bytes:
            truncated = content_bytes[:max_bytes].decode("utf-8", errors="ignore")
            return f"{truncated}\n【输出已截断，超出 {self.DEFAULT_MAX_OUTPUT_KB}KB 限制】"
        return content

    # ====================== 状态轮询 & 结果收尾 ======================
    def _check_sandbox_completion(self, instruction_id: str, now: float):
        with self._lock:
            context = self._active_sandboxes.get(instruction_id)
        if not context:
            return

        command = context["command"]
        elapsed = now - context["start_time"]

        # 执行超时判定
        if elapsed >= command.timeout_sec:
            result = CodeExecutionResult(
                instruction_id=instruction_id,
                step_id=command.step_id,
                plan_id=command.plan_id,
                status="timeout",
                actual_duration_sec=command.timeout_sec,
                stderr="代码执行超时，已强制终止",
                exit_code=-2
            )
            self._finalize_result(result, command)
            return

        # 异步任务执行完成
        future = context.get("future")
        if future and future.done():
            self.state = SandboxState.COLLECTING_RESULT
            try:
                result = future.result()
            except Exception as e:
                result = CodeExecutionResult(
                    instruction_id=instruction_id,
                    step_id=command.step_id,
                    plan_id=command.plan_id,
                    status="failure",
                    stderr=f"沙箱内部异常: {str(e)}",
                    exit_code=-3
                )
            self._finalize_result(result, command)

    def _finalize_result(self, result: CodeExecutionResult, command: CodeExecutionCommand):
        with self._lock:
            if result.instruction_id in self._active_sandboxes:
                del self._active_sandboxes[result.instruction_id]

        # 全局统计更新
        self._total_executions += 1
        if result.status == "success":
            self._success_count += 1
        self._total_execution_time += result.actual_duration_sec

        # 回传结果至 ag-mcc-01
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
                    "output_data": result.stdout,
                    "error_code": str(result.exit_code),
                    "error_message": result.stderr,
                    "duration_sec": result.actual_duration_sec,
                    "resource_consumption": result.resource_consumption,
                    "timestamp": result.timestamp
                }
            )
            # 资源释放至 ag-mcc-03
            self.bus.publish_to_module(
                target_module="ag-mcc-03",
                event_type="resource_release",
                source_module=self.module_id,
                data={
                    "instruction_id": result.instruction_id,
                    "memory_released_mb": command.memory_limit_mb,
                    "cpu_time_released": result.actual_duration_sec
                }
            )

        # 回归空闲状态
        if not self._active_sandboxes and not self._waiting_queue:
            self.state = SandboxState.WAITING_COMMAND

    # ====================== 状态上报 & 运维接口 ======================
    def _publish_status(self):
        if not self.bus:
            return
        success_rate = self._success_count / max(self._total_executions, 1)
        avg_ms = (self._total_execution_time / max(self._total_executions, 1)) * 1000

        self.bus.publish_to_module(
            target_module="ag-mcc-12",
            event_type="engine_status",
            source_module=self.module_id,
            data={
                "state": self.state.value,
                "active_sandboxes": len(self._active_sandboxes),
                "today_executions": self._total_executions,
                "success_rate": round(success_rate, 3),
                "avg_execution_ms": round(avg_ms, 2)
            }
        )

    def get_state(self) -> SandboxState:
        return self.state

    def emergency_shutdown(self):
        """紧急熔断：终止所有任务、清空队列"""
        self.state = SandboxState.SYSTEM_PAUSED
        with self._lock:
            # 取消异步任务
            for ctx in self._active_sandboxes.values():
                fut = ctx.get("future")
                if fut and not fut.done():
                    fut.cancel()
            self._active_sandboxes.clear()
            self._waiting_queue.clear()
        print(f"[{self.module_id}] 紧急熔断，所有沙箱任务已终止")

    def shutdown(self):
        self.state = SandboxState.WAITING_COMMAND
        print(f"[{self.module_id}] 已安全关闭")


# ====================== 演示与测试 ======================
def demo_main():
    print("=" * 70)
    print("  ag-mcc-07 代码执行沙箱 V1.0 增强版 演示")
    print("=" * 70)

    from memory_bus import InternalBus
    bus = InternalBus()
    bus.register_module("ag-mcc-07")
    bus.register_module("ag-mcc-01")
    bus.register_module("ag-mcc-03")
    bus.register_module("ag-mcc-12")

    sandbox = CodeExecutionSandbox()
    sandbox.bus = bus
    bus.subscribe_to_module("ag-mcc-07", sandbox.handle_message)

    # 1. 正常代码执行
    print("\n[演示1] 正常 Python 代码执行")
    bus.publish_to_module("ag-mcc-07", "code_exec_command", "ag-mcc-01", {
        "instruction_id": "CMD-001",
        "step_id": "S01",
        "plan_id": "P01",
        "language": "python",
        "code": "print(2 + 3)",
        "timeout_sec": 5.0,
        "security_token": "valid-token"
    })
    bus.process_all()
    sandbox.sandbox_main_loop()
    time.sleep(0.2)
    sandbox.sandbox_main_loop()

    # 2. 网络调用安全拦截
    print("\n[演示2] 检测网络调用，触发安全告警")
    bus.publish_to_module("ag-mcc-07", "code_exec_command", "ag-mcc-01", {
        "instruction_id": "CMD-002",
        "step_id": "S02",
        "plan_id": "P02",
        "language": "python",
        "code": "import socket\nsocket.connect(('127.0.0.1', 80))",
        "timeout_sec": 5.0,
        "security_token": "valid-token"
    })
    bus.process_all()
    sandbox.sandbox_main_loop()

    # 3. 危险函数拦截
    print("\n[演示3] 检测 eval 危险函数，触发安全拦截")
    bus.publish_to_module("ag-mcc-07", "code_exec_command", "ag-mcc-01", {
        "instruction_id": "CMD-003",
        "step_id": "S03",
        "plan_id": "P03",
        "language": "python",
        "code": "eval('__import__(\"os\").system(\"ls\")')",
        "timeout_sec": 5.0,
        "security_token": "valid-token"
    })
    bus.process_all()
    sandbox.sandbox_main_loop()

    print(f"\n运行统计 -> 总执行: {sandbox._total_executions}, 成功: {sandbox._success_count}")
    print("\n✅ 所有演示执行完毕")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("单元测试入口已就绪，可扩展测试用例")
    else:
        demo_main()