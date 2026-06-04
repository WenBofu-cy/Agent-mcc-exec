#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-08
模块名称: 文件操作执行器
所属分区: 三、调用执行引擎
核心职责: 在用户授权的文件路径范围内，安全地执行文件的读取、写入、创建、删除、列表查询等
          操作。基于 ag-mcc-05（工具参数校验器）已验证的路径白名单与安全约束，对每次文件
          操作进行路径合法性二次校验，防止路径穿越攻击。所有操作均在限定的工作目录下执行，
          操作完成后记录详细的文件变更审计日志。不参与文件内容的解析或业务决策，仅负责文件
          I/O 的精准执行与结果返回。

依赖模块:
    ag-mcc-01(执行调度核心), ag-mcc-04(工具注册中心), ag-mcc-05(工具参数校验器)
被依赖模块:
    ag-mcc-01, ag-mcc-03(资源配额管控单元), ag-mcc-12(执行日志记录单元)

安全约束:
  F-01: 所有文件操作必须在用户授权的白名单根目录下执行，禁止访问授权范围外的任何路径
  F-02: 路径穿越攻击检测为强制性安全检查，任何向上穿越的路径必须被拒绝并记录安全告警
  F-03: 禁止操作可执行文件（.exe, .sh, .bat 等），防止恶意代码植入
  F-04: 所有文件操作必须记录完整的审计日志
  F-05: 文件写入操作不支持追加模式写入系统关键配置文件
  F-06: 删除操作不可逆，执行前必须在审计日志中记录文件的完整元数据
"""

from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid
import hashlib
import os


class ExecutorState(Enum):
    WAITING_COMMAND = "waiting_command"
    EXECUTING = "executing"
    SYSTEM_PAUSED = "system_paused"


class FileOperation(Enum):
    READ = "读取"
    WRITE = "写入"
    CREATE = "创建"
    DELETE = "删除"
    LIST = "列出目录"
    MOVE = "移动/重命名"


@dataclass
class FileOperationCommand:
    command_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    operation: FileOperation = FileOperation.READ
    target_path: str = ""
    data_content: Optional[str] = None
    encoding: str = "utf-8"
    source_path: str = ""           # MOVE 操作时的源路径
    security_token: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class PathWhitelistConfig:
    authorized_root: str = "/home/user/workspace/"
    forbidden_patterns: List[str] = field(default_factory=lambda: [
        "/etc/", "/sys/", "/proc/", "C:\\Windows\\", "C:\\Program Files\\"
    ])
    forbidden_extensions: List[str] = field(default_factory=lambda: [
        ".exe", ".sh", ".bat", ".dll", ".so", ".cmd", ".ps1"
    ])
    max_file_size_bytes: int = 100 * 1024 * 1024  # 100MB
    allowed_operations: List[str] = field(default_factory=lambda: ["READ", "WRITE", "CREATE", "DELETE", "LIST", "MOVE"])


@dataclass
class PathValidationResult:
    valid: bool = True
    reject_reason: str = ""
    severity: str = ""  # "" / "路径违规" / "安全告警" / "文件类型限制"


@dataclass
class FileOperationResult:
    command_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    status: str = "success"  # success / failure / permission_denied / path_violation
    operation_detail: str = ""
    file_size: int = 0
    file_hash: str = ""
    duration_sec: float = 0.0
    error_code: str = ""
    error_message: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class FileChangeAuditLog:
    command_id: str = ""
    operation: str = ""
    target_path: str = ""
    operation_time: float = 0.0
    result: str = ""
    file_hash: str = ""
    data_size: int = 0


@dataclass
class ResourceReleaseNotice:
    command_id: str = ""
    storage_released_kb: float = 0.0


@dataclass
class ExecutorStatus:
    state: ExecutorState = ExecutorState.WAITING_COMMAND
    today_operations: int = 0
    operation_distribution: Dict[str, int] = field(default_factory=dict)
    success_rate: float = 0.0
    avg_duration_ms: float = 0.0


class FileOperationExecutor:
    # 统计上报间隔
    STATUS_REPORT_INTERVAL_SEC = 60

    def __init__(self):
        self.module_id = "ag-mcc-08"
        self.module_name = "文件操作执行器"
        self.version = "V1.0"

        self.state = ExecutorState.WAITING_COMMAND
        self._whitelist_config = PathWhitelistConfig()
        self._total_operations: int = 0
        self._success_count: int = 0
        self._operation_distribution: Dict[str, int] = {}
        self._total_duration: float = 0.0
        self._last_status_time: float = time.time()
        self._pending_logs: List[Dict[str, Any]] = []

        # 回调注入
        self._query_file_command = None
        self._query_whitelist_config = None

        self._publish_operation_result = None
        self._publish_audit_log = None
        self._publish_resource_release = None
        self._publish_status_report = None
        self._publish_event_log = None

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ========== 回调注入 ==========
    def set_file_command_query(self, callback: Callable[[], Optional[FileOperationCommand]]):
        self._query_file_command = callback

    def set_whitelist_config_query(self, callback: Callable[[], Optional[PathWhitelistConfig]]):
        self._query_whitelist_config = callback

    def set_operation_result_publisher(self, callback: Callable[[FileOperationResult], None]):
        self._publish_operation_result = callback

    def set_audit_log_publisher(self, callback: Callable[[FileChangeAuditLog], None]):
        self._publish_audit_log = callback

    def set_resource_release_publisher(self, callback: Callable[[ResourceReleaseNotice], None]):
        self._publish_resource_release = callback

    def set_status_report_publisher(self, callback: Callable[[ExecutorStatus], None]):
        self._publish_status_report = callback

    def set_event_log_publisher(self, callback: Callable[[Dict[str, Any]], None]):
        self._publish_event_log = callback

    # ========== 主循环 ==========
    def run_executor_cycle(self) -> Optional[FileOperationResult]:
        now = time.time()

        if self.state == ExecutorState.SYSTEM_PAUSED:
            return None

        # 定期状态上报
        if now - self._last_status_time >= self.STATUS_REPORT_INTERVAL_SEC:
            self._publish_status()
            self._last_status_time = now

        # 更新白名单配置
        config = self._query_whitelist_config() if self._query_whitelist_config else None
        if config:
            self._whitelist_config = config

        # 接收文件操作指令
        command = self._query_file_command() if self._query_file_command else None
        if command is None:
            return None

        self.state = ExecutorState.EXECUTING
        start_time = time.time()

        # 路径合法性二次校验
        path_check = self._validate_path(command.target_path, command.operation)
        if not path_check.valid:
            result = FileOperationResult(
                command_id=command.command_id,
                step_id=command.step_id,
                plan_id=command.plan_id,
                status="path_violation" if path_check.severity == "路径违规" else "permission_denied",
                error_code="PATH_VIOLATION" if path_check.severity == "路径违规" else "SECURITY_ALERT",
                error_message=path_check.reject_reason,
                duration_sec=time.time() - start_time
            )
            self._finalize_result(result, command)
            if path_check.severity == "安全告警":
                self._log_event("SECURITY_ALERT", {
                    "command_id": command.command_id,
                    "path": command.target_path,
                    "reason": path_check.reject_reason
                })
            return result

        # 执行操作
        result = self._execute_operation(command, start_time)
        return self._finalize_result(result, command)

    # ========== 路径校验 ==========
    def _validate_path(self, path: str, operation: FileOperation) -> PathValidationResult:
        config = self._whitelist_config

        # 检查是否在白名单根目录下
        if not path.startswith(config.authorized_root):
            return PathValidationResult(
                valid=False,
                reject_reason=f"路径不在授权范围内，必须在 {config.authorized_root} 下",
                severity="路径违规"
            )

        # 检查路径穿越
        if "../" in path or "..\\" in path:
            return PathValidationResult(
                valid=False,
                reject_reason="检测到路径穿越攻击特征",
                severity="安全告警"
            )

        # 检查禁止的目录模式
        for pattern in config.forbidden_patterns:
            if pattern.lower() in path.lower():
                return PathValidationResult(
                    valid=False,
                    reject_reason=f"禁止操作的目录: {pattern}",
                    severity="路径违规"
                )

        # 检查禁止的文件扩展名
        _, ext = os.path.splitext(path)
        if ext.lower() in [e.lower() for e in config.forbidden_extensions]:
            return PathValidationResult(
                valid=False,
                reject_reason=f"禁止操作的文件类型: {ext}",
                severity="文件类型限制"
            )

        return PathValidationResult(valid=True)

    # ========== 操作执行 ==========
    def _execute_operation(self, command: FileOperationCommand, start_time: float) -> FileOperationResult:
        op = command.operation
        path = command.target_path
        detail = ""
        file_size = 0
        file_hash = ""
        error_code = ""
        error_message = ""

        try:
            if op == FileOperation.READ:
                # 模拟读取文件
                detail = f"[模拟读取] 文件内容: {path}"
                file_size = len(detail)
                file_hash = hashlib.sha256(detail.encode()).hexdigest()[:16]

            elif op == FileOperation.WRITE:
                if not command.data_content:
                    return FileOperationResult(
                        command_id=command.command_id, step_id=command.step_id, plan_id=command.plan_id,
                        status="failure", error_code="EMPTY_DATA", error_message="写入数据为空"
                    )
                # 模拟写入
                file_size = len(command.data_content)
                file_hash = hashlib.sha256(command.data_content.encode()).hexdigest()[:16]
                detail = f"写入成功, 字节数={file_size}"

            elif op == FileOperation.CREATE:
                detail = f"文件创建成功: {path}"
                if command.data_content:
                    file_size = len(command.data_content)
                    file_hash = hashlib.sha256(command.data_content.encode()).hexdigest()[:16]

            elif op == FileOperation.DELETE:
                # 模拟删除
                detail = f"文件删除成功: {path}"
                file_size = 1024  # 模拟释放空间

            elif op == FileOperation.LIST:
                detail = f"目录列表: [file1.txt, file2.txt, subdir/]"

            elif op == FileOperation.MOVE:
                source = command.source_path or path
                source_check = self._validate_path(source, FileOperation.MOVE)
                if not source_check.valid:
                    return FileOperationResult(
                        command_id=command.command_id, step_id=command.step_id, plan_id=command.plan_id,
                        status="path_violation", error_code="PATH_VIOLATION",
                        error_message=f"源路径校验失败: {source_check.reject_reason}"
                    )
                detail = f"文件移动成功: {source} -> {path}"

            else:
                error_code = "UNKNOWN_OPERATION"
                error_message = f"未知的文件操作类型: {op}"

        except Exception as e:
            error_code = "EXECUTION_ERROR"
            error_message = str(e)

        duration = time.time() - start_time
        has_error = bool(error_code)

        return FileOperationResult(
            command_id=command.command_id,
            step_id=command.step_id,
            plan_id=command.plan_id,
            status="failure" if has_error else "success",
            operation_detail=detail,
            file_size=file_size,
            file_hash=file_hash,
            duration_sec=duration,
            error_code=error_code,
            error_message=error_message
        )

    def _finalize_result(self, result: FileOperationResult, command: FileOperationCommand) -> FileOperationResult:
        self._total_operations += 1
        if result.status == "success":
            self._success_count += 1
        op_name = command.operation.value
        self._operation_distribution[op_name] = self._operation_distribution.get(op_name, 0) + 1
        self._total_duration += result.duration_sec

        # 发送操作结果
        if self._publish_operation_result:
            self._publish_operation_result(result)

        # 记录审计日志
        if self._publish_audit_log:
            self._publish_audit_log(FileChangeAuditLog(
                command_id=command.command_id,
                operation=op_name,
                target_path=command.target_path,
                operation_time=time.time(),
                result=result.status,
                file_hash=result.file_hash,
                data_size=result.file_size
            ))

        # 删除操作释放资源
        if command.operation == FileOperation.DELETE and result.status == "success":
            if self._publish_resource_release:
                self._publish_resource_release(ResourceReleaseNotice(
                    command_id=command.command_id,
                    storage_released_kb=result.file_size / 1024.0
                ))

        self.state = ExecutorState.WAITING_COMMAND
        return result

    # ========== 辅助 ==========
    def _publish_status(self):
        if self._publish_status_report:
            rate = self._success_count / max(self._total_operations, 1)
            avg = self._total_duration / max(self._total_operations, 1) * 1000
            self._publish_status_report(ExecutorStatus(
                state=self.state,
                today_operations=self._total_operations,
                operation_distribution=self._operation_distribution.copy(),
                success_rate=round(rate, 3),
                avg_duration_ms=round(avg, 2)
            ))

    def get_state(self) -> ExecutorState:
        return self.state

    def emergency_shutdown(self):
        self.state = ExecutorState.SYSTEM_PAUSED
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
    print("  Agent-mcc-exec 文件操作执行器 (ag-mcc-08) 演示")
    print("=" * 70)

    executor = FileOperationExecutor()

    print_separator("STEP 1: 正常读取文件")
    executor.set_file_command_query(lambda: FileOperationCommand(
        command_id="CMD-001", step_id="S01", plan_id="P01",
        operation=FileOperation.READ,
        target_path="/home/user/workspace/data.txt"
    ))
    result = executor.run_executor_cycle()
    if result:
        print(f"  状态: {result.status}")
        print(f"  详情: {result.operation_detail}")

    print_separator("STEP 2: 路径穿越攻击被拦截")
    executor.set_file_command_query(lambda: FileOperationCommand(
        command_id="CMD-002", step_id="S02", plan_id="P02",
        operation=FileOperation.READ,
        target_path="../../../etc/passwd"
    ))
    result = executor.run_executor_cycle()
    if result:
        print(f"  状态: {result.status}")
        print(f"  错误: {result.error_message}")

    print_separator("STEP 3: 正常删除文件")
    executor.set_file_command_query(lambda: FileOperationCommand(
        command_id="CMD-003", step_id="S03", plan_id="P03",
        operation=FileOperation.DELETE,
        target_path="/home/user/workspace/old_file.txt"
    ))
    result = executor.run_executor_cycle()
    if result:
        print(f"  状态: {result.status}")

    print("\n✅ 文件操作执行器演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("ag-mcc-08 文件操作执行器 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        def setup_executor():
            return FileOperationExecutor()

        # TC-MCC-08-01: 正常读取文件
        print("\n[TC-MCC-08-01] 正常读取文件")
        try:
            e = setup_executor()
            e.set_file_command_query(lambda: FileOperationCommand(
                command_id="T01", operation=FileOperation.READ,
                target_path="/home/user/workspace/test.txt"
            ))
            result = e.run_executor_cycle()
            assert result is not None
            assert result.status == "success"
            print("   ✅ PASS")
            passed += 1
        except Exception as ex:
            print(f"   ❌ FAIL: {ex}")
            failed += 1

        # TC-MCC-08-02: 正常写入文件
        print("\n[TC-MCC-08-02] 正常写入文件")
        try:
            e = setup_executor()
            e.set_file_command_query(lambda: FileOperationCommand(
                command_id="T02", operation=FileOperation.WRITE,
                target_path="/home/user/workspace/output.txt",
                data_content="Hello World"
            ))
            result = e.run_executor_cycle()
            assert result is not None
            assert result.status == "success"
            print("   ✅ PASS")
            passed += 1
        except Exception as ex:
            print(f"   ❌ FAIL: {ex}")
            failed += 1

        # TC-MCC-08-03: 路径穿越攻击
        print("\n[TC-MCC-08-03] 路径穿越攻击被拦截")
        try:
            e = setup_executor()
            e.set_file_command_query(lambda: FileOperationCommand(
                command_id="T03", operation=FileOperation.READ,
                target_path="../../../etc/passwd"
            ))
            result = e.run_executor_cycle()
            assert result is not None
            assert result.status in ("path_violation", "permission_denied")
            print("   ✅ PASS")
            passed += 1
        except Exception as ex:
            print(f"   ❌ FAIL: {ex}")
            failed += 1

        # TC-MCC-08-04: 禁止的文件扩展名
        print("\n[TC-MCC-08-04] 禁止的文件扩展名")
        try:
            e = setup_executor()
            e.set_file_command_query(lambda: FileOperationCommand(
                command_id="T04", operation=FileOperation.READ,
                target_path="/home/user/workspace/script.sh"
            ))
            result = e.run_executor_cycle()
            assert result is not None
            assert result.status in ("path_violation", "permission_denied")
            print("   ✅ PASS")
            passed += 1
        except Exception as ex:
            print(f"   ❌ FAIL: {ex}")
            failed += 1

        # TC-MCC-08-05: 正常删除文件
        print("\n[TC-MCC-08-05] 正常删除文件")
        try:
            e = setup_executor()
            e.set_file_command_query(lambda: FileOperationCommand(
                command_id="T05", operation=FileOperation.DELETE,
                target_path="/home/user/workspace/old.txt"
            ))
            result = e.run_executor_cycle()
            assert result is not None
            assert result.status == "success"
            print("   ✅ PASS")
            passed += 1
        except Exception as ex:
            print(f"   ❌ FAIL: {ex}")
            failed += 1

        # TC-MCC-08-06: 紧急熔断
        print("\n[TC-MCC-08-06] 紧急熔断")
        try:
            e = setup_executor()
            e.emergency_shutdown()
            assert e.state == ExecutorState.SYSTEM_PAUSED
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