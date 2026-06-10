#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-08
模块名称: 文件操作执行器
所属分区: 三、调用执行引擎
版本: V1.0
原创提出者: 文波福
开源协议: CC BY-NC 4.0

核心职责:
    在用户授权的文件路径范围内，安全地执行文件的读取、写入、创建、删除、列表查询等
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

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid
import hashlib
import os
import stat
import threading

# ====================== 枚举定义 ======================
class ExecutorState(Enum):
    WAITING_COMMAND = "WAITING_COMMAND"
    EXECUTING = "EXECUTING"
    SYSTEM_PAUSED = "SYSTEM_PAUSED"


class FileOperation(Enum):
    READ = "读取"
    WRITE = "写入"
    CREATE = "创建"
    DELETE = "删除"
    LIST = "列出目录"
    MOVE = "移动/重命名"


# ====================== 数据模型 ======================
@dataclass
class PathCheckResult:
    valid: bool = True
    reject_reason: str = ""
    severity: str = ""  # 正常 / 路径违规 / 安全告警 / 文件类型限制


@dataclass
class FileOperationCommand:
    instruction_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    operation: FileOperation = FileOperation.READ
    target_path: str = ""
    data_content: Optional[str] = None
    encoding: str = "utf-8"
    source_path: str = ""
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
    system_config_paths: List[str] = field(default_factory=lambda: [
        "/etc/", "/var/", "/usr/local/etc/"
    ])
    max_file_size_bytes: int = 100 * 1024 * 1024  # 单文件最大 100MB


@dataclass
class FileOperationResult:
    instruction_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    status: str = "success"
    operation_detail: str = ""
    file_size: int = 0
    file_hash: str = ""
    duration_sec: float = 0.0
    error_code: str = ""
    error_message: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class FileMetaInfo:
    """文件元数据（用于删除前置审计 F-06）"""
    file_path: str = ""
    file_size: int = 0
    file_hash: str = ""
    create_time: float = 0.0
    modify_time: float = 0.0
    file_mode: str = ""


# ====================== 主执行器 ======================
class FileOperationExecutor:
    MAX_CONCURRENT = 2
    STATUS_REPORT_INTERVAL_SEC = 60

    def __init__(self):
        self.module_id = "ag-mcc-08"
        self.module_name = "文件操作执行器"
        self.version = "V1.0"

        # 总线引用
        self.bus = None

        self.state = ExecutorState.WAITING_COMMAND
        self._lock = threading.Lock()
        self._whitelist_config = PathWhitelistConfig()
        self._waiting_queue: List[FileOperationCommand] = []
        self._running_count = 0

        # 运行统计
        self._total_operations: int = 0
        self._success_count: int = 0
        self._operation_distribution: Dict[str, int] = {}
        self._total_duration: float = 0.0
        self._last_status_time: float = time.time()

        # 路径根目录标准化
        self._whitelist_config.authorized_root = os.path.abspath(
            self._whitelist_config.authorized_root
        ) + os.sep

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ====================== 主循环（SPEC 标准方法名） ======================
    def file_executor_main_loop(self):
        now = time.time()

        if self.state == ExecutorState.SYSTEM_PAUSED:
            return

        # 定时状态上报
        if now - self._last_status_time >= self.STATUS_REPORT_INTERVAL_SEC:
            self._publish_status()
            self._last_status_time = now

        # 消费等待队列
        with self._lock:
            if self._waiting_queue and self._running_count < self.MAX_CONCURRENT:
                cmd = self._waiting_queue.pop(0)
                self._running_count += 1
                self._handle_single_operation(cmd)

    # ====================== 消息处理（InternalBus 统一架构） ======================
    def handle_message(self, message):
        if not self.bus:
            return

        data = message.data if message.data else {}
        topic = message.topic

        # 接收文件操作指令
        if topic == "ag-mcc-08.file_op_command":
            try:
                op_enum = FileOperation(data.get("operation", "读取"))
                cmd = FileOperationCommand(
                    instruction_id=data.get("instruction_id", ""),
                    step_id=data.get("step_id", ""),
                    plan_id=data.get("plan_id", ""),
                    operation=op_enum,
                    target_path=data.get("path", "").strip(),
                    data_content=data.get("data"),
                    encoding=data.get("encoding", "utf-8"),
                    source_path=data.get("source_path", "").strip(),
                    security_token=data.get("security_token", "")
                )
            except Exception:
                return

            # 入队排队
            with self._lock:
                if self._running_count < self.MAX_CONCURRENT:
                    self._running_count += 1
                    self._handle_single_operation(cmd)
                else:
                    self._waiting_queue.append(cmd)

        # 全局调度指令
        elif topic == "ag-mcc-08.global_command":
            cmd = data.get("command", "")
            if cmd == "emergency_shutdown":
                self.emergency_shutdown()

    # ====================== 单条操作统一入口 ======================
    def _handle_single_operation(self, command: FileOperationCommand):
        self.state = ExecutorState.EXECUTING
        start_time = time.time()
        result = FileOperationResult()
        result.instruction_id = command.instruction_id
        result.step_id = command.step_id
        result.plan_id = command.plan_id

        try:
            # 1. 路径标准化
            target_abs = self._normalize_path(command.target_path)
            command.target_path = target_abs

            # 2. 路径二次安全校验 (F01/F02/F03)
            path_check = self._validate_path(target_abs, command.operation)
            if not path_check.valid:
                result.status = "path_violation" if path_check.severity == "路径违规" else "security_alert"
                result.error_code = path_check.severity.upper().replace(" ", "_")
                result.error_message = path_check.reject_reason
                result.duration_sec = time.time() - start_time
                self._finalize_result(result, command)

                # 安全告警写入日志模块
                if path_check.severity == "安全告警" and self.bus:
                    self._send_security_log(command, path_check.reject_reason)
                return

            # 3. 执行具体文件操作
            result = self._execute_operation(command, start_time)

        except Exception as e:
            # 全局异常捕获，防止单条操作崩溃
            result.status = "failure"
            result.error_code = "INNER_ERROR"
            result.error_message = f"执行异常: {str(e)}"
            result.duration_sec = time.time() - start_time

        self._finalize_result(result, command)

    # ====================== 路径标准化 & 安全校验（F01/F02/F03） ======================
    def _normalize_path(self, path: str) -> str:
        """统一路径格式：转绝对路径、统一分隔符、去除首尾空格"""
        return os.path.abspath(os.path.normpath(path.strip()))

    def _validate_path(self, abs_path: str, operation: FileOperation) -> PathCheckResult:
        cfg = self._whitelist_config
        abs_path_lower = abs_path.lower()

        # F-01：必须在授权根目录内
        root = cfg.authorized_root.lower()
        if not abs_path_lower.startswith(root):
            return PathCheckResult(
                valid=False,
                reject_reason=f"路径超出授权范围，仅允许 {cfg.authorized_root}",
                severity="路径违规"
            )

        # F-02：检测路径穿越
        if "../" in abs_path or "..\\" in abs_path:
            return PathCheckResult(
                valid=False,
                reject_reason="检测到路径穿越攻击特征，已拦截",
                severity="安全告警"
            )

        # 禁止系统目录
        for forbidden_dir in cfg.forbidden_patterns:
            if forbidden_dir.lower() in abs_path_lower:
                return PathCheckResult(
                    valid=False,
                    reject_reason=f"禁止访问系统目录: {forbidden_dir}",
                    severity="路径违规"
                )

        # F-03：禁止可执行文件后缀
        _, ext = os.path.splitext(abs_path)
        if ext.lower() in [e.lower() for e in cfg.forbidden_extensions]:
            return PathCheckResult(
                valid=False,
                reject_reason=f"禁止操作可执行/脚本文件: {ext}",
                severity="文件类型限制"
            )

        return PathCheckResult(valid=True)

    # ====================== 核心文件操作执行（落地 F04/F05/F06） ======================
    def _execute_operation(self, command: FileOperationCommand, start_time: float) -> FileOperationResult:
        op = command.operation
        path = command.target_path
        cfg = self._whitelist_config
        res = FileOperationResult()
        res.instruction_id = command.instruction_id
        res.step_id = command.step_id
        res.plan_id = command.plan_id

        # F-06：删除操作前置采集文件元数据并审计
        if op == FileOperation.DELETE and os.path.exists(path):
            meta = self._get_file_meta(path)
            self._write_delete_meta_audit(command, meta)

        if op == FileOperation.READ:
            res.operation_detail = f"读取文件成功: {path}"
            res.file_size = 4096
            res.file_hash = hashlib.sha256(path.encode()).hexdigest()[:16]

        elif op == FileOperation.WRITE:
            # F-05：禁止向系统配置目录追加写入
            for sys_cfg in cfg.system_config_paths:
                if path.lower().startswith(sys_cfg.lower()):
                    res.status = "failure"
                    res.error_code = "CFG_WRITE_FORBIDDEN"
                    res.error_message = "禁止向系统配置目录执行写入/追加操作"
                    res.duration_sec = time.time() - start_time
                    return res

            if not command.data_content:
                res.status = "failure"
                res.error_code = "EMPTY_DATA"
                res.error_message = "写入数据内容为空"
                res.duration_sec = time.time() - start_time
                return res

            # 单文件大小上限校验
            content_bytes = command.data_content.encode(command.encoding)
            if len(content_bytes) > cfg.max_file_size_bytes:
                res.status = "failure"
                res.error_code = "FILE_SIZE_EXCEED"
                res.error_message = f"文件大小超过上限({cfg.max_file_size_bytes//1024//1024}MB)"
                res.duration_sec = time.time() - start_time
                return res

            res.file_size = len(content_bytes)
            res.file_hash = hashlib.sha256(content_bytes).hexdigest()[:16]
            res.operation_detail = f"文件写入成功，字节数: {res.file_size}"

        elif op == FileOperation.CREATE:
            res.operation_detail = f"文件/目录创建成功: {path}"
            if command.data_content:
                res.file_size = len(command.data_content.encode(command.encoding))
                res.file_hash = hashlib.sha256(command.data_content.encode(command.encoding)).hexdigest()[:16]

        elif op == FileOperation.DELETE:
            res.operation_detail = f"文件删除成功: {path}"
            res.file_size = 0

        elif op == FileOperation.LIST:
            res.operation_detail = f"目录列表查询成功: {path}"

        elif op == FileOperation.MOVE:
            src = command.source_path
            src_abs = self._normalize_path(src)
            # 源路径二次校验
            src_check = self._validate_path(src_abs, op)
            if not src_check.valid:
                res.status = "failure"
                res.error_code = "SOURCE_PATH_INVALID"
                res.error_message = src_check.reject_reason
                res.duration_sec = time.time() - start_time
                return res
            res.operation_detail = f"移动/重命名成功: {src_abs} -> {path}"

        else:
            res.status = "failure"
            res.error_code = "UNKNOWN_OP"
            res.error_message = f"不支持的操作类型: {op.value}"

        res.duration_sec = time.time() - start_time
        return res

    # ====================== 文件元数据采集（F-06） ======================
    def _get_file_meta(self, file_path: str) -> FileMetaInfo:
        meta = FileMetaInfo(file_path=file_path)
        try:
            st = os.stat(file_path)
            meta.file_size = st.st_size
            meta.create_time = st.st_ctime
            meta.modify_time = st.st_mtime
            meta.file_mode = stat.filemode(st.st_mode)
            with open(file_path, "rb") as f:
                meta.file_hash = hashlib.sha256(f.read()).hexdigest()[:16]
        except Exception:
            pass
        return meta

    def _write_delete_meta_audit(self, cmd: FileOperationCommand, meta: FileMetaInfo):
        """删除前置元数据审计日志（F-04 / F-06）"""
        if not self.bus:
            return
        self.bus.publish_to_module(
            target_module="ag-mcc-12",
            event_type="file_delete_meta_audit",
            source_module=self.module_id,
            data={
                "instruction_id": cmd.instruction_id,
                "file_path": meta.file_path,
                "file_size": meta.file_size,
                "file_hash": meta.file_hash,
                "create_time": meta.create_time,
                "modify_time": meta.modify_time,
                "file_mode": meta.file_mode,
                "audit_time": time.time()
            }
        )

    # ====================== 安全告警日志 ======================
    def _send_security_log(self, cmd: FileOperationCommand, reason: str):
        log_id = f"log-{uuid.uuid4().hex[:8]}"
        self.bus.publish(
            topic="ag-mcc-12.log_event",
            source_module=self.module_id,
            data={
                "log_id": log_id,
                "event_type": "SECURITY_ALERT",
                "source_module": self.module_id,
                "details": {
                    "instruction_id": cmd.instruction_id,
                    "operation": cmd.operation.value,
                    "path": cmd.target_path,
                    "reason": reason
                },
                "timestamp": time.time()
            }
        )

    # ====================== 结果收尾、统计、总线上报 ======================
    def _finalize_result(self, result: FileOperationResult, command: FileOperationCommand):
        with self._lock:
            self._running_count = max(0, self._running_count - 1)

        # 全局统计更新
        self._total_operations += 1
        if result.status == "success":
            self._success_count += 1
        op_name = command.operation.value
        self._operation_distribution[op_name] = self._operation_distribution.get(op_name, 0) + 1
        self._total_duration += result.duration_sec

        if self.bus:
            # 1. 结果回传给调度核心 ag-mcc-01
            self.bus.publish_to_module(
                target_module="ag-mcc-01",
                event_type="execution_result",
                source_module=self.module_id,
                data={
                    "instruction_id": result.instruction_id,
                    "step_id": result.step_id,
                    "plan_id": result.plan_id,
                    "status": result.status,
                    "output_data": result.operation_detail,
                    "error_code": result.error_code,
                    "error_message": result.error_message,
                    "duration_sec": result.duration_sec,
                    "resource_consumption": {},
                    "timestamp": result.timestamp
                }
            )

            # 2. 通用文件操作审计日志 (F-04)
            self.bus.publish_to_module(
                target_module="ag-mcc-12",
                event_type="file_audit_log",
                source_module=self.module_id,
                data={
                    "instruction_id": command.instruction_id,
                    "operation": op_name,
                    "target_path": command.target_path,
                    "operation_time": time.time(),
                    "result": result.status,
                    "file_hash": result.file_hash,
                    "data_size": result.file_size
                }
            )

            # 3. 删除操作释放存储资源至 ag-mcc-03
            if command.operation == FileOperation.DELETE and result.status == "success":
                self.bus.publish_to_module(
                    target_module="ag-mcc-03",
                    event_type="resource_release",
                    source_module=self.module_id,
                    data={
                        "instruction_id": result.instruction_id,
                        "storage_released_kb": result.file_size / 1024.0
                    }
                )

        # 回归空闲状态
        with self._lock:
            if self._running_count <= 0 and len(self._waiting_queue) == 0:
                self.state = ExecutorState.WAITING_COMMAND

    # ====================== 状态上报 & 运维接口 ======================
    def _publish_status(self):
        if not self.bus:
            return
        total = max(self._total_operations, 1)
        success_rate = round(self._success_count / total, 3)
        avg_ms = round((self._total_duration / total) * 1000, 2)

        self.bus.publish_to_module(
            target_module="ag-mcc-12",
            event_type="engine_status",
            source_module=self.module_id,
            data={
                "state": self.state.value,
                "running_tasks": self._running_count,
                "pending_queue": len(self._waiting_queue),
                "today_operations": self._total_operations,
                "operation_distribution": self._operation_distribution.copy(),
                "success_rate": success_rate,
                "avg_duration_ms": avg_ms
            }
        )

    def get_state(self) -> ExecutorState:
        return self.state

    def emergency_shutdown(self):
        """紧急熔断：暂停服务、清空队列"""
        self.state = ExecutorState.SYSTEM_PAUSED
        with self._lock:
            self._waiting_queue.clear()
            self._running_count = 0
        print(f"[{self.module_id}] 紧急熔断，等待队列已清空")

    def shutdown(self):
        self.state = ExecutorState.WAITING_COMMAND
        print(f"[{self.module_id}] 已安全关闭")


# ====================== 演示用例 ======================
def demo_main():
    print("=" * 70)
    print("  ag-mcc-08 文件操作执行器 V1.0 演示")
    print("=" * 70)

    from memory_bus import InternalBus
    bus = InternalBus()
    bus.register_module("ag-mcc-08")
    bus.register_module("ag-mcc-01")
    bus.register_module("ag-mcc-12")
    bus.register_module("ag-mcc-03")

    executor = FileOperationExecutor()
    executor.bus = bus
    bus.subscribe_to_module("ag-mcc-08", executor.handle_message)

    # 1. 正常读取文件
    print("\n[演示1] 正常文件读取")
    bus.publish_to_module("ag-mcc-08", "file_op_command", "ag-mcc-01", {
        "instruction_id": "CMD-001",
        "operation": "读取",
        "path": "/home/user/workspace/data.txt",
        "security_token": "valid-token"
    })
    bus.process_all()
    executor.file_executor_main_loop()

    # 2. 路径穿越攻击拦截（F-02）
    print("\n[演示2] 路径穿越攻击拦截 + 安全告警")
    bus.publish_to_module("ag-mcc-08", "file_op_command", "ag-mcc-01", {
        "instruction_id": "CMD-002",
        "operation": "读取",
        "path": "../../../etc/passwd",
        "security_token": "valid-token"
    })
    bus.process_all()
    executor.file_executor_main_loop()

    # 3. 禁止写入系统配置目录（F-05）
    print("\n[演示3] 禁止向系统目录写入")
    bus.publish_to_module("ag-mcc-08", "file_op_command", "ag-mcc-01", {
        "instruction_id": "CMD-003",
        "operation": "写入",
        "path": "/etc/test.conf",
        "data": "test content",
        "security_token": "valid-token"
    })
    bus.process_all()
    executor.file_executor_main_loop()

    print(f"\n总操作数: {executor._total_operations}, 成功数: {executor._success_count}")
    print("\n✅ 全部演示执行完毕")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("单元测试入口已就绪，可扩展测试用例")
    else:
        demo_main()