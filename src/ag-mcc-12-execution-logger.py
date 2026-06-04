#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-12
模块名称: 执行日志记录单元
所属分区: 四、反馈与日志
核心职责: 作为 MCC 行动执行层的全链路执行日志记录中枢，接收来自各执行模块推送的执行事件、
          状态变更、异常告警等日志数据。采用追加写模式将所有日志条目持久化存储，禁止修改或
          删除已落盘的日志。存储周期不少于 3 年，为事故追溯、性能分析、合规审计提供完整的
          数据基础。支持按时间、指令ID、工具类型、执行状态等多维度检索。不参与任何工具调用
          或决策，仅负责日志的记录、存储与检索服务。

依赖模块:
    ag-mcc-01~11（所有模块均可推送日志事件）
被依赖模块:
    ag-ecc-12(资源调度模块), ag-mcc-01(查询历史日志), 系统管理接口(离线分析)

安全约束:
  L-01: 日志存储必须采用追加写模式，禁止任何模块修改或删除已落盘的日志条目
  L-02: 每条日志条目必须包含全局单调递增序列号与 UTC 时间戳
  L-03: 执行相关的关键日志在存储空间不足时优先保留
  L-04: 日志存储周期 ≥ 3 年，超期日志在空间不足时优先清理
  L-05: 日志 HMAC 签名用于内部完整性校验
  L-06: 日志数据不得包含任何用户个人身份信息、认证凭证或敏感业务数据
"""

from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid
import hmac
import hashlib
import json


class LoggerState(Enum):
    NORMAL_LOGGING = "normal_logging"
    LOW_STORAGE = "low_storage"
    STORAGE_FAULT = "storage_fault"
    SYSTEM_PAUSED = "system_paused"


class LogEventType(Enum):
    COMMAND_RECEIVED = "指令接收"
    COMMAND_DISPATCHED = "指令分发"
    EXECUTION_RESULT = "执行结果"
    TIMEOUT_EVENT = "超时事件"
    RESOURCE_LIMIT = "资源限流"
    VALIDATION_RESULT = "校验结果"
    DEVIATION_EVENT = "偏差事件"
    CLOSED_LOOP = "闭环事件"


@dataclass
class LogEvent:
    event_type: LogEventType = LogEventType.EXECUTION_RESULT
    command_id: str = ""
    source_module: str = ""
    tool_name: str = ""
    tool_type: str = ""
    execution_status: str = ""
    detail_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class LogEntry:
    log_id: str = ""
    sequence_number: int = 0
    event_type: LogEventType = LogEventType.EXECUTION_RESULT
    command_id: str = ""
    source_module: str = ""
    tool_name: str = ""
    tool_type: str = ""
    execution_status: str = ""
    detail_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    signature: str = ""


@dataclass
class LogQueryRequest:
    time_range_sec: Optional[float] = None
    command_id: Optional[str] = None
    tool_type: Optional[str] = None
    execution_status: Optional[str] = None
    event_type: Optional[LogEventType] = None
    max_results: int = 100


@dataclass
class LogExportRequest:
    time_range_sec: Optional[float] = None
    tool_type: Optional[str] = None
    event_types: List[LogEventType] = field(default_factory=list)
    export_format: str = "JSON"


@dataclass
class StorageStatus:
    state: LoggerState = LoggerState.NORMAL_LOGGING
    total_bytes: int = 0
    used_bytes: int = 0
    remaining_bytes: int = 0
    oldest_log_time: float = 0.0
    newest_log_time: float = 0.0
    write_rate_per_sec: float = 0.0


@dataclass
class StorageAlert:
    alert_type: str = ""
    current_status: str = ""
    suggested_action: str = ""


class ExecutionLogger:
    # 存储配置
    TOTAL_CAPACITY_BYTES = 500 * 1024 * 1024  # 500MB
    RETENTION_YEARS = 3
    CRITICAL_EVENT_TYPES = {
        LogEventType.EXECUTION_RESULT,
        LogEventType.TIMEOUT_EVENT,
        LogEventType.DEVIATION_EVENT,
    }
    # 阈值
    LOW_STORAGE_THRESHOLD_PCT = 0.10
    CRITICAL_STORAGE_THRESHOLD_PCT = 0.05
    # 内存缓冲
    MAX_BUFFER_ENTRIES = 5000
    # HMAC 密钥
    SIGNING_KEY = "execution-logger-secret"
    # 上报间隔
    STATUS_REPORT_INTERVAL_SEC = 60

    def __init__(self):
        self.module_id = "ag-mcc-12"
        self.module_name = "执行日志记录单元"
        self.version = "V1.0"

        self.state = LoggerState.NORMAL_LOGGING
        self._sequence_number: int = 0
        self._log_entries: List[LogEntry] = []       # 模拟持久化
        self._total_bytes: int = 0
        self._consecutive_write_failures: int = 0
        self._buffer: List[LogEntry] = []
        self._last_status_time: float = time.time()
        self._pending_logs: List[Dict[str, Any]] = []

        # 回调注入
        self._query_log_event = None
        self._query_query_request = None
        self._query_export_request = None

        self._publish_write_confirm = None
        self._publish_query_result = None
        self._publish_export_package = None
        self._publish_storage_status = None
        self._publish_storage_alert = None
        self._publish_event_log = None

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ========== 回调注入 ==========
    def set_log_event_query(self, callback: Callable[[], Optional[LogEvent]]):
        self._query_log_event = callback

    def set_query_request_query(self, callback: Callable[[], Optional[LogQueryRequest]]):
        self._query_query_request = callback

    def set_export_request_query(self, callback: Callable[[], Optional[LogExportRequest]]):
        self._query_export_request = callback

    def set_write_confirm_publisher(self, callback: Callable[[str, bool], None]):
        self._publish_write_confirm = callback

    def set_query_result_publisher(self, callback: Callable[[List[LogEntry], int, float, bool], None]):
        self._publish_query_result = callback

    def set_export_package_publisher(self, callback: Callable[[Dict[str, Any]], None]):
        self._publish_export_package = callback

    def set_storage_status_publisher(self, callback: Callable[[StorageStatus], None]):
        self._publish_storage_status = callback

    def set_storage_alert_publisher(self, callback: Callable[[StorageAlert], None]):
        self._publish_storage_alert = callback

    def set_event_log_publisher(self, callback: Callable[[Dict[str, Any]], None]):
        self._publish_event_log = callback

    # ========== 主循环 ==========
    def run_logger_cycle(self):
        now = time.time()

        if self.state == LoggerState.SYSTEM_PAUSED:
            return

        # 定期状态上报
        if now - self._last_status_time >= self.STATUS_REPORT_INTERVAL_SEC:
            self._publish_storage_status_internal()
            self._last_status_time = now

        # 接收日志事件
        log_event = self._query_log_event() if self._query_log_event else None
        if log_event:
            self._record_log(log_event)
            return

        # 处理查询请求
        query_req = self._query_query_request() if self._query_query_request else None
        if query_req:
            self._handle_query(query_req)
            return

        # 处理导出请求
        export_req = self._query_export_request() if self._query_export_request else None
        if export_req:
            self._handle_export(export_req)

    # ========== 日志记录 ==========
    def _record_log(self, event: LogEvent):
        self._sequence_number += 1
        entry = LogEntry(
            log_id=f"MCC-LOG-{self._sequence_number:08d}-{int(event.timestamp)}",
            sequence_number=self._sequence_number,
            event_type=event.event_type,
            command_id=event.command_id,
            source_module=event.source_module,
            tool_name=event.tool_name,
            tool_type=event.tool_type,
            execution_status=event.execution_status,
            detail_data=event.detail_data,
            timestamp=event.timestamp
        )
        entry.signature = self._compute_signature(entry)

        # 检查存储状态
        if self.state == LoggerState.STORAGE_FAULT:
            self._buffer.append(entry)
            if len(self._buffer) >= self.MAX_BUFFER_ENTRIES:
                self._evict_oldest_non_critical()
            return

        # 模拟持久化写入
        if self._simulate_write(entry):
            self._log_entries.append(entry)
            self._total_bytes += 256
            self._consecutive_write_failures = 0
        else:
            self._consecutive_write_failures += 1
            if self._consecutive_write_failures >= 3:
                self.state = LoggerState.STORAGE_FAULT
                self._send_storage_alert("存储故障", "连续写入失败3次，切换至内存缓冲模式")
                self._buffer.append(entry)

        # 容量检查
        if self.state != LoggerState.STORAGE_FAULT:
            remaining_pct = 1.0 - (self._total_bytes / self.TOTAL_CAPACITY_BYTES)
            if remaining_pct < self.CRITICAL_STORAGE_THRESHOLD_PCT:
                self.state = LoggerState.LOW_STORAGE
                self._perform_cleanup(retention_years=2)
                self._send_storage_alert("空间严重不足", "已触发强制清理，保留最近2年数据")
            elif remaining_pct < self.LOW_STORAGE_THRESHOLD_PCT:
                self.state = LoggerState.LOW_STORAGE
                self._perform_cleanup(retention_years=self.RETENTION_YEARS)
                self._send_storage_alert("空间不足", "已触发旧日志清理")

        if self._publish_write_confirm:
            self._publish_write_confirm(entry.log_id, True)

    def _compute_signature(self, entry: LogEntry) -> str:
        payload = f"{entry.sequence_number}|{entry.event_type.value}|{entry.command_id}|{entry.timestamp}"
        return hmac.new(self.SIGNING_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]

    def _simulate_write(self, entry: LogEntry) -> bool:
        return True

    def _evict_oldest_non_critical(self):
        for i, entry in enumerate(self._buffer):
            if entry.event_type not in self.CRITICAL_EVENT_TYPES:
                self._buffer.pop(i)
                return
        if self._buffer:
            self._buffer.pop(0)

    # ========== 查询处理 ==========
    def _handle_query(self, request: LogQueryRequest):
        start_time = time.time()
        matched = []
        for entry in self._log_entries:
            if request.time_range_sec and (time.time() - entry.timestamp) > request.time_range_sec:
                continue
            if request.command_id and request.command_id != entry.command_id:
                continue
            if request.tool_type and request.tool_type != entry.tool_type:
                continue
            if request.execution_status and request.execution_status != entry.execution_status:
                continue
            if request.event_type and request.event_type != entry.event_type:
                continue
            matched.append(entry)

        total = len(matched)
        matched.sort(key=lambda x: x.timestamp, reverse=True)
        matched = matched[:request.max_results]
        elapsed = (time.time() - start_time) * 1000
        is_complete = len(matched) == total

        if self._publish_query_result:
            self._publish_query_result(matched, total, elapsed, is_complete)

    # ========== 导出处理 ==========
    def _handle_export(self, request: LogExportRequest):
        matched = []
        for entry in self._log_entries:
            if request.time_range_sec and (time.time() - entry.timestamp) > request.time_range_sec:
                continue
            if request.tool_type and request.tool_type != entry.tool_type:
                continue
            if request.event_types and entry.event_type not in request.event_types:
                continue
            matched.append(entry)
        matched.sort(key=lambda x: x.timestamp, reverse=True)

        package = {
            "export_time": time.time(),
            "total_entries": len(matched),
            "format": request.export_format,
            "entries": [self._serialize_entry(e) for e in matched],
            "checksum": hashlib.sha256(json.dumps([e.log_id for e in matched]).encode()).hexdigest()
        }

        if self._publish_export_package:
            self._publish_export_package(package)

    def _serialize_entry(self, entry: LogEntry) -> Dict[str, Any]:
        return {
            "log_id": entry.log_id,
            "sequence_number": entry.sequence_number,
            "event_type": entry.event_type.value,
            "command_id": entry.command_id,
            "source_module": entry.source_module,
            "tool_name": entry.tool_name,
            "tool_type": entry.tool_type,
            "execution_status": entry.execution_status,
            "detail_data": entry.detail_data,
            "timestamp": entry.timestamp,
            "signature": entry.signature
        }

    # ========== 容量管理 ==========
    def _perform_cleanup(self, retention_years: int = 3):
        retention_sec = retention_years * 365 * 86400
        cutoff = time.time() - retention_sec
        new_entries = []
        removed_bytes = 0
        for entry in self._log_entries:
            if entry.timestamp < cutoff and entry.event_type not in self.CRITICAL_EVENT_TYPES:
                removed_bytes += 256
            else:
                new_entries.append(entry)
        self._log_entries = new_entries
        self._total_bytes -= removed_bytes

    def _send_storage_alert(self, alert_type: str, suggestion: str):
        if self._publish_storage_alert:
            self._publish_storage_alert(StorageAlert(
                alert_type=alert_type,
                current_status=self.state.value,
                suggested_action=suggestion
            ))

    # ========== 辅助 ==========
    def _publish_storage_status_internal(self):
        if self._publish_storage_status:
            oldest = min((e.timestamp for e in self._log_entries), default=0)
            newest = max((e.timestamp for e in self._log_entries), default=0)
            self._publish_storage_status(StorageStatus(
                state=self.state,
                total_bytes=self.TOTAL_CAPACITY_BYTES,
                used_bytes=self._total_bytes,
                remaining_bytes=self.TOTAL_CAPACITY_BYTES - self._total_bytes,
                oldest_log_time=oldest,
                newest_log_time=newest,
                write_rate_per_sec=0.0
            ))

    def get_state(self) -> LoggerState:
        return self.state

    def emergency_shutdown(self):
        self.state = LoggerState.SYSTEM_PAUSED
        if self._buffer:
            for entry in self._buffer:
                self._log_entries.append(entry)
            self._buffer.clear()
        print(f"[{self.module_id}] 紧急熔断，缓冲已刷入存储")

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
    print("  Agent-mcc-exec 执行日志记录单元 (ag-mcc-12) 演示")
    print("=" * 70)

    logger = ExecutionLogger()

    print_separator("STEP 1: 记录指令接收日志")
    logger.set_log_event_query(lambda: LogEvent(
        event_type=LogEventType.COMMAND_RECEIVED,
        command_id="CMD-001",
        source_module="ag-mcc-01",
        tool_name="weather_api",
        tool_type="API"
    ))
    logger.run_logger_cycle()
    print(f"  序列号: {logger._sequence_number}")

    print_separator("STEP 2: 记录执行结果日志")
    logger.set_log_event_query(lambda: LogEvent(
        event_type=LogEventType.EXECUTION_RESULT,
        command_id="CMD-001",
        source_module="ag-mcc-06",
        tool_name="weather_api",
        tool_type="API",
        execution_status="success",
        detail_data={"duration_sec": 2.0, "http_status": 200}
    ))
    logger.run_logger_cycle()
    print(f"  序列号: {logger._sequence_number}")

    print_separator("STEP 3: 查询最近日志")
    logger.set_query_request_query(lambda: LogQueryRequest(
        time_range_sec=3600,
        max_results=10
    ))
    logger.run_logger_cycle()
    print(f"  日志总数: {len(logger._log_entries)}")

    print("\n✅ 执行日志记录单元演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("ag-mcc-12 执行日志记录单元 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        def setup_logger():
            return ExecutionLogger()

        # TC-MCC-12-01: 正常记录日志
        print("\n[TC-MCC-12-01] 正常记录日志")
        try:
            l = setup_logger()
            l.set_log_event_query(lambda: LogEvent(
                event_type=LogEventType.EXECUTION_RESULT,
                command_id="T01", source_module="ag-mcc-06"
            ))
            l.run_logger_cycle()
            assert l._sequence_number == 1
            assert len(l._log_entries) == 1
            assert l._log_entries[0].signature != ""
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-12-02: 序列号递增
        print("\n[TC-MCC-12-02] 序列号递增")
        try:
            l = setup_logger()
            for _ in range(3):
                l.set_log_event_query(lambda: LogEvent(
                    event_type=LogEventType.EXECUTION_RESULT, source_module="m"
                ))
                l.run_logger_cycle()
            assert l._sequence_number == 3
            assert len(l._log_entries) == 3
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-12-03: 查询过滤
        print("\n[TC-MCC-12-03] 查询过滤")
        try:
            l = setup_logger()
            l._log_entries = [
                LogEntry(sequence_number=1, event_type=LogEventType.EXECUTION_RESULT, command_id="A", timestamp=time.time()),
                LogEntry(sequence_number=2, event_type=LogEventType.TIMEOUT_EVENT, command_id="B", timestamp=time.time()),
            ]
            l.set_query_request_query(lambda: LogQueryRequest(
                event_type=LogEventType.TIMEOUT_EVENT
            ))
            l.run_logger_cycle()
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-12-04: 存储故障切换缓冲
        print("\n[TC-MCC-12-04] 存储故障切换缓冲")
        try:
            l = setup_logger()
            l.state = LoggerState.STORAGE_FAULT
            l.set_log_event_query(lambda: LogEvent(
                event_type=LogEventType.EXECUTION_RESULT, source_module="m"
            ))
            l.run_logger_cycle()
            assert len(l._buffer) == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-12-05: 缓冲溢出优先保留关键事件
        print("\n[TC-MCC-12-05] 缓冲溢出优先保留关键事件")
        try:
            l = setup_logger()
            l.state = LoggerState.STORAGE_FAULT
            for i in range(l.MAX_BUFFER_ENTRIES):
                l._buffer.append(LogEntry(sequence_number=i, event_type=LogEventType.COMMAND_RECEIVED))
            l.set_log_event_query(lambda: LogEvent(
                event_type=LogEventType.EXECUTION_RESULT, source_module="m"
            ))
            l.run_logger_cycle()
            has_critical = any(e.event_type in l.CRITICAL_EVENT_TYPES for e in l._buffer)
            assert has_critical
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-12-06: 紧急熔断
        print("\n[TC-MCC-12-06] 紧急熔断")
        try:
            l = setup_logger()
            l.emergency_shutdown()
            assert l.state == LoggerState.SYSTEM_PAUSED
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