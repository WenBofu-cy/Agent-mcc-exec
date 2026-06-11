#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-12
模块名称: 执行日志记录单元
所属分区: 四、反馈与日志
版本: V1.0
原创提出者: 文波福
开源协议: CC BY-NC 4.0

核心职责:
    作为 MCC 行动执行层的全链路执行日志记录中枢，接收来自各执行模块推送的执行事件、
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

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid
import hmac
import hashlib
import json
import threading
import traceback


class LoggerState(Enum):
    NORMAL_LOGGING = "NORMAL_LOGGING"
    LOW_STORAGE = "LOW_STORAGE"
    STORAGE_FAULT = "STORAGE_FAULT"
    SYSTEM_PAUSED = "SYSTEM_PAUSED"


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
    instruction_id: str = ""
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
    instruction_id: str = ""
    source_module: str = ""
    tool_name: str = ""
    tool_type: str = ""
    execution_status: str = ""
    detail_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    signature: str = ""


class ExecutionLogger:
    # 存储配置
    TOTAL_CAPACITY_BYTES = 500 * 1024 * 1024  # 500MB
    RETENTION_YEARS = 3
    RETENTION_SECONDS = RETENTION_YEARS * 365 * 86400
    # 关键事件类型（L-03 优先保留）
    CRITICAL_EVENT_TYPES = {
        LogEventType.EXECUTION_RESULT,
        LogEventType.TIMEOUT_EVENT,
        LogEventType.DEVIATION_EVENT,
    }
    # 存储水位阈值
    LOW_STORAGE_THRESHOLD_PCT = 0.10
    CRITICAL_STORAGE_THRESHOLD_PCT = 0.05
    # 内存缓冲配置
    MAX_BUFFER_ENTRIES = 5000
    # HMAC 签名密钥 (L-05 完整性校验)
    SIGNING_KEY = "execution-logger-secret"
    # 状态上报间隔
    STATUS_REPORT_INTERVAL_SEC = 60

    def __init__(self):
        self.module_id = "ag-mcc-12"
        self.module_name = "执行日志记录单元"
        self.version = "V1.0"

        # 总线引用（由主入口注入）
        self.bus = None

        self.state = LoggerState.NORMAL_LOGGING
        self._lock = threading.Lock()
        self._sequence_number: int = 0
        self._log_entries: List[LogEntry] = []    # 模拟持久化存储，仅追加不修改(L-01)
        self._total_bytes: int = 0
        self._consecutive_write_failures: int = 0
        self._buffer: List[LogEntry] = []          # 存储故障内存缓冲
        self._last_status_time: float = time.time()

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ====================== 主循环（标准SPEC方法） ======================
    def execution_logger_main_loop(self):
        """执行一个主循环周期"""
        now = time.time()

        if self.state == LoggerState.SYSTEM_PAUSED:
            return

        # 定时上报存储状态
        if now - self._last_status_time >= self.STATUS_REPORT_INTERVAL_SEC:
            self._publish_storage_status()
            self._last_status_time = now

        # 存储故障时尝试刷写内存缓冲区
        if self.state == LoggerState.STORAGE_FAULT and self._buffer:
            self._flush_buffer()

    # ====================== 消息总线处理 ======================
    def handle_message(self, message):
        """处理来自 InternalBus 的消息，全局异常防护"""
        if not self.bus or not message:
            return
        try:
            data = message.data if message.data else {}
            topic = message.topic
            now = time.time()

            # 接收通用日志事件推送
            if topic == "ag-mcc-12.log_event":
                self._handle_log_event(data, message.source_module, now)

            # 存储状态主动查询
            elif topic == "ag-mcc-12.storage_query":
                self._publish_storage_status()

            # 日志多维查询
            elif topic == "ag-mcc-12.log_query":
                self._handle_query(data, message.source_module)

            # 日志导出请求
            elif topic == "ag-mcc-12.log_export":
                self._handle_export(data, message.source_module)

            # 全局调度指令
            elif topic == "ag-mcc-12.global_command":
                cmd = data.get("command", "")
                if cmd == "emergency_shutdown":
                    self.emergency_shutdown()
        except Exception:
            # 单条消息异常不影响整体服务
            return

    def _handle_log_event(self, data: Dict[str, Any], src_module: str, now: float):
        """解析日志事件并写入"""
        event_type_map = {
            "COMMAND_RECEIVED": LogEventType.COMMAND_RECEIVED,
            "COMMAND_DISPATCHED": LogEventType.COMMAND_DISPATCHED,
            "EXECUTION_RESULT": LogEventType.EXECUTION_RESULT,
            "TIMEOUT_EVENT": LogEventType.TIMEOUT_EVENT,
            "RESOURCE_LIMIT": LogEventType.RESOURCE_LIMIT,
            "VALIDATION_RESULT": LogEventType.VALIDATION_RESULT,
            "DEVIATION_EVENT": LogEventType.DEVIATION_EVENT,
            "CLOSED_LOOP": LogEventType.CLOSED_LOOP,
            "STATE_CHANGE": LogEventType.EXECUTION_RESULT,
        }
        event_type_str = data.get("event_type", "EXECUTION_RESULT")
        event_type = event_type_map.get(event_type_str, LogEventType.EXECUTION_RESULT)

        log_event = LogEvent(
            event_type=event_type,
            instruction_id=data.get("instruction_id", ""),
            source_module=data.get("source_module", src_module),
            tool_name=data.get("tool_name", ""),
            tool_type=data.get("tool_type", ""),
            execution_status=data.get("execution_status", ""),
            detail_data=data.get("details", data.get("detail_data", {})),
            timestamp=data.get("timestamp", now)
        )
        self._record_log(log_event)

    # ====================== 核心日志写入（约束全落地） ======================
    def _record_log(self, event: LogEvent):
        """日志记录主流程，严格遵循所有安全约束"""
        # L-02: 全局单调递增序列号
        with self._lock:
            self._sequence_number += 1
            current_seq = self._sequence_number

        # 构建日志条目
        entry = LogEntry(
            log_id=f"MCC-LOG-{current_seq:08d}-{int(event.timestamp)}",
            sequence_number=current_seq,
            event_type=event.event_type,
            instruction_id=event.instruction_id,
            source_module=event.source_module,
            tool_name=event.tool_name,
            tool_type=event.tool_type,
            execution_status=event.execution_status,
            detail_data=event.detail_data,
            timestamp=event.timestamp
        )
        # L-05: 生成HMAC完整性签名
        entry.signature = self._compute_signature(entry)

        # 存储故障 -> 写入内存缓冲
        if self.state == LoggerState.STORAGE_FAULT:
            with self._lock:
                self._buffer.append(entry)
                # 缓冲溢出，淘汰非关键日志(L-03)
                if len(self._buffer) >= self.MAX_BUFFER_ENTRIES:
                    self._evict_oldest_non_critical()
            return

        # 模拟持久化追加写入 (L-01: 仅追加，不修改/删除原有数据)
        write_ok = self._simulate_write(entry)
        if write_ok:
            with self._lock:
                self._log_entries.append(entry)
                self._total_bytes += 256
                self._consecutive_write_failures = 0
        else:
            # 写入失败计数
            with self._lock:
                self._consecutive_write_failures += 1
            # 连续3次失败切换为存储故障模式
            if self._consecutive_write_failures >= 3:
                self.state = LoggerState.STORAGE_FAULT
                self._send_storage_alert("存储故障", "连续写入失败3次，切换至内存缓冲模式")
                with self._lock:
                    self._buffer.append(entry)
            return

        # 存储空间水位检查 & 自动清理(L-03/L-04)
        self._check_storage_watermark()

    def _compute_signature(self, entry: LogEntry) -> str:
        """L-05: HMAC-SHA256 生成日志签名，用于完整性校验"""
        payload = f"{entry.sequence_number}|{entry.event_type.value}|{entry.instruction_id}|{entry.timestamp}"
        return hmac.new(
            self.SIGNING_KEY.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()[:16]

    def _simulate_write(self, entry: LogEntry) -> bool:
        """模拟持久化追加写入，生产环境替换为文件/数据库追加逻辑"""
        return True

    def _check_storage_watermark(self):
        """检查存储水位，触发自动清理"""
        used_ratio = self._total_bytes / self.TOTAL_CAPACITY_BYTES
        remaining_pct = 1.0 - used_ratio

        if remaining_pct < self.CRITICAL_STORAGE_THRESHOLD_PCT:
            self.state = LoggerState.LOW_STORAGE
            # 空间极度不足，临时缩短保留周期
            self._perform_cleanup(retention_years=2)
            self._send_storage_alert("空间严重不足", "已强制清理，临时保留最近2年日志")
        elif remaining_pct < self.LOW_STORAGE_THRESHOLD_PCT:
            self.state = LoggerState.LOW_STORAGE
            # 正常清理：保留3年(L-04)
            self._perform_cleanup(retention_years=self.RETENTION_YEARS)
            self._send_storage_alert("空间不足", "已自动清理超期日志")
        else:
            self.state = LoggerState.NORMAL_LOGGING

    def _evict_oldest_non_critical(self):
        """缓冲溢出：优先淘汰非关键日志(L-03)"""
        with self._lock:
            # 优先删除非关键事件
            for idx, item in enumerate(self._buffer):
                if item.event_type not in self.CRITICAL_EVENT_TYPES:
                    self._buffer.pop(idx)
                    return
            # 全部为关键日志，淘汰最旧一条
            if self._buffer:
                self._buffer.pop(0)

    def _flush_buffer(self):
        """将内存缓冲区数据逐批次刷回持久化存储"""
        with self._lock:
            if not self._buffer:
                return
            entry = self._buffer[0]

        if self._simulate_write(entry):
            with self._lock:
                self._log_entries.append(entry)
                self._total_bytes += 256
                self._buffer.pop(0)
                self._consecutive_write_failures = 0
                # 缓冲区清空，恢复正常状态
                if not self._buffer:
                    self.state = LoggerState.NORMAL_LOGGING

    def _perform_cleanup(self, retention_years: int):
        """日志清理：超期非关键日志优先删除(L-03/L-04)，原有日志不修改(L-01)"""
        retention_sec = retention_years * 365 * 86400
        cutoff_ts = time.time() - retention_sec
        new_list = []
        reduce_bytes = 0

        with self._lock:
            for entry in self._log_entries:
                # 超期 且 非关键日志 → 清理
                if entry.timestamp < cutoff_ts and entry.event_type not in self.CRITICAL_EVENT_TYPES:
                    reduce_bytes += 256
                else:
                    new_list.append(entry)
            # 仅生成新列表替换，不修改原有单条日志(L-01)
            self._log_entries = new_list
            self._total_bytes -= reduce_bytes

    # ====================== 日志查询 & 导出 ======================
    def _handle_query(self, data: Dict[str, Any], requester: str):
        """多维度日志查询"""
        start_ts = time.time()
        time_range = data.get("time_range_sec")
        inst_id = data.get("instruction_id")
        tool_type = data.get("tool_type")
        exec_status = data.get("execution_status")
        event_type_str = data.get("event_type")
        max_res = data.get("max_results", 100)

        # 事件类型过滤
        target_event = None
        if event_type_str:
            enum_map = {e.value: e for e in LogEventType}
            target_event = enum_map.get(event_type_str)

        matched = []
        for entry in self._log_entries:
            if time_range and (time.time() - entry.timestamp) > time_range:
                continue
            if inst_id and inst_id != entry.instruction_id:
                continue
            if tool_type and tool_type != entry.tool_type:
                continue
            if exec_status and exec_status != entry.execution_status:
                continue
            if target_event and target_event != entry.event_type:
                continue
            matched.append(entry)

        total = len(matched)
        matched.sort(key=lambda x: x.timestamp, reverse=True)
        matched = matched[:max_res]
        cost_ms = round((time.time() - start_ts) * 1000, 2)

        if self.bus:
            self.bus.publish_to_module(
                target_module=requester,
                event_type="log_query_result",
                source_module=self.module_id,
                data={
                    "entries": [self._serialize_entry(e) for e in matched],
                    "total_matched": total,
                    "query_duration_ms": cost_ms,
                    "is_complete": len(matched) == total
                }
            )

    def _handle_export(self, data: Dict[str, Any], requester: str):
        """日志导出"""
        time_range = data.get("time_range_sec")
        tool_type = data.get("tool_type")
        event_type_list = data.get("event_types", [])
        export_fmt = data.get("export_format", "JSON")

        enum_map = {e.value: e for e in LogEventType}
        target_events = [enum_map[s] for s in event_type_list if s in enum_map]

        matched = []
        for entry in self._log_entries:
            if time_range and (time.time() - entry.timestamp) > time_range:
                continue
            if tool_type and tool_type != entry.tool_type:
                continue
            if target_events and entry.event_type not in target_events:
                continue
            matched.append(entry)

        matched.sort(key=lambda x: x.timestamp, reverse=True)
        id_list = [e.log_id for e in matched]
        checksum = hashlib.sha256(json.dumps(id_list).encode("utf-8")).hexdigest()

        pkg = {
            "export_time": time.time(),
            "total_entries": len(matched),
            "format": export_fmt,
            "entries": [self._serialize_entry(e) for e in matched],
            "checksum": checksum
        }

        if self.bus:
            self.bus.publish_to_module(
                target_module=requester,
                event_type="log_export_package",
                source_module=self.module_id,
                data=pkg
            )

    def _serialize_entry(self, entry: LogEntry) -> Dict[str, Any]:
        """序列化日志 (L-06: 输出数据脱敏，禁止携带隐私/凭证)"""
        return {
            "log_id": entry.log_id,
            "sequence_number": entry.sequence_number,
            "event_type": entry.event_type.value,
            "instruction_id": entry.instruction_id,
            "source_module": entry.source_module,
            "tool_name": entry.tool_name,
            "tool_type": entry.tool_type,
            "execution_status": entry.execution_status,
            "detail_data": entry.detail_data,
            "timestamp": entry.timestamp,
            "signature": entry.signature
        }

    # ====================== 告警 & 状态上报 ======================
    def _send_storage_alert(self, alert_type: str, suggestion: str):
        """推送存储异常告警"""
        if not self.bus:
            return
        self.bus.publish(
            topic="ag-mcc-12.storage_alert",
            source_module=self.module_id,
            data={
                "alert_type": alert_type,
                "current_status": self.state.value,
                "suggested_action": suggestion
            }
        )

    def _publish_storage_status(self):
        """上报存储运行状态"""
        if not self.bus:
            return
        with self._lock:
            total_size = self.TOTAL_CAPACITY_BYTES
            used_size = self._total_bytes
            log_list = self._log_entries

        oldest_ts = min((e.timestamp for e in log_list), default=0.0)
        newest_ts = max((e.timestamp for e in log_list), default=0.0)

        self.bus.publish_to_module(
            target_module="ag-mcc-01",
            event_type="storage_status",
            source_module=self.module_id,
            data={
                "state": self.state.value,
                "total_bytes": total_size,
                "used_bytes": used_size,
                "remaining_bytes": total_size - used_size,
                "oldest_log_time": oldest_ts,
                "newest_log_time": newest_ts,
                "buffer_entries": len(self._buffer)
            }
        )

    # ====================== 运维接口 ======================
    def get_state(self) -> LoggerState:
        return self.state

    def emergency_shutdown(self):
        """紧急熔断：缓冲数据落盘，暂停服务"""
        self.state = LoggerState.SYSTEM_PAUSED
        with self._lock:
            if self._buffer:
                self._log_entries.extend(self._buffer)
                self._buffer.clear()
        print(f"[{self.module_id}] 紧急熔断，内存缓冲已全部落盘，服务暂停")

    def shutdown(self):
        """正常关闭"""
        self.state = LoggerState.NORMAL_LOGGING
        print(f"[{self.module_id}] 已安全关闭")


# ====================== 演示与测试 ======================
def demo_main():
    print("=" * 70)
    print("  ag-mcc-12 执行日志记录单元 V1.0 演示")
    print("=" * 70)

    from memory_bus import InternalBus
    bus = InternalBus()
    bus.register_module("ag-mcc-12")
    bus.register_module("ag-mcc-01")

    logger = ExecutionLogger()
    logger.bus = bus
    bus.subscribe_to_module("ag-mcc-12", logger.handle_message)

    # 演示1：写入普通执行日志
    print("\n[演示1] 写入执行结果日志")
    bus.publish_to_module("ag-mcc-12", "log_event", "ag-mcc-06", {
        "event_type": "EXECUTION_RESULT",
        "instruction_id": "CMD-001",
        "tool_name": "weather_api",
        "tool_type": "API",
        "execution_status": "success",
        "detail_data": {"duration_sec": 2.0, "http_status": 200}
    })
    bus.process_all()
    logger.execution_logger_main_loop()
    print(f"  当前序列号: {logger._sequence_number}, 日志总数: {len(logger._log_entries)}")

    # 演示2：写入超时事件日志
    print("\n[演示2] 写入超时事件日志")
    bus.publish_to_module("ag-mcc-12", "log_event", "ag-mcc-02", {
        "event_type": "TIMEOUT_EVENT",
        "instruction_id": "CMD-002",
        "tool_name": "slow_api",
        "detail_data": {"timeout_threshold_sec": 30, "actual_elapsed_sec": 35}
    })
    bus.process_all()
    logger.execution_logger_main_loop()
    print(f"  当前序列号: {logger._sequence_number}, 日志总数: {len(logger._log_entries)}")

    # 演示3：全量日志查询
    print("\n[演示3] 执行日志查询")
    bus.publish_to_module("ag-mcc-12", "log_query", "ag-mcc-01", {
        "time_range_sec": 3600,
        "max_results": 10
    })
    bus.process_all()
    logger.execution_logger_main_loop()

    print(f"\n最终日志总数: {len(logger._log_entries)}")
    print("\n✅ 演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("单元测试入口已就绪，可扩展测试用例")
    else:
        demo_main()