#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-11
模块名称: 闭环反馈单元
所属分区: 四、反馈与日志
版本: V1.0
原创提出者: 文波福
开源协议: CC BY-NC 4.0

核心职责:
    作为 MCC 行动执行层的结果汇总与反馈中枢，接收各执行模块返回并经 ag-mcc-09
    （结果校验器）校验、ag-mcc-10（执行偏差监控）偏差分析后的执行结果。将所有结果
    统一封装为标准化闭环回执，通过 CerebellumBus 上报至 ag-ecc-12（资源调度模块），
    完成从指令下发到结果回传的完整执行闭环。同时汇总执行过程中的异常事件、超时通知
    与偏差告警，一并上报供 ECC 认知大脑进行任务恢复与决策优化。不参与结果校验或偏差
    分析，仅负责结果的最终汇总、封装与回传。

依赖模块:
    ag-mcc-09(结果校验器), ag-mcc-10(执行偏差监控), ag-mcc-02(工具超时管理器)
被依赖模块:
    ag-ecc-12(资源调度模块), ag-mcc-12(执行日志记录单元)

安全约束:
  F-01: 闭环回执中不得包含任何认证凭证、密钥或敏感用户数据
  F-02: 闭环回执发送必须通过 CerebellumBus 传输（CerebellumBus 默认加密）
  F-03: 未能在规定时间内完成闭环的指令，不得无限期等待，超时后必须强制构建回执上报
  F-04: 闭环回执中的偏差分析摘要不得包含原始输出数据，仅保留统计级别的偏差指标
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid
import threading


class FeedbackState(Enum):
    WAITING_RESULT = "WAITING_RESULT"
    AGGREGATING = "AGGREGATING"
    REPORTING = "REPORTING"
    SYSTEM_PAUSED = "SYSTEM_PAUSED"


@dataclass
class ValidatedResult:
    instruction_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    tool_name: str = ""
    execution_status: str = "success"
    validation_flag: str = "通过"
    cleaned_output_data: Any = None
    duration_sec: float = 0.0
    resource_consumption: Dict[str, float] = field(default_factory=dict)
    validation_duration_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class DeviationReport:
    instruction_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    composite_deviation: float = 0.0
    dimension_details: Dict[str, float] = field(default_factory=dict)
    alert_level: str = "正常"
    alert_dimensions: List[str] = field(default_factory=list)
    suggestion: str = ""


@dataclass
class TimeoutEventLog:
    instruction_id: str = ""
    tool_name: str = ""
    timeout_threshold_sec: float = 0.0
    actual_elapsed_sec: float = 0.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class ClosedLoopReceipt:
    instruction_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    tool_name: str = ""
    execution_status: str = "success"
    output_data: Any = None
    validation_flag: str = "通过"
    deviation_summary: Dict[str, Any] = field(default_factory=dict)
    timeout_mark: bool = False
    actual_duration_sec: float = 0.0
    resource_consumption_summary: Dict[str, float] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class ClosedLoopFeedback:
    # 各环节超时等待（秒）
    COLLECTION_TIMEOUT_SEC = 10.0
    # 发送重试次数
    MAX_SEND_RETRIES = 3
    # 统计上报间隔
    STATS_REPORT_INTERVAL_SEC = 60

    def __init__(self):
        self.module_id = "ag-mcc-11"
        self.module_name = "闭环反馈单元"
        self.version = "V1.0"

        # 总线引用（由主入口注入）
        self.bus = None                 # InternalBus（MCC内部通信）
        self.external_bus = None        # CerebellumBus（与ECC通信，上报闭环回执）

        self.state = FeedbackState.WAITING_RESULT
        self._lock = threading.Lock()
        self._pending_aggregations: Dict[str, Dict[str, Any]] = {}
        self._total_closed_loops: int = 0
        self._anomaly_loops: int = 0
        self._total_loop_duration: float = 0.0
        self._last_stats_time: float = time.time()

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ====================== 主循环（SPEC 定义的标准方法名） ======================
    def feedback_loop_main_loop(self):
        """执行一个主循环周期"""
        now = time.time()

        if self.state == FeedbackState.SYSTEM_PAUSED:
            return

        # 定期统计上报
        if now - self._last_stats_time >= self.STATS_REPORT_INTERVAL_SEC:
            self._publish_stats()
            self._last_stats_time = now

        # 超时未完成闭环的强制上报
        self._force_timeout_assemblies(now)

    # ====================== 消息处理（InternalBus） ======================
    def handle_message(self, message):
        """处理来自 InternalBus 的消息"""
        if not self.bus:
            return

        data = message.data if message.data else {}
        topic = message.topic
        now = time.time()

        # 接收校验后结果（来自 ag-mcc-09）
        if topic == "ag-mcc-11.validated_result":
            validated = ValidatedResult(
                instruction_id=data.get("instruction_id", ""),
                step_id=data.get("step_id", ""),
                plan_id=data.get("plan_id", ""),
                tool_name=data.get("tool_name", ""),
                execution_status=data.get("original_status", "success"),
                validation_flag=data.get("validation_flag", "通过"),
                cleaned_output_data=data.get("cleaned_output_data"),
                duration_sec=data.get("duration_sec", 0.0),
                resource_consumption=data.get("resource_consumption", {}),
                timestamp=now
            )
            self._ingest_validated(validated)
            self._try_assemble(validated.instruction_id, now)

        # 接收偏差分析报告（来自 ag-mcc-10）
        elif topic == "ag-mcc-11.deviation_report":
            deviation = DeviationReport(
                instruction_id=data.get("instruction_id", ""),
                step_id=data.get("step_id", ""),
                plan_id=data.get("plan_id", ""),
                composite_deviation=data.get("composite_deviation", 0.0),
                dimension_details=data.get("dimension_details", {}),
                alert_level=data.get("alert_level", "正常"),
                alert_dimensions=data.get("alert_dimensions", []),
                suggestion=data.get("suggestion", "")
            )
            self._ingest_deviation(deviation)
            self._try_assemble(deviation.instruction_id, now)

        # 接收超时事件日志（来自 ag-mcc-02）
        elif topic == "ag-mcc-11.timeout_event":
            timeout_event = TimeoutEventLog(
                instruction_id=data.get("instruction_id", ""),
                tool_name=data.get("tool_name", ""),
                timeout_threshold_sec=data.get("timeout_threshold_sec", 0.0),
                actual_elapsed_sec=data.get("actual_elapsed_sec", 0.0),
                timestamp=data.get("timestamp", now)
            )
            self._ingest_timeout(timeout_event)
            self._try_assemble(timeout_event.instruction_id, now)

        # 接收全局调度指令
        elif topic == "ag-mcc-11.global_command":
            command = data.get("command", "")
            if command == "emergency_shutdown":
                self.emergency_shutdown()

    # ====================== 数据摄入 ======================
    def _ingest_validated(self, result: ValidatedResult):
        with self._lock:
            if result.instruction_id not in self._pending_aggregations:
                self._pending_aggregations[result.instruction_id] = {}
            self._pending_aggregations[result.instruction_id]["validated"] = result

    def _ingest_deviation(self, report: DeviationReport):
        with self._lock:
            if report.instruction_id not in self._pending_aggregations:
                self._pending_aggregations[report.instruction_id] = {}
            self._pending_aggregations[report.instruction_id]["deviation"] = report

    def _ingest_timeout(self, event: TimeoutEventLog):
        with self._lock:
            if event.instruction_id not in self._pending_aggregations:
                self._pending_aggregations[event.instruction_id] = {}
            self._pending_aggregations[event.instruction_id]["timeout"] = event

    # ====================== 闭环组装判定 ======================
    def _try_assemble(self, instruction_id: str, now: float):
        with self._lock:
            data = self._pending_aggregations.get(instruction_id)

        if not data:
            return

        validated = data.get("validated")
        if not validated:
            return

        # 成功且校验通过，可以直接闭环（不需要偏差报告）
        if validated.execution_status == "success" and validated.validation_flag == "通过":
            self._assemble_and_report(instruction_id, now)
            return

        # 否则需要偏差报告
        if "deviation" in data:
            self._assemble_and_report(instruction_id, now)

    # ====================== 闭环回执组装与上报 ======================
    def _assemble_and_report(self, instruction_id: str, now: float):
        self.state = FeedbackState.AGGREGATING

        with self._lock:
            data = self._pending_aggregations.get(instruction_id)

        validated: Optional[ValidatedResult] = data.get("validated") if data else None
        deviation: Optional[DeviationReport] = data.get("deviation") if data else None
        timeout_event: Optional[TimeoutEventLog] = data.get("timeout") if data else None

        if not validated:
            return

        # 构建闭环回执（F-04: 偏差摘要仅保留统计级指标，不包含原始输出数据）
        receipt = ClosedLoopReceipt(
            instruction_id=instruction_id,
            step_id=validated.step_id,
            plan_id=validated.plan_id,
            tool_name=validated.tool_name,
            execution_status=validated.execution_status,
            output_data=validated.cleaned_output_data,
            validation_flag=validated.validation_flag,
            deviation_summary={
                "composite_deviation": deviation.composite_deviation if deviation else 0.0,
                "alert_level": deviation.alert_level if deviation else "正常",
                "key_dimensions": deviation.alert_dimensions if deviation else []
            },
            timeout_mark=timeout_event is not None,
            actual_duration_sec=validated.duration_sec,
            resource_consumption_summary=validated.resource_consumption,
            timestamp=now
        )

        self.state = FeedbackState.REPORTING

        # 通过 CerebellumBus 上报闭环回执至 ECC（F-02: CerebellumBus 默认加密传输）
        sent = False
        if self.external_bus:
            for attempt in range(self.MAX_SEND_RETRIES):
                try:
                    self.external_bus.publish_to_module(
                        target_module="ag-ecc-12",
                        event_type="closed_loop_receipt",
                        source_module=self.module_id,
                        data={
                            "instruction_id": receipt.instruction_id,
                            "step_id": receipt.step_id,
                            "plan_id": receipt.plan_id,
                            "tool_name": receipt.tool_name,
                            "execution_status": receipt.execution_status,
                            "output_data": receipt.output_data,
                            "validation_flag": receipt.validation_flag,
                            "deviation_summary": receipt.deviation_summary,
                            "timeout_mark": receipt.timeout_mark,
                            "actual_duration_sec": receipt.actual_duration_sec,
                            "resource_consumption_summary": receipt.resource_consumption_summary,
                            "timestamp": receipt.timestamp
                        }
                    )
                    sent = True
                    break
                except Exception:
                    time.sleep(0.1 * (attempt + 1))

        if sent:
            # 更新统计
            anomaly = (deviation and deviation.alert_level != "正常") or (timeout_event is not None)
            with self._lock:
                self._total_closed_loops += 1
                if anomaly:
                    self._anomaly_loops += 1
                # 清理已完成的聚合数据
                self._pending_aggregations.pop(instruction_id, None)

            # 通过 InternalBus 记录闭环事件日志至 ag-mcc-12
            if self.bus:
                self.bus.publish_to_module(
                    target_module="ag-mcc-12",
                    event_type="closed_loop_event",
                    source_module=self.module_id,
                    data={
                        "log_id": f"log-{uuid.uuid4().hex[:8]}",
                        "instruction_id": instruction_id,
                        "loop_status": "完成",
                        "anomaly_mark": anomaly,
                        "timestamp": now
                    }
                )

        self.state = FeedbackState.WAITING_RESULT

    # ====================== 超时强制闭环 ======================
    def _force_timeout_assemblies(self, now: float):
        """超时未完成闭环的指令，强制构建回执上报（F-03）"""
        to_force = []
        with self._lock:
            for cid, data in self._pending_aggregations.items():
                validated = data.get("validated")
                if validated:
                    elapsed = now - validated.timestamp
                    if elapsed > self.COLLECTION_TIMEOUT_SEC:
                        to_force.append(cid)

        for cid in to_force:
            with self._lock:
                data = self._pending_aggregations.get(cid)
                # 补全缺失的偏差报告
                if "deviation" not in data and "validated" in data:
                    v = data["validated"]
                    data["deviation"] = DeviationReport(
                        instruction_id=cid,
                        step_id=v.step_id,
                        plan_id=v.plan_id,
                        composite_deviation=0.0,
                        alert_level="正常"
                    )
            self._assemble_and_report(cid, now)

    # ====================== 状态上报 & 运维 ======================
    def _publish_stats(self):
        if not self.bus:
            return
        with self._lock:
            total = max(self._total_closed_loops, 1)
            rate = self._anomaly_loops / total
        self.bus.publish_to_module(
            target_module="ag-mcc-12",
            event_type="feedback_status",
            source_module=self.module_id,
            data={
                "state": self.state.value,
                "today_closed_loops": self._total_closed_loops,
                "anomaly_loop_rate": round(rate, 3)
            }
        )

    def get_state(self) -> FeedbackState:
        return self.state

    def emergency_shutdown(self):
        """紧急熔断：强制上报所有未完成的闭环，然后暂停服务"""
        self.state = FeedbackState.SYSTEM_PAUSED
        now = time.time()
        with self._lock:
            cids = list(self._pending_aggregations.keys())
        for cid in cids:
            with self._lock:
                data = self._pending_aggregations.get(cid)
                if "deviation" not in data and "validated" in data:
                    v = data["validated"]
                    data["deviation"] = DeviationReport(
                        instruction_id=cid, step_id=v.step_id, plan_id=v.plan_id,
                        composite_deviation=1.0, alert_level="严重"
                    )
            self._assemble_and_report(cid, now)
        with self._lock:
            self._pending_aggregations.clear()
        print(f"[{self.module_id}] 紧急熔断，未完成闭环已强制上报")

    def shutdown(self):
        self.state = FeedbackState.WAITING_RESULT
        print(f"[{self.module_id}] 已安全关闭")


# ====================== 演示与测试 ======================
def demo_main():
    print("=" * 70)
    print("  ag-mcc-11 闭环反馈单元 V1.0 演示")
    print("=" * 70)

    from memory_bus import InternalBus, CerebellumBus

    internal_bus = InternalBus()
    internal_bus.register_module("ag-mcc-11")
    internal_bus.register_module("ag-mcc-12")

    external_bus = CerebellumBus()
    external_bus.register_module("ag-mcc-11")
    external_bus.register_module("ag-ecc-12")

    feedback = ClosedLoopFeedback()
    feedback.bus = internal_bus
    feedback.external_bus = external_bus
    internal_bus.subscribe_to_module("ag-mcc-11", feedback.handle_message)

    now = time.time()

    # 演示1：成功结果直接闭环
    print("\n[演示1] 成功结果直接闭环")
    internal_bus.publish_to_module("ag-mcc-11", "validated_result", "ag-mcc-09", {
        "instruction_id": "CMD-001",
        "step_id": "S01",
        "plan_id": "P01",
        "tool_name": "weather_api",
        "original_status": "success",
        "validation_flag": "通过",
        "cleaned_output_data": {"result": "晴天", "status": "ok"},
        "duration_sec": 2.0,
        "resource_consumption": {"api_calls": 1}
    })
    internal_bus.process_all()
    external_bus.process_all()
    feedback.feedback_loop_main_loop()
    print(f"  已完成闭环数: {feedback._total_closed_loops}")

    # 演示2：偏差报告到达后闭环
    print("\n[演示2] 偏差报告到达后闭环")
    internal_bus.publish_to_module("ag-mcc-11", "validated_result", "ag-mcc-09", {
        "instruction_id": "CMD-002",
        "step_id": "S02",
        "plan_id": "P02",
        "tool_name": "search_engine",
        "original_status": "success",
        "validation_flag": "通过",
        "cleaned_output_data": {"results": []},
        "duration_sec": 15.0,
        "resource_consumption": {"api_calls": 2}
    })
    internal_bus.process_all()
    # 注入偏差报告
    internal_bus.publish_to_module("ag-mcc-11", "deviation_report", "ag-mcc-10", {
        "instruction_id": "CMD-002",
        "step_id": "S02",
        "plan_id": "P02",
        "composite_deviation": 0.35,
        "alert_level": "一般告警",
        "alert_dimensions": ["耗时偏差过大"],
        "suggestion": "建议关注耗时偏差"
    })
    internal_bus.process_all()
    external_bus.process_all()
    feedback.feedback_loop_main_loop()
    print(f"  已完成闭环数: {feedback._total_closed_loops}")

    # 演示3：超时强制闭环
    print("\n[演示3] 超时强制闭环")
    # 手动注入一个已过期的校验结果
    feedback._ingest_validated(ValidatedResult(
        instruction_id="CMD-003",
        step_id="S03",
        plan_id="P03",
        tool_name="slow_api",
        execution_status="success",
        validation_flag="通过",
        cleaned_output_data={"result": "ok"},
        duration_sec=5.0,
        timestamp=now - feedback.COLLECTION_TIMEOUT_SEC - 1
    ))
    feedback.feedback_loop_main_loop()
    external_bus.process_all()
    print(f"  已完成闭环数: {feedback._total_closed_loops}")

    print("\n✅ 演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("单元测试入口已就绪，可扩展测试用例")
    else:
        demo_main()