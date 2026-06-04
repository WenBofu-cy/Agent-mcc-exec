#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-11
模块名称: 闭环反馈单元
所属分区: 四、反馈与日志
核心职责: 作为 MCC 行动执行层的结果汇总与反馈中枢，接收各执行模块返回并经 ag-mcc-09
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
  F-02: 闭环回执发送必须加密传输
  F-03: 未能在规定时间内完成闭环的指令，不得无限期等待，超时后必须强制构建回执上报
  F-04: 闭环回执中的偏差分析摘要不得包含原始输出数据，仅保留统计级别的偏差指标
"""

from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid


class FeedbackState(Enum):
    WAITING_RESULT = "waiting_result"
    AGGREGATING = "aggregating"
    REPORTING = "reporting"
    SYSTEM_PAUSED = "system_paused"


@dataclass
class ValidatedResult:
    command_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    tool_name: str = ""
    execution_status: str = "success"
    validation_flag: str = "通过"
    cleaned_output_data: Any = None
    duration_sec: float = 0.0
    resource_consumption: Dict[str, float] = field(default_factory=dict)
    validation_duration_ms: float = 0.0


@dataclass
class DeviationReport:
    command_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    composite_deviation: float = 0.0
    dimension_details: Dict[str, float] = field(default_factory=dict)
    alert_level: str = "正常"
    alert_dimensions: List[str] = field(default_factory=list)
    suggestion: str = ""


@dataclass
class TimeoutEventLog:
    task_id: str = ""
    tool_name: str = ""
    timeout_threshold_sec: float = 0.0
    actual_elapsed_sec: float = 0.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class ClosedLoopReceipt:
    command_id: str = ""
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


@dataclass
class ClosedLoopEventLog:
    command_id: str = ""
    loop_status: str = "完成"
    duration_breakdown: Dict[str, float] = field(default_factory=dict)
    anomaly_mark: bool = False
    timestamp: float = field(default_factory=time.time)


@dataclass
class FeedbackStatus:
    state: FeedbackState = FeedbackState.WAITING_RESULT
    today_closed_loops: int = 0
    avg_loop_duration_ms: float = 0.0
    anomaly_loop_rate: float = 0.0


class ClosedLoopFeedback:
    # 各环节超时等待
    COLLECTION_TIMEOUT_SEC = 10.0
    # 发送重试
    MAX_SEND_RETRIES = 3
    # 统计上报间隔
    STATS_REPORT_INTERVAL_SEC = 60

    def __init__(self):
        self.module_id = "ag-mcc-11"
        self.module_name = "闭环反馈单元"
        self.version = "V1.0"

        self.state = FeedbackState.WAITING_RESULT
        self._pending_aggregations: Dict[str, Dict[str, Any]] = {}  # command_id -> {validated, deviation, timeout}
        self._total_closed_loops: int = 0
        self._anomaly_loops: int = 0
        self._total_loop_duration: float = 0.0
        self._last_stats_time: float = time.time()
        self._pending_logs: List[Dict[str, Any]] = []

        # 回调注入
        self._query_validated_result = None
        self._query_deviation_report = None
        self._query_timeout_event = None

        self._publish_closed_loop_receipt = None
        self._publish_closed_loop_event_log = None
        self._publish_status_report = None
        self._publish_event_log = None

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ========== 回调注入 ==========
    def set_validated_result_query(self, callback: Callable[[], Optional[ValidatedResult]]):
        self._query_validated_result = callback

    def set_deviation_report_query(self, callback: Callable[[], Optional[DeviationReport]]):
        self._query_deviation_report = callback

    def set_timeout_event_query(self, callback: Callable[[], Optional[TimeoutEventLog]]):
        self._query_timeout_event = callback

    def set_closed_loop_receipt_publisher(self, callback: Callable[[ClosedLoopReceipt], None]):
        self._publish_closed_loop_receipt = callback

    def set_closed_loop_event_log_publisher(self, callback: Callable[[ClosedLoopEventLog], None]):
        self._publish_closed_loop_event_log = callback

    def set_status_report_publisher(self, callback: Callable[[FeedbackStatus], None]):
        self._publish_status_report = callback

    def set_event_log_publisher(self, callback: Callable[[Dict[str, Any]], None]):
        self._publish_event_log = callback

    # ========== 主循环 ==========
    def run_feedback_cycle(self):
        now = time.time()

        if self.state == FeedbackState.SYSTEM_PAUSED:
            return

        # 定期统计上报
        if now - self._last_stats_time >= self.STATS_REPORT_INTERVAL_SEC:
            self._publish_stats()
            self._last_stats_time = now

        # 收集校验后结果
        validated = self._query_validated_result() if self._query_validated_result else None
        if validated:
            self._ingest_validated(validated)
            self._try_assemble(validated.command_id, now)

        # 收集偏差分析报告
        deviation = self._query_deviation_report() if self._query_deviation_report else None
        if deviation:
            self._ingest_deviation(deviation)
            self._try_assemble(deviation.command_id, now)

        # 收集超时事件日志
        timeout_event = self._query_timeout_event() if self._query_timeout_event else None
        if timeout_event:
            self._ingest_timeout(timeout_event)
            self._try_assemble(timeout_event.task_id, now)

        # 超时未完成闭环的强制上报
        self._force_timeout_assemblies(now)

    def _ingest_validated(self, result: ValidatedResult):
        cid = result.command_id
        if cid not in self._pending_aggregations:
            self._pending_aggregations[cid] = {}
        self._pending_aggregations[cid]["validated"] = result

    def _ingest_deviation(self, report: DeviationReport):
        cid = report.command_id
        if cid not in self._pending_aggregations:
            self._pending_aggregations[cid] = {}
        self._pending_aggregations[cid]["deviation"] = report

    def _ingest_timeout(self, event: TimeoutEventLog):
        cid = event.task_id
        if cid not in self._pending_aggregations:
            self._pending_aggregations[cid] = {}
        self._pending_aggregations[cid]["timeout"] = event

    def _try_assemble(self, command_id: str, now: float):
        data = self._pending_aggregations.get(command_id)
        if not data:
            return

        validated = data.get("validated")
        if not validated:
            return

        # 成功且校验通过，可以直接闭环
        if validated.execution_status == "success" and validated.validation_flag == "通过":
            self._assemble_and_report(command_id, data, now)
            return

        # 否则需要偏差报告
        if "deviation" in data:
            self._assemble_and_report(command_id, data, now)

    def _assemble_and_report(self, command_id: str, data: Dict[str, Any], now: float):
        self.state = FeedbackState.AGGREGATING
        validated: ValidatedResult = data["validated"]
        deviation: Optional[DeviationReport] = data.get("deviation")
        timeout_event: Optional[TimeoutEventLog] = data.get("timeout")

        # 构建闭环回执
        receipt = ClosedLoopReceipt(
            command_id=command_id,
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

        # 发送闭环回执（带重试）
        sent = False
        for attempt in range(self.MAX_SEND_RETRIES):
            if self._publish_closed_loop_receipt:
                self._publish_closed_loop_receipt(receipt)
                sent = True
                break
            time.sleep(0.1 * (attempt + 1))

        if sent:
            self._total_closed_loops += 1
            anomaly = (deviation and deviation.alert_level != "正常") or (timeout_event is not None)
            if anomaly:
                self._anomaly_loops += 1

            # 记录闭环事件日志
            if self._publish_closed_loop_event_log:
                self._publish_closed_loop_event_log(ClosedLoopEventLog(
                    command_id=command_id,
                    loop_status="完成",
                    duration_breakdown={
                        "validation_ms": validated.validation_duration_ms,
                        "total_ms": (now - validated.timestamp) * 1000 if hasattr(validated, 'timestamp') else 0
                    },
                    anomaly_mark=anomaly
                ))

        # 清理
        self._pending_aggregations.pop(command_id, None)
        self.state = FeedbackState.WAITING_RESULT

    def _force_timeout_assemblies(self, now: float):
        to_remove = []
        for cid, data in self._pending_aggregations.items():
            validated = data.get("validated")
            if validated and hasattr(validated, 'timestamp'):
                elapsed = now - validated.timestamp
                if elapsed > self.COLLECTION_TIMEOUT_SEC:
                    # 强制组装
                    if "deviation" not in data:
                        data["deviation"] = DeviationReport(
                            command_id=cid,
                            step_id=validated.step_id,
                            plan_id=validated.plan_id,
                            composite_deviation=0.0,
                            alert_level="正常"
                        )
                    self._assemble_and_report(cid, data, now)
                    to_remove.append(cid)

        for cid in to_remove:
            self._pending_aggregations.pop(cid, None)

    # ========== 辅助 ==========
    def _publish_stats(self):
        if self._publish_status_report:
            rate = self._anomaly_loops / max(self._total_closed_loops, 1)
            self._publish_status_report(FeedbackStatus(
                state=self.state,
                today_closed_loops=self._total_closed_loops,
                avg_loop_duration_ms=0.0,
                anomaly_loop_rate=round(rate, 3)
            ))

    def get_state(self) -> FeedbackState:
        return self.state

    def emergency_shutdown(self):
        self.state = FeedbackState.SYSTEM_PAUSED
        # 强制上报所有未完成的闭环
        now = time.time()
        for cid in list(self._pending_aggregations.keys()):
            data = self._pending_aggregations[cid]
            if "deviation" not in data and "validated" in data:
                v = data["validated"]
                data["deviation"] = DeviationReport(
                    command_id=cid, step_id=v.step_id, plan_id=v.plan_id,
                    composite_deviation=1.0, alert_level="严重"
                )
            self._assemble_and_report(cid, data, now)
        self._pending_aggregations.clear()
        print(f"[{self.module_id}] 紧急熔断，未完成闭环已强制上报")

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
    print("  Agent-mcc-exec 闭环反馈单元 (ag-mcc-11) 演示")
    print("=" * 70)

    feedback = ClosedLoopFeedback()
    now = time.time()

    print_separator("STEP 1: 正常闭环（校验通过）")
    feedback.set_validated_result_query(lambda: ValidatedResult(
        command_id="CMD-001", step_id="S01", plan_id="P01",
        tool_name="weather_api", execution_status="success",
        validation_flag="通过",
        cleaned_output_data={"result": "晴天", "status": "ok"},
        duration_sec=2.0,
        resource_consumption={"api_calls": 1},
        timestamp=now
    ))
    feedback.run_feedback_cycle()
    print(f"  已完成闭环数: {feedback._total_closed_loops}")

    print_separator("STEP 2: 收集偏差报告后闭环")
    feedback.set_deviation_report_query(lambda: DeviationReport(
        command_id="CMD-002", step_id="S02", plan_id="P02",
        composite_deviation=0.35, alert_level="一般告警",
        alert_dimensions=["耗时偏差过大"]
    ))
    feedback.run_feedback_cycle()
    # 注入对应的校验结果
    feedback._pending_aggregations["CMD-002"] = {
        "validated": ValidatedResult(
            command_id="CMD-002", step_id="S02", plan_id="P02",
            tool_name="search_engine", execution_status="success",
            validation_flag="通过",
            cleaned_output_data={"results": []},
            duration_sec=15.0,
            resource_consumption={"api_calls": 2},
            timestamp=now
        )
    }
    feedback.run_feedback_cycle()
    print(f"  已完成闭环数: {feedback._total_closed_loops}")

    print_separator("STEP 3: 超时强制闭环")
    feedback._pending_aggregations["CMD-003"] = {
        "validated": ValidatedResult(
            command_id="CMD-003", step_id="S03", plan_id="P03",
            tool_name="slow_api", execution_status="success",
            validation_flag="通过",
            cleaned_output_data={"result": "ok"},
            duration_sec=5.0,
            timestamp=now - feedback.COLLECTION_TIMEOUT_SEC - 1
        )
    }
    feedback.run_feedback_cycle()
    print(f"  已完成闭环数: {feedback._total_closed_loops}")

    print("\n✅ 闭环反馈单元演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("ag-mcc-11 闭环反馈单元 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        def setup_feedback():
            return ClosedLoopFeedback()

        # TC-MCC-11-01: 成功结果直接闭环
        print("\n[TC-MCC-11-01] 成功结果直接闭环")
        try:
            f = setup_feedback()
            now = time.time()
            f.set_validated_result_query(lambda: ValidatedResult(
                command_id="T01", step_id="S01", plan_id="P01",
                tool_name="test", execution_status="success",
                validation_flag="通过",
                cleaned_output_data={"result": "ok"},
                duration_sec=2.0,
                timestamp=now
            ))
            f.run_feedback_cycle()
            assert f._total_closed_loops == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-11-02: 收集偏差后闭环
        print("\n[TC-MCC-11-02] 收集偏差后闭环")
        try:
            f = setup_feedback()
            now = time.time()
            f.set_deviation_report_query(lambda: DeviationReport(
                command_id="T02", step_id="S02", plan_id="P02",
                composite_deviation=0.35, alert_level="一般告警",
                alert_dimensions=["耗时偏差过大"]
            ))
            f.run_feedback_cycle()
            f._pending_aggregations["T02"] = {
                "validated": ValidatedResult(
                    command_id="T02", step_id="S02", plan_id="P02",
                    tool_name="test", execution_status="success",
                    validation_flag="通过", cleaned_output_data={},
                    duration_sec=5.0, timestamp=now
                )
            }
            f.run_feedback_cycle()
            assert f._total_closed_loops == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-11-03: 超时强制闭环
        print("\n[TC-MCC-11-03] 超时强制闭环")
        try:
            f = setup_feedback()
            now = time.time()
            f._pending_aggregations["T03"] = {
                "validated": ValidatedResult(
                    command_id="T03", step_id="S03", plan_id="P03",
                    tool_name="test", execution_status="success",
                    validation_flag="通过", cleaned_output_data={},
                    duration_sec=5.0,
                    timestamp=now - f.COLLECTION_TIMEOUT_SEC - 1
                )
            }
            f.run_feedback_cycle()
            assert f._total_closed_loops == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-11-04: 执行失败需偏差报告
        print("\n[TC-MCC-11-04] 执行失败需偏差报告")
        try:
            f = setup_feedback()
            now = time.time()
            f.set_validated_result_query(lambda: ValidatedResult(
                command_id="T04", step_id="S04", plan_id="P04",
                tool_name="test", execution_status="failure",
                validation_flag="FORMAT_ERROR",
                cleaned_output_data={},
                duration_sec=0.0,
                timestamp=now
            ))
            f.run_feedback_cycle()
            # 未偏差报告时不会立即闭环
            assert f._total_closed_loops == 0
            # 注入偏差报告
            f._pending_aggregations["T04"]["deviation"] = DeviationReport(
                command_id="T04", step_id="S04", plan_id="P04",
                composite_deviation=1.0, alert_level="严重"
            )
            f.run_feedback_cycle()
            assert f._total_closed_loops == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-11-05: 收到超时事件标记
        print("\n[TC-MCC-11-05] 收到超时事件标记")
        try:
            f = setup_feedback()
            now = time.time()
            f.set_validated_result_query(lambda: ValidatedResult(
                command_id="T05", step_id="S05", plan_id="P05",
                tool_name="test", execution_status="success",
                validation_flag="通过", cleaned_output_data={},
                duration_sec=5.0, timestamp=now
            ))
            f.run_feedback_cycle()
            f.set_timeout_event_query(lambda: TimeoutEventLog(
                task_id="T05", tool_name="test",
                timeout_threshold_sec=30.0, actual_elapsed_sec=35.0
            ))
            f.run_feedback_cycle()
            assert f._total_closed_loops == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-11-06: 紧急熔断强制上报
        print("\n[TC-MCC-11-06] 紧急熔断强制上报")
        try:
            f = setup_feedback()
            now = time.time()
            f._pending_aggregations["T06"] = {
                "validated": ValidatedResult(
                    command_id="T06", step_id="S06", plan_id="P06",
                    tool_name="test", execution_status="success",
                    validation_flag="通过", cleaned_output_data={},
                    duration_sec=1.0, timestamp=now
                )
            }
            f.emergency_shutdown()
            assert f._total_closed_loops == 1
            assert len(f._pending_aggregations) == 0
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