#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-10
模块名称: 执行偏差监控
所属分区: 四、反馈与日志
核心职责: 在工具调用执行完成后，将实际执行结果与 ag-ecc-02（任务规划模块）下发的预期目标
          进行量化比对。监控执行耗时偏差、输出数据偏差、资源消耗偏差等多维度指标，判定
          执行质量是否符合预期。当偏差超过预设阈值时，生成偏差告警通知 ag-mcc-11（闭环
          反馈单元），为 ECC 认知大脑的任务恢复决策提供数据支撑。不参与任务规划或结果修正，
          仅负责偏差的客观量化与告警。

依赖模块:
    ag-mcc-01(执行调度核心), ag-mcc-09(结果校验器), ag-ecc-02(任务规划模块)
被依赖模块:
    ag-mcc-11(闭环反馈单元), ag-mcc-12(执行日志记录单元)

安全约束:
  D-01: 本模块仅做偏差分析与告警，不直接干预任务执行或结果修正
  D-02: 偏差分析过程中使用的预期目标定义不得包含任何用户个人身份信息或敏感数据
  D-03: 偏差告警仅作为辅助决策参考，最终恢复策略由 ag-ecc-02 任务规划模块决定
  D-04: 偏差分析报告中的原始输出数据必须在发送前经过去敏感化处理
"""

from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid


class MonitorState(Enum):
    WAITING_RESULT = "waiting_result"
    ANALYZING = "analyzing"
    ANALYZED = "analyzed"
    SYSTEM_PAUSED = "system_paused"


class AlertLevel(Enum):
    NORMAL = "正常"
    WARNING = "一般告警"
    CRITICAL = "严重告警"


@dataclass
class ValidatedResult:
    command_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    tool_name: str = ""
    tool_type: str = ""
    execution_status: str = "success"
    cleaned_output_data: Any = None
    duration_sec: float = 0.0
    resource_consumption: Dict[str, float] = field(default_factory=dict)
    validation_flag: str = "通过"


@dataclass
class ExpectedTarget:
    step_id: str = ""
    expected_output_format: Dict[str, Any] = field(default_factory=dict)
    acceptable_deviation: float = 0.2
    estimated_duration_sec: float = 30.0
    kpis: Dict[str, Any] = field(default_factory=dict)
    max_resource_consumption: Dict[str, float] = field(default_factory=dict)


@dataclass
class DeviationReport:
    command_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    composite_deviation: float = 0.0
    dimension_details: Dict[str, float] = field(default_factory=dict)
    alert_level: AlertLevel = AlertLevel.NORMAL
    alert_dimensions: List[str] = field(default_factory=list)
    suggestion: str = ""


@dataclass
class DeviationAlert:
    command_id: str = ""
    step_id: str = ""
    dimension: str = ""
    deviation_magnitude: float = 0.0
    severity: AlertLevel = AlertLevel.NORMAL
    recovery_suggestion: str = ""


@dataclass
class DeviationEventLog:
    command_id: str = ""
    deviation_type: str = ""
    deviation_value: float = 0.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class MonitorStatus:
    state: MonitorState = MonitorState.WAITING_RESULT
    today_analyses: int = 0
    alert_rate: float = 0.0
    avg_deviation: float = 0.0
    avg_analysis_ms: float = 0.0


class DeviationMonitor:
    # 偏差监控维度权重
    WEIGHT_DURATION = 0.25
    WEIGHT_OUTPUT_FORMAT = 0.30
    WEIGHT_KPI = 0.25
    WEIGHT_RESOURCE = 0.20

    # 告警阈值
    COMPOSITE_CRITICAL_THRESHOLD = 0.5
    COMPOSITE_WARNING_THRESHOLD = 0.3
    DURATION_DEVIATION_THRESHOLD = 0.5
    FORMAT_DEVIATION_THRESHOLD = 0.3
    RESOURCE_DEVIATION_THRESHOLD = 0.4

    # 统计上报间隔
    STATS_REPORT_INTERVAL_SEC = 60
    # 去重缓存有效期
    DEDUP_CACHE_TTL_SEC = 5

    def __init__(self):
        self.module_id = "ag-mcc-10"
        self.module_name = "执行偏差监控"
        self.version = "V1.0"

        self.state = MonitorState.WAITING_RESULT
        self._total_analyses: int = 0
        self._alert_count: int = 0
        self._total_composite_deviation: float = 0.0
        self._total_duration: float = 0.0
        self._dedup_cache: Dict[str, Tuple[DeviationReport, float]] = {}
        self._last_stats_time: float = time.time()
        self._pending_logs: List[Dict[str, Any]] = []

        # 回调注入
        self._query_validated_result = None
        self._query_expected_target = None

        self._publish_deviation_report = None
        self._publish_deviation_alert = None
        self._publish_event_log_internal = None
        self._publish_status_report = None
        self._publish_event_log = None

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ========== 回调注入 ==========
    def set_validated_result_query(self, callback: Callable[[], Optional[ValidatedResult]]):
        self._query_validated_result = callback

    def set_expected_target_query(self, callback: Callable[[str], Optional[ExpectedTarget]]):
        self._query_expected_target = callback

    def set_deviation_report_publisher(self, callback: Callable[[DeviationReport], None]):
        self._publish_deviation_report = callback

    def set_deviation_alert_publisher(self, callback: Callable[[DeviationAlert], None]):
        self._publish_deviation_alert = callback

    def set_event_log_internal_publisher(self, callback: Callable[[DeviationEventLog], None]):
        self._publish_event_log_internal = callback

    def set_status_report_publisher(self, callback: Callable[[MonitorStatus], None]):
        self._publish_status_report = callback

    def set_event_log_publisher(self, callback: Callable[[Dict[str, Any]], None]):
        self._publish_event_log = callback

    # ========== 主循环 ==========
    def run_monitor_cycle(self) -> Optional[DeviationReport]:
        now = time.time()

        if self.state == MonitorState.SYSTEM_PAUSED:
            return None

        # 定期统计上报
        if now - self._last_stats_time >= self.STATS_REPORT_INTERVAL_SEC:
            self._publish_stats()
            self._last_stats_time = now

        # 接收校验后结果
        validated = self._query_validated_result() if self._query_validated_result else None
        if validated is None:
            return None

        # 去重检查
        if validated.command_id in self._dedup_cache:
            cached_result, cached_time = self._dedup_cache[validated.command_id]
            if now - cached_time < self.DEDUP_CACHE_TTL_SEC:
                return cached_result

        # 执行失败直接标记为最大偏差
        if validated.execution_status in ("failure", "timeout", "exception"):
            report = DeviationReport(
                command_id=validated.command_id,
                step_id=validated.step_id,
                plan_id=validated.plan_id,
                composite_deviation=1.0,
                dimension_details={"status": 1.0},
                alert_level=AlertLevel.CRITICAL,
                alert_dimensions=["执行失败"],
                suggestion="任务执行失败，建议检查执行日志并尝试恢复"
            )
            self._finalize_report(report, validated, now)
            return report

        self.state = MonitorState.ANALYZING
        start_time = time.time()

        # 获取预期目标
        expected = self._query_expected_target(validated.step_id) if self._query_expected_target else None
        if expected is None:
            expected = ExpectedTarget(step_id=validated.step_id)

        # 各维度偏差分析
        details = {}
        alert_dims = []

        # 1. 耗时偏差
        if expected.estimated_duration_sec > 0:
            duration_dev = abs(validated.duration_sec - expected.estimated_duration_sec) / expected.estimated_duration_sec
            details["duration"] = round(duration_dev, 3)
            if duration_dev > self.DURATION_DEVIATION_THRESHOLD:
                alert_dims.append("耗时偏差过大")
        else:
            details["duration"] = 0.0

        # 2. 输出格式偏差
        format_dev = self._calculate_format_deviation(validated.cleaned_output_data, expected.expected_output_format)
        details["output_format"] = round(format_dev, 3)
        if format_dev > self.FORMAT_DEVIATION_THRESHOLD:
            alert_dims.append("输出格式偏差过大")

        # 3. KPI偏差
        kpi_dev = self._calculate_kpi_deviation(validated.cleaned_output_data, expected.kpis)
        details["kpi"] = round(kpi_dev, 3)
        if kpi_dev > 0:
            alert_dims.append("KPI未达成")

        # 4. 资源消耗偏差
        resource_dev = self._calculate_resource_deviation(validated.resource_consumption, expected.max_resource_consumption)
        details["resource"] = round(resource_dev, 3)
        if resource_dev > self.RESOURCE_DEVIATION_THRESHOLD:
            alert_dims.append("资源消耗偏差过大")

        # 计算综合偏差度
        composite = (
            self.WEIGHT_DURATION * details["duration"] +
            self.WEIGHT_OUTPUT_FORMAT * details["output_format"] +
            self.WEIGHT_KPI * details["kpi"] +
            self.WEIGHT_RESOURCE * details["resource"]
        )
        composite = round(composite, 3)

        # 判定告警等级
        if composite >= self.COMPOSITE_CRITICAL_THRESHOLD:
            level = AlertLevel.CRITICAL
        elif composite >= self.COMPOSITE_WARNING_THRESHOLD:
            level = AlertLevel.WARNING
        else:
            level = AlertLevel.NORMAL

        suggestion = self._generate_suggestion(alert_dims)

        report = DeviationReport(
            command_id=validated.command_id,
            step_id=validated.step_id,
            plan_id=validated.plan_id,
            composite_deviation=composite,
            dimension_details=details,
            alert_level=level,
            alert_dimensions=alert_dims,
            suggestion=suggestion
        )

        elapsed = (time.time() - start_time) * 1000
        self._total_duration += elapsed

        self._finalize_report(report, validated, now)
        return report

    def _calculate_format_deviation(self, output: Any, expected_format: Dict[str, Any]) -> float:
        if not expected_format:
            return 0.0
        if output is None:
            return 1.0
        if isinstance(output, dict) and expected_format:
            expected_keys = set(expected_format.keys())
            output_keys = set(output.keys())
            if not expected_keys:
                return 0.0
            overlap = len(expected_keys & output_keys)
            return 1.0 - (overlap / len(expected_keys))
        return 0.0

    def _calculate_kpi_deviation(self, output: Any, kpis: Dict[str, Any]) -> float:
        if not kpis:
            return 0.0
        if output is None:
            return 1.0
        failed = 0
        total = len(kpis)
        for kpi_name, target in kpis.items():
            actual = output.get(kpi_name) if isinstance(output, dict) else None
            if actual is None or actual != target:
                failed += 1
        return failed / total if total > 0 else 0.0

    def _calculate_resource_deviation(self, actual: Dict[str, float], expected: Dict[str, float]) -> float:
        if not expected:
            return 0.0
        if not actual:
            return 1.0
        deviations = []
        for key, limit in expected.items():
            actual_val = actual.get(key, 0)
            if limit > 0:
                deviations.append(max(0, actual_val - limit) / limit)
        if not deviations:
            return 0.0
        return sum(deviations) / len(deviations)

    def _generate_suggestion(self, alert_dims: List[str]) -> str:
        if not alert_dims:
            return "执行结果符合预期，无需处理"
        return f"建议关注以下偏差维度: {', '.join(alert_dims)}"

    def _finalize_report(self, report: DeviationReport, validated: ValidatedResult, now: float):
        self._dedup_cache[validated.command_id] = (report, now)
        # 清理过期缓存
        expired = [cid for cid, (_, t) in self._dedup_cache.items() if now - t > self.DEDUP_CACHE_TTL_SEC]
        for cid in expired:
            del self._dedup_cache[cid]

        self._total_analyses += 1
        if report.alert_level != AlertLevel.NORMAL:
            self._alert_count += 1
        self._total_composite_deviation += report.composite_deviation

        self.state = MonitorState.ANALYZED

        # 发送偏差分析报告
        if self._publish_deviation_report:
            self._publish_deviation_report(report)

        # 告警时发送偏差告警
        if report.alert_level != AlertLevel.NORMAL:
            if self._publish_deviation_alert:
                for dim in report.alert_dimensions:
                    self._publish_deviation_alert(DeviationAlert(
                        command_id=report.command_id,
                        step_id=report.step_id,
                        dimension=dim,
                        deviation_magnitude=report.composite_deviation,
                        severity=report.alert_level,
                        recovery_suggestion=report.suggestion
                    ))

        # 记录事件日志
        if self._publish_event_log_internal:
            self._publish_event_log_internal(DeviationEventLog(
                command_id=report.command_id,
                deviation_type=report.alert_level.value,
                deviation_value=report.composite_deviation
            ))

        self.state = MonitorState.WAITING_RESULT

    # ========== 辅助 ==========
    def _publish_stats(self):
        if self._publish_status_report:
            rate = self._alert_count / max(self._total_analyses, 1)
            avg_dev = self._total_composite_deviation / max(self._total_analyses, 1)
            avg_dur = self._total_duration / max(self._total_analyses, 1)
            self._publish_status_report(MonitorStatus(
                state=self.state,
                today_analyses=self._total_analyses,
                alert_rate=round(rate, 3),
                avg_deviation=round(avg_dev, 3),
                avg_analysis_ms=round(avg_dur, 2)
            ))

    def get_state(self) -> MonitorState:
        return self.state

    def emergency_shutdown(self):
        self.state = MonitorState.SYSTEM_PAUSED
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
    print("  Agent-mcc-exec 执行偏差监控 (ag-mcc-10) 演示")
    print("=" * 70)

    monitor = DeviationMonitor()
    monitor.set_expected_target_query(lambda step_id: ExpectedTarget(
        step_id=step_id,
        estimated_duration_sec=10.0,
        expected_output_format={"result": {}, "status": {}},
        kpis={"status": "ok"},
        max_resource_consumption={"api_calls": 1, "memory_mb": 50}
    ))

    print_separator("STEP 1: 正常偏差")
    monitor.set_validated_result_query(lambda: ValidatedResult(
        command_id="CMD-001", step_id="S01", plan_id="P01",
        execution_status="success",
        cleaned_output_data={"result": "ok", "status": "ok"},
        duration_sec=8.0,
        resource_consumption={"api_calls": 1, "memory_mb": 30}
    ))
    report = monitor.run_monitor_cycle()
    if report:
        print(f"  综合偏差度: {report.composite_deviation}")
        print(f"  告警等级: {report.alert_level.value}")

    print_separator("STEP 2: 耗时严重超标")
    monitor.set_validated_result_query(lambda: ValidatedResult(
        command_id="CMD-002", step_id="S02", plan_id="P02",
        execution_status="success",
        cleaned_output_data={"result": "ok", "status": "ok"},
        duration_sec=25.0,
        resource_consumption={"api_calls": 1, "memory_mb": 30}
    ))
    report = monitor.run_monitor_cycle()
    if report:
        print(f"  综合偏差度: {report.composite_deviation}")
        print(f"  告警等级: {report.alert_level.value}")
        print(f"  告警维度: {report.alert_dimensions}")

    print_separator("STEP 3: 执行失败直接最大偏差")
    monitor.set_validated_result_query(lambda: ValidatedResult(
        command_id="CMD-003", step_id="S03", plan_id="P03",
        execution_status="failure",
        cleaned_output_data=None,
        duration_sec=0.0,
        resource_consumption={}
    ))
    report = monitor.run_monitor_cycle()
    if report:
        print(f"  综合偏差度: {report.composite_deviation}")
        print(f"  告警等级: {report.alert_level.value}")

    print("\n✅ 执行偏差监控演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("ag-mcc-10 执行偏差监控 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        def setup_monitor():
            m = DeviationMonitor()
            m.set_expected_target_query(lambda step_id: ExpectedTarget(
                step_id=step_id,
                estimated_duration_sec=10.0,
                expected_output_format={"result": {}, "status": {}},
                kpis={"status": "ok"},
                max_resource_consumption={"api_calls": 1, "memory_mb": 50}
            ))
            return m

        # TC-MCC-10-01: 正常偏差
        print("\n[TC-MCC-10-01] 正常偏差")
        try:
            m = setup_monitor()
            m.set_validated_result_query(lambda: ValidatedResult(
                command_id="T01", step_id="S01", plan_id="P01",
                execution_status="success",
                cleaned_output_data={"result": "ok", "status": "ok"},
                duration_sec=8.0,
                resource_consumption={"api_calls": 1, "memory_mb": 30}
            ))
            report = m.run_monitor_cycle()
            assert report is not None
            assert report.alert_level == AlertLevel.NORMAL
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-10-02: 耗时严重超标
        print("\n[TC-MCC-10-02] 耗时严重超标")
        try:
            m = setup_monitor()
            m.set_validated_result_query(lambda: ValidatedResult(
                command_id="T02", step_id="S02", plan_id="P02",
                execution_status="success",
                cleaned_output_data={"result": "ok", "status": "ok"},
                duration_sec=25.0,
                resource_consumption={"api_calls": 1, "memory_mb": 30}
            ))
            report = m.run_monitor_cycle()
            assert report is not None
            assert "耗时偏差过大" in report.alert_dimensions
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-10-03: KPI未达成
        print("\n[TC-MCC-10-03] KPI未达成")
        try:
            m = setup_monitor()
            m.set_validated_result_query(lambda: ValidatedResult(
                command_id="T03", step_id="S03", plan_id="P03",
                execution_status="success",
                cleaned_output_data={"result": "ok", "status": "fail"},
                duration_sec=8.0,
                resource_consumption={"api_calls": 1, "memory_mb": 30}
            ))
            report = m.run_monitor_cycle()
            assert report is not None
            assert "KPI未达成" in report.alert_dimensions
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-10-04: 多维度综合告警
        print("\n[TC-MCC-10-04] 多维度综合告警")
        try:
            m = setup_monitor()
            m.set_validated_result_query(lambda: ValidatedResult(
                command_id="T04", step_id="S04", plan_id="P04",
                execution_status="success",
                cleaned_output_data={"result": "ok"},
                duration_sec=30.0,
                resource_consumption={"api_calls": 5, "memory_mb": 200}
            ))
            report = m.run_monitor_cycle()
            assert report is not None
            assert report.alert_level == AlertLevel.CRITICAL
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-10-05: 执行失败直接最大偏差
        print("\n[TC-MCC-10-05] 执行失败直接最大偏差")
        try:
            m = setup_monitor()
            m.set_validated_result_query(lambda: ValidatedResult(
                command_id="T05", step_id="S05", plan_id="P05",
                execution_status="failure",
                cleaned_output_data=None,
                duration_sec=0.0,
                resource_consumption={}
            ))
            report = m.run_monitor_cycle()
            assert report is not None
            assert report.composite_deviation == 1.0
            assert report.alert_level == AlertLevel.CRITICAL
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-10-06: 紧急熔断
        print("\n[TC-MCC-10-06] 紧急熔断")
        try:
            m = setup_monitor()
            m.emergency_shutdown()
            assert m.state == MonitorState.SYSTEM_PAUSED
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