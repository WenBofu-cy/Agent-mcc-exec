#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-10
模块名称: 执行偏差监控
所属分区: 四、反馈与日志
版本: V1.0
原创提出者: 文波福
开源协议: CC BY-NC 4.0

核心职责:
    在工具调用执行完成后，将实际执行结果与 ag-ecc-02（任务规划模块）下发的预期目标
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

架构约束:
  禁止跨系统直连：本模块不能通过 InternalBus 直接向 ag-ecc-* 发送请求，
  所有外部数据必须由调用方 ag-mcc-01 在请求中作为参数传入。
"""

from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid
import threading
import json


class MonitorState(Enum):
    WAITING_RESULT = "WAITING_RESULT"
    ANALYZING = "ANALYZING"
    ANALYZED = "ANALYZED"
    SYSTEM_PAUSED = "SYSTEM_PAUSED"


class AlertLevel(Enum):
    NORMAL = "正常"
    WARNING = "一般告警"
    CRITICAL = "严重告警"


@dataclass
class ValidatedResult:
    instruction_id: str = ""
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
    instruction_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    composite_deviation: float = 0.0
    dimension_details: Dict[str, float] = field(default_factory=dict)
    alert_level: AlertLevel = AlertLevel.NORMAL
    alert_dimensions: List[str] = field(default_factory=list)
    suggestion: str = ""


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

        # 总线引用（由主入口注入）
        self.bus = None

        self.state = MonitorState.WAITING_RESULT
        self._lock = threading.Lock()
        self._total_analyses: int = 0
        self._alert_count: int = 0
        self._total_composite_deviation: float = 0.0
        self._total_duration: float = 0.0
        self._dedup_cache: Dict[str, Tuple[DeviationReport, float]] = {}
        self._last_stats_time: float = time.time()

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ====================== 主循环（SPEC 定义的标准方法名） ======================
    def deviation_monitor_main_loop(self):
        """执行一个主循环周期"""
        now = time.time()

        if self.state == MonitorState.SYSTEM_PAUSED:
            return

        # 定期统计上报
        if now - self._last_stats_time >= self.STATS_REPORT_INTERVAL_SEC:
            self._publish_stats()
            self._last_stats_time = now

    # ====================== 消息处理（InternalBus） ======================
    def handle_message(self, message):
        """处理来自 InternalBus 的消息"""
        if not self.bus or not message:
            return

        data = message.data if message.data else {}
        topic = message.topic

        # 接收偏差分析请求（来自 ag-mcc-01，应包含校验后结果和预期目标）
        if topic == "ag-mcc-10.deviation_analysis":
            try:
                validated = ValidatedResult(
                    instruction_id=data.get("instruction_id", ""),
                    step_id=data.get("step_id", ""),
                    plan_id=data.get("plan_id", ""),
                    tool_name=data.get("tool_name", ""),
                    tool_type=data.get("tool_type", ""),
                    execution_status=data.get("execution_status", "success"),
                    cleaned_output_data=data.get("cleaned_output_data"),
                    duration_sec=data.get("duration_sec", 0.0),
                    resource_consumption=data.get("resource_consumption", {}),
                    validation_flag=data.get("validation_flag", "通过")
                )
                # 预期目标由调用方传入，不再跨系统查询（遵守架构约束）
                expected = self._parse_expected_target(data.get("expected_target", {}))
                self._handle_analysis(validated, expected)
            except Exception:
                return

        # 接收全局调度指令
        elif topic == "ag-mcc-10.global_command":
            command = data.get("command", "")
            if command == "emergency_shutdown":
                self.emergency_shutdown()

    def _parse_expected_target(self, raw: Dict[str, Any]) -> ExpectedTarget:
        """从请求数据中解析预期目标，若缺失则使用默认值"""
        return ExpectedTarget(
            step_id=raw.get("step_id", ""),
            expected_output_format=raw.get("expected_output_format", {}),
            acceptable_deviation=raw.get("acceptable_deviation", 0.2),
            estimated_duration_sec=raw.get("estimated_duration_sec", 30.0),
            kpis=raw.get("kpis", {}),
            max_resource_consumption=raw.get("max_resource_consumption", {})
        )

    # ====================== 偏差分析执行 ======================
    def _handle_analysis(self, validated: ValidatedResult, expected: ExpectedTarget):
        """执行偏差分析并输出"""
        now = time.time()
        instruction_id = validated.instruction_id

        # 去重检查 + 线程安全
        with self._lock:
            if instruction_id in self._dedup_cache:
                cached_result, cached_time = self._dedup_cache[instruction_id]
                if now - cached_time < self.DEDUP_CACHE_TTL_SEC:
                    self._send_deviation_report(cached_result)
                    return

        self.state = MonitorState.ANALYZING
        start_time = time.time()

        # 执行失败/超时/异常 直接标记为最大偏差
        if validated.execution_status in ("failure", "timeout", "exception"):
            report = DeviationReport(
                instruction_id=validated.instruction_id,
                step_id=validated.step_id,
                plan_id=validated.plan_id,
                composite_deviation=1.0,
                dimension_details={"status": 1.0},
                alert_level=AlertLevel.CRITICAL,
                alert_dimensions=["执行失败"],
                suggestion="任务执行失败，建议检查执行日志并尝试恢复"
            )
            self._finalize_report(report, validated, now)
            return

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
            instruction_id=validated.instruction_id,
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

    # ====================== 偏差计算方法（与 SPEC 一致） ======================
    def _calculate_format_deviation(self, output: Any, expected_format: Dict[str, Any]) -> float:
        if not expected_format:
            return 0.0
        if output is None:
            return 1.0
        if isinstance(output, dict):
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
            actual_val = actual.get(key, 0.0)
            if limit > 0:
                dev = max(0.0, actual_val - limit) / limit
                deviations.append(dev)
        if not deviations:
            return 0.0
        return sum(deviations) / len(deviations)

    def _generate_suggestion(self, alert_dims: List[str]) -> str:
        if not alert_dims:
            return "执行结果符合预期，无需处理"
        return f"建议关注以下偏差维度: {', '.join(alert_dims)}"

    # ====================== 结果处理与总线发送 ======================
    def _finalize_report(self, report: DeviationReport, validated: ValidatedResult, now: float):
        instruction_id = validated.instruction_id

        # 缓存更新+过期清理（加锁，线程安全）
        with self._lock:
            self._dedup_cache[instruction_id] = (report, now)
            expired = [cid for cid, (_, t) in self._dedup_cache.items() if now - t > self.DEDUP_CACHE_TTL_SEC]
            for cid in expired:
                del self._dedup_cache[cid]

            # 全局统计更新
            self._total_analyses += 1
            if report.alert_level != AlertLevel.NORMAL:
                self._alert_count += 1
            self._total_composite_deviation += report.composite_deviation

        self.state = MonitorState.ANALYZED

        # D-04: 输出数据脱敏后再发送
        self._send_deviation_report(report)

        # 告警时发送偏差告警至 ag-mcc-01
        if report.alert_level != AlertLevel.NORMAL:
            self._send_deviation_alert(report)

        # 记录事件日志至 ag-mcc-12
        self._send_event_log(report)

        self.state = MonitorState.WAITING_RESULT

    def _send_deviation_report(self, report: DeviationReport):
        if not self.bus:
            return
        # D-04 数据脱敏：敏感字段剔除/掩码
        send_data = {
            "instruction_id": report.instruction_id,
            "step_id": report.step_id,
            "plan_id": report.plan_id,
            "composite_deviation": report.composite_deviation,
            "dimension_details": report.dimension_details,
            "alert_level": report.alert_level.value,
            "alert_dimensions": report.alert_dimensions,
            "suggestion": report.suggestion,
        }
        self.bus.publish_to_module(
            target_module="ag-mcc-11",
            event_type="deviation_report",
            source_module=self.module_id,
            data=send_data
        )

    def _send_deviation_alert(self, report: DeviationReport):
        if not self.bus:
            return
        for dim in report.alert_dimensions:
            self.bus.publish_to_module(
                target_module="ag-mcc-01",
                event_type="deviation_alert",
                source_module=self.module_id,
                data={
                    "instruction_id": report.instruction_id,
                    "step_id": report.step_id,
                    "dimension": dim,
                    "deviation_magnitude": report.composite_deviation,
                    "severity": report.alert_level.value,
                    "recovery_suggestion": report.suggestion,
                }
            )

    def _send_event_log(self, report: DeviationReport):
        if not self.bus:
            return
        self.bus.publish_to_module(
            target_module="ag-mcc-12",
            event_type="deviation_event",
            source_module=self.module_id,
            data={
                "log_id": f"log-{uuid.uuid4().hex[:8]}",
                "instruction_id": report.instruction_id,
                "deviation_type": report.alert_level.value,
                "deviation_value": report.composite_deviation,
                "timestamp": time.time()
            }
        )

    # ====================== 状态上报 & 运维 ======================
    def _publish_stats(self):
        if not self.bus:
            return
        with self._lock:
            total = max(self._total_analyses, 1)
            rate = self._alert_count / total
            avg_dev = self._total_composite_deviation / total
        avg_dur = self._total_duration / max(self._total_analyses, 1)

        self.bus.publish_to_module(
            target_module="ag-mcc-12",
            event_type="monitor_status",
            source_module=self.module_id,
            data={
                "state": self.state.value,
                "today_analyses": self._total_analyses,
                "alert_rate": round(rate, 3),
                "avg_deviation": round(avg_dev, 3),
                "avg_analysis_ms": round(avg_dur, 2)
            }
        )

    def get_state(self) -> MonitorState:
        return self.state

    def emergency_shutdown(self):
        self.state = MonitorState.SYSTEM_PAUSED
        # 紧急熔断清空缓存
        with self._lock:
            self._dedup_cache.clear()
        print(f"[{self.module_id}] 紧急熔断，服务已暂停")

    def shutdown(self):
        self.state = MonitorState.WAITING_RESULT
        print(f"[{self.module_id}] 已安全关闭")


# ====================== 演示与测试 ======================
def demo_main():
    print("=" * 70)
    print("  ag-mcc-10 执行偏差监控 V1.0 演示")
    print("=" * 70)

    from memory_bus import InternalBus
    bus = InternalBus()
    bus.register_module("ag-mcc-10")
    bus.register_module("ag-mcc-11")
    bus.register_module("ag-mcc-12")
    bus.register_module("ag-mcc-01")

    monitor = DeviationMonitor()
    monitor.bus = bus
    bus.subscribe_to_module("ag-mcc-10", monitor.handle_message)

    # 模拟带有预期目标的正常偏差分析
    print("\n[演示1] 正常偏差分析 (预期目标由请求携带)")
    bus.publish_to_module("ag-mcc-10", "deviation_analysis", "ag-mcc-01", {
        "instruction_id": "CMD-001",
        "step_id": "S01",
        "plan_id": "P01",
        "execution_status": "success",
        "cleaned_output_data": {"result": "ok", "status": "ok"},
        "duration_sec": 8.0,
        "resource_consumption": {"api_calls": 1, "memory_mb": 30},
        "expected_target": {
            "step_id": "S01",
            "expected_output_format": {"result": "", "status": ""},
            "estimated_duration_sec": 10.0,
            "kpis": {"status": "ok"},
            "max_resource_consumption": {"memory_mb": 50}
        }
    })
    bus.process_all()
    monitor.deviation_monitor_main_loop()

    # 模拟执行失败（最大偏差）
    print("\n[演示2] 执行失败直接最大偏差")
    bus.publish_to_module("ag-mcc-10", "deviation_analysis", "ag-mcc-01", {
        "instruction_id": "CMD-002",
        "step_id": "S02",
        "plan_id": "P02",
        "execution_status": "failure",
        "cleaned_output_data": None,
        "duration_sec": 0.0,
        "resource_consumption": {}
    })
    bus.process_all()
    monitor.deviation_monitor_main_loop()

    # 模拟重复请求去重
    print("\n[演示3] 重复指令去重测试")
    bus.publish_to_module("ag-mcc-10", "deviation_analysis", "ag-mcc-01", {
        "instruction_id": "CMD-001",
        "step_id": "S01",
        "plan_id": "P01",
        "execution_status": "success",
        "cleaned_output_data": {"result": "ok", "status": "ok"},
        "duration_sec": 8.0,
        "resource_consumption": {"api_calls": 1, "memory_mb": 30},
        "expected_target": {
            "step_id": "S01",
            "expected_output_format": {"result": "", "status": ""},
            "estimated_duration_sec": 10.0,
            "kpis": {"status": "ok"},
            "max_resource_consumption": {"memory_mb": 50}
        }
    })
    bus.process_all()
    monitor.deviation_monitor_main_loop()

    print(f"\n总分析次数: {monitor._total_analyses}, 告警次数: {monitor._alert_count}")
    print("\n✅ 演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("单元测试入口已就绪，可扩展测试用例")
    else:
        demo_main()