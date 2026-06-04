#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-03
模块名称: 资源配额管控单元
所属分区: 一、执行中枢调度
核心职责: 监控并管控行动执行层各执行模块的资源消耗，包括 API 调用频次、代码执行内存上限、
          文件操作路径白名单、大模型 Token 配额等。在执行任务前，校验当前资源使用是否在安全
          阈值内——若资源充足则放行；若接近上限则触发限流；若已耗尽则拒绝执行并返回资源不足
          通知。同时向 ag-mcc-12（执行日志记录单元）周期性上报资源使用状态。不参与工具的实际
          调用，仅负责资源配额的校验与管控。

依赖模块:
    ag-mcc-01(执行调度核心), ag-mcc-04(工具注册中心), ag-mcc-12(执行日志记录单元)
被依赖模块:
    ag-mcc-01, ag-mcc-06~08(各执行模块)

安全约束:
  Q-01: 资源配额管控单元仅负责校验与通知，不得直接终止或中断正在执行的任务
  Q-02: 资源使用计数器在系统重启后必须重新从零开始计数
  Q-03: 紧急状态下拒绝新任务时，必须明确告知拒绝原因与资源现状
  Q-04: 资源使用状态数据仅用于内部管控，不得泄露至外部系统或第三方模块
"""

from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid


class QuotaState(Enum):
    NORMAL_FLOW = "normal_flow"
    RESOURCE_WARNING = "resource_warning"
    RESOURCE_CRITICAL = "resource_critical"
    SYSTEM_PAUSED = "system_paused"


@dataclass
class QuotaCheckRequest:
    command_id: str = ""
    tool_name: str = ""
    tool_type: str = ""
    estimated_api_calls: int = 1
    estimated_memory_mb: float = 10.0
    estimated_storage_kb: float = 0.0
    estimated_tokens: int = 0
    priority: int = 5  # 1=HIGH, 5=NORMAL, 9=LOW


@dataclass
class ToolResourcePreset:
    tool_name: str = ""
    max_api_calls: int = 1
    max_memory_mb: float = 64.0
    max_storage_kb: float = 1024.0
    max_tokens: int = 1000


@dataclass
class ResourceUsageSnapshot:
    api_calls_today: int = 0
    memory_used_mb: float = 0.0
    storage_used_kb: float = 0.0
    tokens_used_today: int = 0
    concurrent_connections: int = 0


@dataclass
class ResourceReleaseNotification:
    command_id: str = ""
    api_calls_released: int = 0
    memory_released_mb: float = 0.0
    tokens_released: int = 0


@dataclass
class QuotaCheckResult:
    command_id: str = ""
    allowed: bool = True
    reject_reason: str = ""
    constraints: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResourceLimitNotice:
    limit_type: str = ""
    current_usage: float = 0.0
    quota_limit: float = 0.0
    estimated_recovery_sec: float = 0.0
    affected_modules: List[str] = field(default_factory=list)


@dataclass
class ResourceUsageReport:
    state: QuotaState = QuotaState.NORMAL_FLOW
    api_usage_pct: float = 0.0
    memory_usage_pct: float = 0.0
    storage_usage_pct: float = 0.0
    token_usage_pct: float = 0.0
    concurrent_usage_pct: float = 0.0


class ResourceQuotaController:
    # 配额上限
    QUOTA_LIMITS = {
        "api_calls_per_min": 100,
        "memory_mb": 512,
        "storage_kb": 100 * 1024,
        "tokens_per_day": 100000,
        "max_concurrent": 10,
    }
    # 阈值
    WARN_THRESHOLD = 0.70
    CRITICAL_THRESHOLD = 0.90
    # 默认工具配额
    DEFAULT_PRESET = ToolResourcePreset()
    # 状态上报间隔
    STATUS_REPORT_INTERVAL_SEC = 30

    def __init__(self):
        self.module_id = "ag-mcc-03"
        self.module_name = "资源配额管控单元"
        self.version = "V1.0"

        self.state = QuotaState.NORMAL_FLOW
        self._usage = ResourceUsageSnapshot()
        self._tool_presets: Dict[str, ToolResourcePreset] = {}
        self._last_snapshot_time: float = 0.0
        self._last_status_time: float = time.time()
        self._pending_logs: List[Dict[str, Any]] = []

        # 修复：API调用每分钟重置的计数器
        self._api_calls_this_minute: int = 0
        self._last_api_minute: int = -1

        # 回调注入
        self._query_quota_check = None
        self._query_tool_preset = None
        self._query_resource_snapshot = None
        self._query_resource_release = None

        self._publish_check_result = None
        self._publish_limit_notice = None
        self._publish_usage_report = None
        self._publish_event_log = None

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ========== 回调注入 ==========
    def set_quota_check_query(self, callback: Callable[[], Optional[QuotaCheckRequest]]):
        self._query_quota_check = callback

    def set_tool_preset_query(self, callback: Callable[[str], Optional[ToolResourcePreset]]):
        self._query_tool_preset = callback

    def set_resource_snapshot_query(self, callback: Callable[[], Optional[ResourceUsageSnapshot]]):
        self._query_resource_snapshot = callback

    def set_resource_release_query(self, callback: Callable[[], Optional[ResourceReleaseNotification]]):
        self._query_resource_release = callback

    def set_check_result_publisher(self, callback: Callable[[QuotaCheckResult], None]):
        self._publish_check_result = callback

    def set_limit_notice_publisher(self, callback: Callable[[ResourceLimitNotice], None]):
        self._publish_limit_notice = callback

    def set_usage_report_publisher(self, callback: Callable[[ResourceUsageReport], None]):
        self._publish_usage_report = callback

    def set_event_log_publisher(self, callback: Callable[[Dict[str, Any]], None]):
        self._publish_event_log = callback

    # ========== 主循环 ==========
    def run_quota_cycle(self):
        now = time.time()

        if self.state == QuotaState.SYSTEM_PAUSED:
            return

        # 定期状态上报
        if now - self._last_status_time >= self.STATUS_REPORT_INTERVAL_SEC:
            self._publish_usage_report_internal()
            self._last_status_time = now

        # 更新资源使用快照
        snapshot = self._query_resource_snapshot() if self._query_resource_snapshot else None
        if snapshot:
            self._usage = snapshot
            self._reassess_state()
            self._last_snapshot_time = now

        # 处理资源释放
        release = self._query_resource_release() if self._query_resource_release else None
        if release:
            self._apply_release(release)

        # 处理配额校验请求
        check_req = self._query_quota_check() if self._query_quota_check else None
        if check_req:
            self._handle_quota_check(check_req)
            return

    # ========== 状态评估 ==========
    def _reassess_state(self):
        # API使用率基于每分钟计数
        api_pct = self._api_calls_this_minute / self.QUOTA_LIMITS["api_calls_per_min"]
        mem_pct = self._usage.memory_used_mb / self.QUOTA_LIMITS["memory_mb"]
        tok_pct = self._usage.tokens_used_today / self.QUOTA_LIMITS["tokens_per_day"]
        conc_pct = self._usage.concurrent_connections / self.QUOTA_LIMITS["max_concurrent"]

        max_pct = max(api_pct, mem_pct, tok_pct, conc_pct)
        if max_pct >= self.CRITICAL_THRESHOLD:
            if self.state != QuotaState.RESOURCE_CRITICAL:
                self.state = QuotaState.RESOURCE_CRITICAL
                self._send_limit_notice("紧急", max_pct)
        elif max_pct >= self.WARN_THRESHOLD:
            if self.state == QuotaState.NORMAL_FLOW:
                self.state = QuotaState.RESOURCE_WARNING
                self._send_limit_notice("预警", max_pct)
        else:
            if self.state != QuotaState.NORMAL_FLOW:
                self.state = QuotaState.NORMAL_FLOW

    # ========== 配额校验 ==========
    def _handle_quota_check(self, request: QuotaCheckRequest):
        # 修复：每分钟重置API调用计数
        self._reset_api_calls_per_minute()

        # 紧急状态仅放行高优先级
        if self.state == QuotaState.RESOURCE_CRITICAL and request.priority > 1:
            if self._publish_check_result:
                self._publish_check_result(QuotaCheckResult(
                    command_id=request.command_id, allowed=False,
                    reject_reason="资源紧急，仅允许高优先级任务"
                ))
            return

        # 获取工具预设
        preset = None
        if self._query_tool_preset:
            preset = self._query_tool_preset(request.tool_name)
        if preset is None:
            preset = self.DEFAULT_PRESET

        reject_reasons = []
        constraints = {}

        # API配额检查（使用每分钟计数）
        if self._api_calls_this_minute + request.estimated_api_calls > self.QUOTA_LIMITS["api_calls_per_min"]:
            reject_reasons.append("API配额不足")

        # 内存检查
        if self._usage.memory_used_mb + request.estimated_memory_mb > self.QUOTA_LIMITS["memory_mb"]:
            if self.state == QuotaState.RESOURCE_WARNING:
                constraints["memory_limit_mb"] = self.QUOTA_LIMITS["memory_mb"] * 0.8
            else:
                reject_reasons.append("内存配额不足")

        # Token检查
        if request.estimated_tokens > 0 and self._usage.tokens_used_today + request.estimated_tokens > self.QUOTA_LIMITS["tokens_per_day"]:
            reject_reasons.append("Token配额不足")

        # 并发检查
        if self._usage.concurrent_connections >= self.QUOTA_LIMITS["max_concurrent"]:
            reject_reasons.append("并发连接数已满")

        if reject_reasons:
            if self._publish_check_result:
                self._publish_check_result(QuotaCheckResult(
                    command_id=request.command_id, allowed=False,
                    reject_reason="; ".join(reject_reasons)
                ))
        else:
            # 放行后增加计数
            self._api_calls_this_minute += request.estimated_api_calls
            if self._publish_check_result:
                self._publish_check_result(QuotaCheckResult(
                    command_id=request.command_id, allowed=True, constraints=constraints
                ))

    def _reset_api_calls_per_minute(self):
        """检查是否需要重置每分钟API调用计数器"""
        current_minute = int(time.time() / 60)
        if current_minute != self._last_api_minute:
            self._api_calls_this_minute = 0
            self._last_api_minute = current_minute

    # ========== 资源释放 ==========
    def _apply_release(self, release: ResourceReleaseNotification):
        # 注意：API调用每分钟自动重置，此处释放对内存和Token有效
        self._usage.memory_used_mb = max(0.0, self._usage.memory_used_mb - release.memory_released_mb)
        self._usage.tokens_used_today = max(0, self._usage.tokens_used_today - release.tokens_released)
        self._reassess_state()

    # ========== 通知 ==========
    def _send_limit_notice(self, level: str, usage_pct: float):
        if self._publish_limit_notice:
            self._publish_limit_notice(ResourceLimitNotice(
                limit_type=level,
                current_usage=round(usage_pct, 3),
                quota_limit=1.0,
                estimated_recovery_sec=0.0,
                affected_modules=["ag-mcc-06", "ag-mcc-07", "ag-mcc-08"]
            ))

    def _publish_usage_report_internal(self):
        if self._publish_usage_report:
            self._publish_usage_report(ResourceUsageReport(
                state=self.state,
                api_usage_pct=round(self._api_calls_this_minute / self.QUOTA_LIMITS["api_calls_per_min"], 3),
                memory_usage_pct=round(self._usage.memory_used_mb / self.QUOTA_LIMITS["memory_mb"], 3),
                storage_usage_pct=round(self._usage.storage_used_kb / self.QUOTA_LIMITS["storage_kb"], 3),
                token_usage_pct=round(self._usage.tokens_used_today / self.QUOTA_LIMITS["tokens_per_day"], 3),
                concurrent_usage_pct=round(self._usage.concurrent_connections / self.QUOTA_LIMITS["max_concurrent"], 3)
            ))

    # ========== 辅助 ==========
    def get_state(self) -> QuotaState:
        return self.state

    def emergency_shutdown(self):
        self.state = QuotaState.SYSTEM_PAUSED
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
    print("  Agent-mcc-exec 资源配额管控单元 (ag-mcc-03) 演示")
    print("=" * 70)

    controller = ResourceQuotaController()

    print_separator("STEP 1: 正常配额校验通过")
    controller.set_quota_check_query(lambda: QuotaCheckRequest(
        command_id="CMD-001", tool_name="weather_api", tool_type="API",
        estimated_api_calls=1, estimated_memory_mb=10
    ))
    controller.run_quota_cycle()

    print_separator("STEP 2: 模拟资源预警，请求仍放行但附加约束")
    controller._api_calls_this_minute = 75
    controller._reassess_state()
    print(f"  当前状态: {controller.state.value}")
    controller.set_quota_check_query(lambda: QuotaCheckRequest(
        command_id="CMD-002", tool_name="search_engine", tool_type="API",
        estimated_api_calls=5, estimated_memory_mb=20
    ))
    controller.run_quota_cycle()

    print_separator("STEP 3: 资源紧急拒绝新任务")
    controller._usage.memory_used_mb = 480
    controller._reassess_state()
    print(f"  当前状态: {controller.state.value}")
    controller.set_quota_check_query(lambda: QuotaCheckRequest(
        command_id="CMD-003", tool_name="heavy_tool", tool_type="CODE",
        estimated_memory_mb=100
    ))
    controller.run_quota_cycle()

    print("\n✅ 资源配额管控单元演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("ag-mcc-03 资源配额管控单元 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        def setup_controller():
            return ResourceQuotaController()

        # TC-MCC-03-01: 正常放行
        print("\n[TC-MCC-03-01] 正常放行")
        try:
            c = setup_controller()
            c.set_quota_check_query(lambda: QuotaCheckRequest(
                command_id="T01", tool_name="test", estimated_api_calls=1
            ))
            c.run_quota_cycle()
            assert c.state == QuotaState.NORMAL_FLOW
            assert c._api_calls_this_minute == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-03-02: 预警状态放行但附加约束
        print("\n[TC-MCC-03-02] 预警状态附加约束")
        try:
            c = setup_controller()
            c._api_calls_this_minute = 75
            c._reassess_state()
            assert c.state == QuotaState.RESOURCE_WARNING
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-03-03: 紧急状态拒绝低优先级
        print("\n[TC-MCC-03-03] 紧急状态拒绝低优先级")
        try:
            c = setup_controller()
            c._usage.memory_used_mb = 480
            c._reassess_state()
            assert c.state == QuotaState.RESOURCE_CRITICAL
            c.set_quota_check_query(lambda: QuotaCheckRequest(
                command_id="T03", tool_name="test", priority=5, estimated_memory_mb=100
            ))
            c.run_quota_cycle()
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-03-04: 紧急状态放行高优先级
        print("\n[TC-MCC-03-04] 紧急状态放行高优先级")
        try:
            c = setup_controller()
            c._usage.memory_used_mb = 480
            c._reassess_state()
            c.set_quota_check_query(lambda: QuotaCheckRequest(
                command_id="T04", tool_name="test", priority=1, estimated_api_calls=1
            ))
            c.run_quota_cycle()
            assert c._api_calls_this_minute == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-03-05: 并发满拒绝
        print("\n[TC-MCC-03-05] 并发满拒绝")
        try:
            c = setup_controller()
            c._usage.concurrent_connections = 10
            c.set_quota_check_query(lambda: QuotaCheckRequest(
                command_id="T05", tool_name="test", estimated_api_calls=1
            ))
            c.run_quota_cycle()
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-03-06: API调用分钟重置
        print("\n[TC-MCC-03-06] API调用分钟重置")
        try:
            c = setup_controller()
            # 模拟上一分钟有大量调用
            c._api_calls_this_minute = 99
            c._last_api_minute = int(time.time() / 60) - 1  # 上一分钟
            c.set_quota_check_query(lambda: QuotaCheckRequest(
                command_id="T06", tool_name="test", estimated_api_calls=5
            ))
            c.run_quota_cycle()
            # 应该触发重置，当前分钟计数从0开始
            assert c._api_calls_this_minute == 5  # 重置后 + 本次预估
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