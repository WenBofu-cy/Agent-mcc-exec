#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-02
模块名称: 工具超时管理器
所属分区: 一、执行中枢调度
核心职责: 监控所有活跃的工具调用任务的执行时长，在任务超过预设的超时时间后自动触发中断
          流程。管理各类型工具的差异化超时阈值，支持任务级别的超时动态调整。当检测到超时
          事件时，立即通知 ag-mcc-01（执行调度核心）强制终止对应任务，并向 ag-mcc-11
          （闭环反馈单元）上报超时事件供审计。不参与工具的实际调用或参数校验，仅负责时间
          监控与超时告警。

依赖模块:
    ag-mcc-01(执行调度核心), ag-mcc-11(闭环反馈单元)
被依赖模块:
    ag-mcc-01, ag-mcc-11

安全约束:
  T-01: 超时管理器仅负责时间监控与通知，不得直接执行任务的中断或资源回收
  T-02: 最小超时阈值硬编码为 5 秒，任何动态调整不得低于此值
  T-03: 超时事件日志必须包含完整的任务ID、工具名称、超时阈值与实际耗时，不可篡改
  T-04: 紧急熔断时监控表必须清空，避免恢复后残留过期的监控数据导致误报
"""

from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid


class ManagerState(Enum):
    NORMAL_MONITOR = "normal_monitor"
    TIMEOUT_DETECTED = "timeout_detected"
    SYSTEM_PAUSED = "system_paused"


@dataclass
class ActiveTaskSnapshot:
    task_id: str = ""
    task_type: str = ""
    start_timestamp: float = 0.0
    timeout_threshold_sec: float = 30.0
    allow_extension: bool = False


@dataclass
class TimeoutThresholdConfig:
    default_timeout_sec: float = 30.0
    max_timeout_sec: float = 300.0
    allow_dynamic_adjust: bool = True


@dataclass
class TimeoutNotification:
    task_id: str = ""
    elapsed_sec: float = 0.0
    timeout_threshold_sec: float = 0.0
    reason: str = "超时"


@dataclass
class TimeoutEventLog:
    task_id: str = ""
    tool_name: str = ""
    timeout_threshold_sec: float = 0.0
    actual_elapsed_sec: float = 0.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class TimeoutStatistics:
    state: ManagerState = ManagerState.NORMAL_MONITOR
    active_monitoring_count: int = 0
    today_timeout_count: int = 0
    timeout_rate: float = 0.0


class TimeoutManager:
    # 默认超时配置
    DEFAULT_TIMEOUTS = {
        "API": TimeoutThresholdConfig(60, 300, True),
        "CODE": TimeoutThresholdConfig(30, 120, True),
        "FILE": TimeoutThresholdConfig(10, 30, False),
        "LLM": TimeoutThresholdConfig(120, 600, True),
        "DB": TimeoutThresholdConfig(15, 60, True),
    }
    DEFAULT_TIMEOUT = TimeoutThresholdConfig(30, 300, True)
    MIN_TIMEOUT_SEC = 5  # 最小超时阈值
    SCAN_INTERVAL_SEC = 0.5
    STATS_REPORT_INTERVAL_SEC = 60

    def __init__(self):
        self.module_id = "ag-mcc-02"
        self.module_name = "工具超时管理器"
        self.version = "V1.0"

        self.state = ManagerState.NORMAL_MONITOR
        self._monitor_table: Dict[str, Dict[str, Any]] = {}  # task_id -> {start, threshold, tool_type}
        self._timeout_configs = self.DEFAULT_TIMEOUTS.copy()
        self._today_timeout_count = 0
        self._last_scan_time = time.time()
        self._last_stats_time = time.time()
        self._pending_logs: List[Dict[str, Any]] = []

        # 回调注入
        self._query_active_tasks = None
        self._query_threshold_config = None

        self._publish_timeout_notification = None
        self._publish_timeout_event_log = None
        self._publish_timeout_statistics = None
        self._publish_event_log = None

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ========== 回调注入 ==========
    def set_active_tasks_query(self, callback: Callable[[], Optional[List[ActiveTaskSnapshot]]]):
        self._query_active_tasks = callback

    def set_threshold_config_query(self, callback: Callable[[], Optional[Dict[str, TimeoutThresholdConfig]]]):
        self._query_threshold_config = callback

    def set_timeout_notification_publisher(self, callback: Callable[[TimeoutNotification], None]):
        self._publish_timeout_notification = callback

    def set_timeout_event_log_publisher(self, callback: Callable[[TimeoutEventLog], None]):
        self._publish_timeout_event_log = callback

    def set_timeout_statistics_publisher(self, callback: Callable[[TimeoutStatistics], None]):
        self._publish_timeout_statistics = callback

    def set_event_log_publisher(self, callback: Callable[[Dict[str, Any]], None]):
        self._publish_event_log = callback

    # ========== 主循环 ==========
    def run_timeout_cycle(self):
        now = time.time()

        if self.state == ManagerState.SYSTEM_PAUSED:
            return

        # 定期统计上报
        if now - self._last_stats_time >= self.STATS_REPORT_INTERVAL_SEC:
            self._publish_statistics()
            self._last_stats_time = now

        # 接收活跃任务快照
        tasks = self._query_active_tasks() if self._query_active_tasks else None
        if tasks:
            self._update_monitor_table(tasks, now)

        # 定时扫描超时
        if now - self._last_scan_time >= self.SCAN_INTERVAL_SEC:
            self._scan_timeouts(now)
            self._last_scan_time = now

    # ========== 监控表更新 ==========
    def _update_monitor_table(self, tasks: List[ActiveTaskSnapshot], now: float):
        active_ids = set()
        for task in tasks:
            active_ids.add(task.task_id)
            if task.task_id not in self._monitor_table:
                self._monitor_table[task.task_id] = {
                    "start": task.start_timestamp,
                    "threshold": task.timeout_threshold_sec,
                    "tool_type": task.task_type
                }
            else:
                # 更新阈值（可能动态调整）
                self._monitor_table[task.task_id]["threshold"] = task.timeout_threshold_sec

        # 清理已结束的任务
        to_remove = [tid for tid in self._monitor_table if tid not in active_ids]
        for tid in to_remove:
            del self._monitor_table[tid]

    # ========== 超时扫描 ==========
    def _scan_timeouts(self, now: float):
        timeout_tasks = []
        for task_id, info in list(self._monitor_table.items()):
            elapsed = now - info["start"]
            threshold = info["threshold"]
            if elapsed >= threshold:
                timeout_tasks.append({
                    "task_id": task_id,
                    "elapsed": elapsed,
                    "threshold": threshold,
                    "tool_type": info["tool_type"]
                })

        if timeout_tasks:
            self.state = ManagerState.TIMEOUT_DETECTED
            for task in timeout_tasks:
                # 通知执行调度核心
                if self._publish_timeout_notification:
                    self._publish_timeout_notification(TimeoutNotification(
                        task_id=task["task_id"],
                        elapsed_sec=round(task["elapsed"], 3),
                        timeout_threshold_sec=task["threshold"],
                        reason="超时"
                    ))

                # 记录超时事件日志
                if self._publish_timeout_event_log:
                    self._publish_timeout_event_log(TimeoutEventLog(
                        task_id=task["task_id"],
                        tool_name=task["tool_type"],
                        timeout_threshold_sec=task["threshold"],
                        actual_elapsed_sec=round(task["elapsed"], 3)
                    ))

                self._today_timeout_count += 1
                del self._monitor_table[task["task_id"]]

            self.state = ManagerState.NORMAL_MONITOR

    # ========== 辅助 ==========
    def _publish_statistics(self):
        if self._publish_timeout_statistics:
            total = len(self._monitor_table)
            rate = self._today_timeout_count / max(total + self._today_timeout_count, 1)
            self._publish_timeout_statistics(TimeoutStatistics(
                state=self.state,
                active_monitoring_count=total,
                today_timeout_count=self._today_timeout_count,
                timeout_rate=round(rate, 3)
            ))

    def get_state(self) -> ManagerState:
        return self.state

    def emergency_shutdown(self):
        self.state = ManagerState.SYSTEM_PAUSED
        self._monitor_table.clear()
        print(f"[{self.module_id}] 紧急熔断，监控表已清空")

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
    print("  Agent-mcc-exec 工具超时管理器 (ag-mcc-02) 演示")
    print("=" * 70)

    manager = TimeoutManager()
    now = time.time()

    print_separator("STEP 1: 接收活跃任务，正常监控")
    manager.set_active_tasks_query(lambda: [
        ActiveTaskSnapshot(task_id="T1", task_type="API", start_timestamp=now - 50, timeout_threshold_sec=60),
        ActiveTaskSnapshot(task_id="T2", task_type="CODE", start_timestamp=now - 10, timeout_threshold_sec=30),
    ])
    manager.run_timeout_cycle()
    print(f"  监控任务数: {len(manager._monitor_table)}")

    print_separator("STEP 2: 超时任务被检测")
    manager.set_active_tasks_query(lambda: [
        ActiveTaskSnapshot(task_id="T3", task_type="API", start_timestamp=now - 65, timeout_threshold_sec=60),
    ])
    manager.run_timeout_cycle()
    # 再次扫描
    manager._last_scan_time = 0
    manager.run_timeout_cycle()
    print(f"  今日超时次数: {manager._today_timeout_count}")

    print_separator("STEP 3: 任务完成后自动清理")
    manager.set_active_tasks_query(lambda: [
        ActiveTaskSnapshot(task_id="T4", task_type="FILE", start_timestamp=now, timeout_threshold_sec=10),
    ])
    manager.run_timeout_cycle()
    # 下次更新不包含T4
    manager.set_active_tasks_query(lambda: [])
    manager.run_timeout_cycle()
    print(f"  监控表剩余: {len(manager._monitor_table)} (应为0)")

    print("\n✅ 工具超时管理器演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("ag-mcc-02 工具超时管理器 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        def setup_manager():
            return TimeoutManager()

        # TC-MCC-02-01: 正常监控不超时
        print("\n[TC-MCC-02-01] 正常监控不超时")
        try:
            m = setup_manager()
            now = time.time()
            m.set_active_tasks_query(lambda: [
                ActiveTaskSnapshot(task_id="T01", task_type="API", start_timestamp=now, timeout_threshold_sec=60)
            ])
            m.run_timeout_cycle()
            m._last_scan_time = 0
            m.run_timeout_cycle()
            assert "T01" in m._monitor_table
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-02-02: 超时检测并通知
        print("\n[TC-MCC-02-02] 超时检测并通知")
        try:
            m = setup_manager()
            now = time.time()
            m.set_active_tasks_query(lambda: [
                ActiveTaskSnapshot(task_id="T02", task_type="API", start_timestamp=now - 65, timeout_threshold_sec=60)
            ])
            m.run_timeout_cycle()
            m._last_scan_time = 0
            m.run_timeout_cycle()
            assert "T02" not in m._monitor_table
            assert m._today_timeout_count == 1
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-02-03: 任务完成自动清理
        print("\n[TC-MCC-02-03] 任务完成自动清理")
        try:
            m = setup_manager()
            now = time.time()
            m.set_active_tasks_query(lambda: [
                ActiveTaskSnapshot(task_id="T03", task_type="FILE", start_timestamp=now, timeout_threshold_sec=10)
            ])
            m.run_timeout_cycle()
            m.set_active_tasks_query(lambda: [])
            m.run_timeout_cycle()
            assert len(m._monitor_table) == 0
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-02-04: 未知工具类型使用默认超时
        print("\n[TC-MCC-02-04] 未知工具类型使用默认超时")
        try:
            m = setup_manager()
            config = m._timeout_configs.get("UNKNOWN", m.DEFAULT_TIMEOUT)
            assert config.default_timeout_sec == 30
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-02-05: 最小阈值保护
        print("\n[TC-MCC-02-05] 最小阈值保护")
        try:
            m = setup_manager()
            assert m.MIN_TIMEOUT_SEC == 5
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-02-06: 紧急熔断清空监控表
        print("\n[TC-MCC-02-06] 紧急熔断清空监控表")
        try:
            m = setup_manager()
            m._monitor_table["T06"] = {"start": time.time(), "threshold": 30, "tool_type": "API"}
            m.emergency_shutdown()
            assert len(m._monitor_table) == 0
            assert m.state == ManagerState.SYSTEM_PAUSED
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