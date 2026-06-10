#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-02
模块名称: 工具超时管理器
所属分区: 一、执行中枢调度
版本: V1.0
原创提出者: 文波福
开源协议: CC BY-NC 4.0

核心职责:
    监控所有活跃的工具调用任务的执行时长，在任务超过预设的超时时间后自动触发中断
    流程。管理各类型工具的差异化超时阈值，支持任务级别的超时动态调整。当检测到超时
    事件时，立即通知 ag-mcc-01（执行调度核心）强制终止对应任务，并向 ag-mcc-11
    （闭环反馈单元）上报超时事件供审计。不参与工具的实际调用或参数校验，仅负责时间
    监控与超时告警。

依赖模块:
    ag-mcc-01(执行调度核心), ag-mcc-11(闭环反馈单元), ag-mcc-04(工具注册中心)
被依赖模块:
    ag-mcc-01, ag-mcc-11

安全约束:
  T-01: 超时管理器仅负责时间监控与通知，不得直接执行任务的中断或资源回收
  T-02: 最小超时阈值硬编码为 5 秒，任何动态调整不得低于此值
  T-03: 超时事件日志必须包含完整的任务ID、工具名称、超时阈值与实际耗时，不可篡改
  T-04: 紧急熔断时监控表必须清空，避免恢复后残留过期的监控数据导致误报
"""

import time
import threading
from typing import Dict, List, Any
from dataclasses import dataclass, field
from enum import Enum


class ManagerState(Enum):
    NORMAL_MONITOR = "NORMAL_MONITOR"
    TIMEOUT_DETECTED = "TIMEOUT_DETECTED"
    SYSTEM_PAUSED = "SYSTEM_PAUSED"


@dataclass
class ActiveTaskSnapshot:
    instruction_id: str = ""
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
    instruction_id: str = ""
    elapsed_sec: float = 0.0
    timeout_threshold_sec: float = 0.0
    reason: str = "超时"


@dataclass
class TimeoutEventLog:
    instruction_id: str = ""
    tool_name: str = ""
    timeout_threshold_sec: float = 0.0
    actual_elapsed_sec: float = 0.0
    timestamp: float = field(default_factory=time.time)


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
    MIN_TIMEOUT_SEC = 5
    SCAN_INTERVAL_SEC = 0.5
    STATS_REPORT_INTERVAL_SEC = 60

    def __init__(self):
        self.module_id = "ag-mcc-02"
        self.module_name = "工具超时管理器"
        self.version = "V1.0"

        # 总线引用（由 agent_mcc_exec.py 注入）
        self.bus = None

        self.state = ManagerState.NORMAL_MONITOR
        self._lock = threading.Lock()
        self._monitor_table: Dict[str, Dict[str, Any]] = {}
        self._timeout_configs: Dict[str, TimeoutThresholdConfig] = self.DEFAULT_TIMEOUTS.copy()
        self._today_timeout_count = 0
        self._last_scan_time = time.time()
        self._last_stats_time = time.time()

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ====================== 主循环（SPEC 定义的标准方法名） ======================
    def timeout_manager_main_loop(self):
        """执行一个主循环周期"""
        if self.state == ManagerState.SYSTEM_PAUSED:
            return

        now = time.time()

        # 定期统计上报
        if now - self._last_stats_time >= self.STATS_REPORT_INTERVAL_SEC:
            self._publish_statistics()
            self._last_stats_time = now

        # 定时扫描超时
        if now - self._last_scan_time >= self.SCAN_INTERVAL_SEC:
            self._scan_timeouts(now)
            self._last_scan_time = now

    # ====================== 消息处理（InternalBus） ======================
    def handle_message(self, message):
        """处理来自 InternalBus 的消息"""
        if not self.bus:
            return

        data = message.data if message.data else {}
        topic = message.topic

        # 接收活跃任务快照（来自 ag-mcc-01）
        if topic == "ag-mcc-02.active_tasks_snapshot":
            tasks = []
            for t in data.get("tasks", []):
                tasks.append(ActiveTaskSnapshot(
                    instruction_id=t.get("instruction_id", ""),
                    task_type=t.get("task_type", ""),
                    start_timestamp=t.get("start_timestamp", 0),
                    timeout_threshold_sec=t.get("timeout_threshold_sec", 30),
                    allow_extension=t.get("allow_extension", False),
                ))
            self._update_monitor_table(tasks, time.time())

        # 接收单个任务注册（来自 ag-mcc-01 的分发回调）
        elif topic == "ag-mcc-02.register_task":
            instruction_id = data.get("instruction_id", "")
            if not instruction_id:
                return
            tool_type = data.get("tool_type", "")
            start_time = data.get("start_time", time.time())
            timeout_sec = data.get("timeout_sec", 30)
            with self._lock:
                self._monitor_table[instruction_id] = {
                    "start": start_time,
                    "threshold": timeout_sec,
                    "tool_type": tool_type
                }

        # 接收超时阈值配置更新（来自 ag-mcc-04）
        elif topic == "ag-mcc-02.threshold_config":
            with self._lock:
                for tool_type, cfg in data.get("configs", {}).items():
                    default_sec = max(cfg.get("default", 30), self.MIN_TIMEOUT_SEC)
                    self._timeout_configs[tool_type] = TimeoutThresholdConfig(
                        default_timeout_sec=default_sec,
                        max_timeout_sec=cfg.get("max", 300),
                        allow_dynamic_adjust=cfg.get("dynamic", True),
                    )

        # 接收全局调度指令（来自 ag-mcc-01）
        elif topic == "ag-mcc-02.global_command":
            command = data.get("command", "")
            if command == "emergency_shutdown":
                self.emergency_shutdown()

    # ========== 监控表更新 ==========
    def _update_monitor_table(self, tasks: List[ActiveTaskSnapshot], now: float):
        with self._lock:
            active_ids = set()
            for task in tasks:
                if not task.instruction_id:
                    continue
                active_ids.add(task.instruction_id)
                if task.instruction_id not in self._monitor_table:
                    self._monitor_table[task.instruction_id] = {
                        "start": task.start_timestamp,
                        "threshold": task.timeout_threshold_sec,
                        "tool_type": task.task_type
                    }
                else:
                    self._monitor_table[task.instruction_id]["threshold"] = task.timeout_threshold_sec

            # 清理已结束任务
            to_remove = [tid for tid in self._monitor_table if tid not in active_ids]
            for tid in to_remove:
                del self._monitor_table[tid]

    # ========== 超时扫描 ==========
    def _scan_timeouts(self, now: float):
        timeout_tasks = []

        # 锁内：扫描并收集超时任务，更新监控表与统计
        with self._lock:
            for instruction_id, info in list(self._monitor_table.items()):
                elapsed = now - info["start"]
                threshold = info["threshold"]
                if elapsed >= threshold:
                    timeout_tasks.append({
                        "instruction_id": instruction_id,
                        "elapsed": elapsed,
                        "threshold": threshold,
                        "tool_type": info["tool_type"]
                    })

            for task in timeout_tasks:
                del self._monitor_table[task["instruction_id"]]
            self._today_timeout_count += len(timeout_tasks)

        # 锁外：发送总线通知（不持有锁，避免死锁）
        if timeout_tasks:
            self.state = ManagerState.TIMEOUT_DETECTED
            for task in timeout_tasks:
                if self.bus:
                    self.bus.publish_to_module(
                        target_module="ag-mcc-01",
                        event_type="timeout_notification",
                        source_module="ag-mcc-02",
                        data={
                            "instruction_id": task["instruction_id"],
                            "elapsed_sec": round(task["elapsed"], 3),
                            "timeout_threshold_sec": task["threshold"],
                            "reason": "超时",
                        },
                    )

                    self.bus.publish_to_module(
                        target_module="ag-mcc-11",
                        event_type="timeout_event",
                        source_module="ag-mcc-02",
                        data={
                            "instruction_id": task["instruction_id"],
                            "tool_name": task["tool_type"],
                            "timeout_threshold_sec": task["threshold"],
                            "actual_elapsed_sec": round(task["elapsed"], 3),
                            "timestamp": now,
                        },
                    )
            self.state = ManagerState.NORMAL_MONITOR

    # ========== 状态上报 ==========
    def _publish_statistics(self):
        if not self.bus:
            return
        with self._lock:
            total = len(self._monitor_table)
            timeout_count = self._today_timeout_count

        rate = timeout_count / max(total + timeout_count, 1)
        self.bus.publish_to_module(
            target_module="ag-mcc-01",
            event_type="statistics",
            source_module="ag-mcc-02",
            data={
                "state": self.state.value,
                "active_monitoring_count": total,
                "today_timeout_count": timeout_count,
                "timeout_rate": round(rate, 3),
            },
        )

    def emergency_shutdown(self):
        self.state = ManagerState.SYSTEM_PAUSED
        with self._lock:
            self._monitor_table.clear()
        print(f"[{self.module_id}] 紧急熔断，监控表已清空")

    def shutdown(self):
        self.state = ManagerState.NORMAL_MONITOR
        print(f"[{self.module_id}] 已安全关闭")


# ====================== 演示与测试 ======================
def demo_main():
    print("=" * 60)
    print("  ag-mcc-02 工具超时管理器 V1.0 演示")
    print("=" * 60)

    from memory_bus import InternalBus
    bus = InternalBus()
    bus.register_module("ag-mcc-02")
    bus.register_module("ag-mcc-01")
    bus.register_module("ag-mcc-11")

    manager = TimeoutManager()
    manager.bus = bus
    bus.subscribe_to_module("ag-mcc-02", manager.handle_message)

    now = time.time()
    # 模拟任务注册
    bus.publish_to_module("ag-mcc-02", "register_task", "ag-mcc-01", {
        "instruction_id": "T1", "tool_type": "API",
        "start_time": now - 50, "timeout_sec": 60,
    })
    bus.publish_to_module("ag-mcc-02", "register_task", "ag-mcc-01", {
        "instruction_id": "T2", "tool_type": "CODE",
        "start_time": now - 10, "timeout_sec": 30,
    })
    bus.process_all()
    manager.timeout_manager_main_loop()
    print(f"  监控任务数: {len(manager._monitor_table)}")

    # 加入已超时任务
    bus.publish_to_module("ag-mcc-02", "register_task", "ag-mcc-01", {
        "instruction_id": "T3", "tool_type": "API",
        "start_time": now - 65, "timeout_sec": 60,
    })
    bus.process_all()
    manager._last_scan_time = 0
    manager.timeout_manager_main_loop()
    print(f"  今日超时次数: {manager._today_timeout_count}")

    # 阈值配置更新（含最小保护验证）
    bus.publish_to_module("ag-mcc-02", "threshold_config", "ag-mcc-04", {
        "configs": {"API": {"default": 3, "max": 300, "dynamic": True}}
    })
    bus.process_all()
    print(f"  更新后API超时阈值: {manager._timeout_configs['API'].default_timeout_sec} (应 ≥ {manager.MIN_TIMEOUT_SEC})")

    # 任务清理
    bus.publish_to_module("ag-mcc-02", "active_tasks_snapshot", "ag-mcc-01", {
        "tasks": [{"instruction_id": "T4", "task_type": "FILE", "start_timestamp": now, "timeout_threshold_sec": 10}]
    })
    bus.process_all()
    manager.timeout_manager_main_loop()
    bus.publish_to_module("ag-mcc-02", "active_tasks_snapshot", "ag-mcc-01", {"tasks": []})
    bus.process_all()
    manager.timeout_manager_main_loop()
    print(f"  监控表剩余: {len(manager._monitor_table)} (应为0)")

    # 紧急熔断
    bus.publish_to_module("ag-mcc-02", "global_command", "ag-mcc-01", {"command": "emergency_shutdown"})
    bus.process_all()
    print(f"  熔断后监控表: {len(manager._monitor_table)}")

    print("\n✅ 工具超时管理器演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("ag-mcc-02 工具超时管理器 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        def setup():
            from memory_bus import InternalBus
            bus = InternalBus()
            bus.register_module("ag-mcc-02")
            bus.register_module("ag-mcc-01")
            bus.register_module("ag-mcc-11")
            m = TimeoutManager()
            m.bus = bus
            bus.subscribe_to_module("ag-mcc-02", m.handle_message)
            return m, bus

        # TC-01: 正常注册不超时
        print("\n[TC-01] 正常注册不超时")
        try:
            m, bus = setup()
            now = time.time()
            bus.publish_to_module("ag-mcc-02", "register_task", "ag-mcc-01", {
                "instruction_id": "T01", "tool_type": "API", "start_time": now, "timeout_sec": 60
            })
            bus.process_all()
            m.timeout_manager_main_loop()
            assert "T01" in m._monitor_table
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC-02: 超时检测
        print("\n[TC-02] 超时检测并通知")
        try:
            m, bus = setup()
            now = time.time()
            bus.publish_to_module("ag-mcc-02", "register_task", "ag-mcc-01", {
                "instruction_id": "T02", "tool_type": "API", "start_time": now - 65, "timeout_sec": 60
            })
            bus.process_all()
            m._last_scan_time = 0
            m.timeout_manager_main_loop()
            assert "T02" not in m._monitor_table
            assert m._today_timeout_count == 1
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC-03: 任务清理
        print("\n[TC-03] 任务完成自动清理")
        try:
            m, bus = setup()
            now = time.time()
            bus.publish_to_module("ag-mcc-02", "active_tasks_snapshot", "ag-mcc-01", {
                "tasks": [{"instruction_id": "T03", "task_type": "FILE", "start_timestamp": now, "timeout_threshold_sec": 10}]
            })
            bus.process_all()
            m.timeout_manager_main_loop()
            bus.publish_to_module("ag-mcc-02", "active_tasks_snapshot", "ag-mcc-01", {"tasks": []})
            bus.process_all()
            m.timeout_manager_main_loop()
            assert len(m._monitor_table) == 0
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC-04: 熔断清空
        print("\n[TC-04] 紧急熔断清空监控表")
        try:
            m, bus = setup()
            m._monitor_table["T04"] = {"start": time.time(), "threshold": 30, "tool_type": "API"}
            bus.publish_to_module("ag-mcc-02", "global_command", "ag-mcc-01", {"command": "emergency_shutdown"})
            bus.process_all()
            assert len(m._monitor_table) == 0
            assert m.state == ManagerState.SYSTEM_PAUSED
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC-05: 最小阈值保护
        print("\n[TC-05] 最小阈值保护")
        try:
            m, _ = setup()
            assert m.MIN_TIMEOUT_SEC == 5
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC-06: 阈值更新受最小保护
        print("\n[TC-06] 阈值更新受最小保护")
        try:
            m, bus = setup()
            bus.publish_to_module("ag-mcc-02", "threshold_config", "ag-mcc-04", {
                "configs": {"API": {"default": 2, "max": 300, "dynamic": True}}
            })
            bus.process_all()
            assert m._timeout_configs["API"].default_timeout_sec == 5  # 被保护为5，不是2
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        print("\n" + "=" * 60)
        print(f"测试结果: {passed} PASS, {failed} FAIL")
        print("=" * 60)
    else:
        demo_main()