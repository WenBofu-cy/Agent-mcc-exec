#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-03
模块名称: 资源配额管控单元
所属分区: 一、执行中枢调度
版本: V1.0
原创提出者: 文波福
开源协议: CC BY-NC 4.0

核心职责:
    监控并管控行动执行层各执行模块的资源消耗，包括 API 调用频次、代码执行内存上限、
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

import time
import threading
from typing import Dict, List, Any
from dataclasses import dataclass, field
from enum import Enum


class QuotaState(Enum):
    NORMAL_FLOW = "NORMAL_FLOW"
    RESOURCE_WARNING = "RESOURCE_WARNING"
    RESOURCE_CRITICAL = "RESOURCE_CRITICAL"
    SYSTEM_PAUSED = "SYSTEM_PAUSED"


@dataclass
class QuotaCheckRequest:
    instruction_id: str = ""
    tool_name: str = ""
    tool_type: str = ""
    estimated_api_calls: int = 1
    estimated_memory_mb: float = 10.0
    estimated_storage_kb: float = 0.0
    estimated_tokens: int = 0
    priority: str = "NORMAL"  # HIGH/NORMAL/LOW


@dataclass
class ToolResourcePreset:
    tool_name: str = ""
    max_api_calls: int = 1
    max_memory_mb: float = 64.0
    max_storage_kb: float = 1024.0
    max_tokens: int = 1000


@dataclass
class ResourceUsageSnapshot:
    api_calls_this_minute: int = 0
    memory_used_mb: float = 0.0
    storage_used_kb: float = 0.0
    tokens_used_today: int = 0
    concurrent_connections: int = 0


@dataclass
class ResourceReleaseNotification:
    instruction_id: str = ""
    api_calls_released: int = 0
    memory_released_mb: float = 0.0
    storage_released_kb: float = 0.0
    tokens_released: int = 0


@dataclass
class QuotaCheckResult:
    instruction_id: str = ""
    allowed: bool = True
    reject_reason: str = ""
    constraints: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResourceLimitNotice:
    limit_type: str = ""
    current_usage_pct: float = 0.0
    affected_modules: List[str] = field(default_factory=list)


@dataclass
class ResourceUsageReport:
    state: str = "NORMAL_FLOW"
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
    WARN_THRESHOLD = 0.70
    CRITICAL_THRESHOLD = 0.90
    DEFAULT_PRESET = ToolResourcePreset()
    STATUS_REPORT_INTERVAL_SEC = 30

    def __init__(self):
        self.module_id = "ag-mcc-03"
        self.module_name = "资源配额管控单元"
        self.version = "V1.0"

        # 总线引用（由主入口注入）
        self.bus = None                 # InternalBus

        self._lock = threading.Lock()
        with self._lock:
            self.state = QuotaState.NORMAL_FLOW
            self._usage = ResourceUsageSnapshot()
            self._tool_presets: Dict[str, ToolResourcePreset] = {}
            self._last_status_time = time.time()
            self._api_calls_this_minute = 0
            self._last_api_minute = -1

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ====================== 主循环（SPEC 定义的标准方法名） ======================
    def quota_controller_main_loop(self):
        """执行一个主循环周期"""
        now = time.time()

        with self._lock:
            if self.state == QuotaState.SYSTEM_PAUSED:
                return

        # 定期状态上报
        if now - self._last_status_time >= self.STATUS_REPORT_INTERVAL_SEC:
            self._publish_usage_report()
            self._last_status_time = now

        # 每分钟重置API调用计数
        self._reset_api_calls_per_minute()

    # ====================== 消息处理（InternalBus） ======================
    def handle_message(self, message):
        """处理来自 InternalBus 的消息"""
        if not self.bus:
            return

        data = message.data if message.data else {}
        topic = message.topic

        # 接收配额校验请求（来自 ag-mcc-01）
        if topic == "ag-mcc-03.quota_check":
            instruction_id = data.get("instruction_id", "")
            if not instruction_id:
                return  # 过滤无效请求
            
            request = QuotaCheckRequest(
                instruction_id=instruction_id,
                tool_name=data.get("tool_name", ""),
                tool_type=data.get("tool_type", ""),
                estimated_api_calls=data.get("estimated_api_calls", 1),
                estimated_memory_mb=data.get("estimated_memory_mb", 10.0),
                estimated_storage_kb=data.get("estimated_storage_kb", 0.0),
                estimated_tokens=data.get("estimated_tokens", 0),
                priority=data.get("priority", "NORMAL"),
            )
            self._handle_quota_check(request)

        # 接收资源释放通知（来自 ag-mcc-06/07/08 或 ag-mcc-01）
        elif topic == "ag-mcc-03.resource_release":
            release = ResourceReleaseNotification(
                instruction_id=data.get("instruction_id", ""),
                api_calls_released=data.get("api_calls_released", 0),
                memory_released_mb=data.get("memory_released_mb", 0.0),
                storage_released_kb=data.get("storage_released_kb", 0.0),
                tokens_released=data.get("tokens_released", 0),
            )
            self._apply_release(release)

        # 接收工具配额预设更新（来自 ag-mcc-04）
        elif topic == "ag-mcc-03.tool_preset_update":
            tool_name = data.get("tool_name", "")
            if tool_name:
                with self._lock:
                    self._tool_presets[tool_name] = ToolResourcePreset(
                        tool_name=tool_name,
                        max_api_calls=data.get("max_api_calls", 1),
                        max_memory_mb=data.get("max_memory_mb", 64.0),
                        max_storage_kb=data.get("max_storage_kb", 1024.0),
                        max_tokens=data.get("max_tokens", 1000),
                    )

        # 接收资源使用快照更新（来自系统监控）
        elif topic == "ag-mcc-03.resource_snapshot":
            with self._lock:
                self._usage.memory_used_mb = data.get("memory_used_mb", 0.0)
                self._usage.storage_used_kb = data.get("storage_used_kb", 0.0)
                self._usage.tokens_used_today = data.get("tokens_used_today", 0)
                self._usage.concurrent_connections = data.get("concurrent_connections", 0)
            self._reassess_state()

        # 接收全局调度指令（来自 ag-mcc-01）
        elif topic == "ag-mcc-03.global_command":
            command = data.get("command", "")
            if command == "emergency_shutdown":
                self.emergency_shutdown()

    # ====================== 配额校验核心逻辑 ======================
    def _handle_quota_check(self, request: QuotaCheckRequest):
        self._reset_api_calls_per_minute()

        # 紧急状态仅放行高优先级
        with self._lock:
            if self.state == QuotaState.RESOURCE_CRITICAL and request.priority != "HIGH":
                self._send_check_result(request.instruction_id, False,
                                        "资源紧急，仅允许高优先级任务")
                return

        # 获取工具预设
        with self._lock:
            preset = self._tool_presets.get(request.tool_name, self.DEFAULT_PRESET)

        reject_reasons = []
        constraints = {}

        with self._lock:
            # 1. 工具级配额检查
            if request.estimated_api_calls > preset.max_api_calls:
                reject_reasons.append(f"工具{request.tool_name}单次API调用超限(最大{preset.max_api_calls})")
            
            if request.estimated_memory_mb > preset.max_memory_mb:
                reject_reasons.append(f"工具{request.tool_name}内存使用超限(最大{preset.max_memory_mb}MB)")
            
            if request.estimated_storage_kb > preset.max_storage_kb:
                reject_reasons.append(f"工具{request.tool_name}存储使用超限(最大{preset.max_storage_kb}KB)")
            
            if request.estimated_tokens > preset.max_tokens:
                reject_reasons.append(f"工具{request.tool_name}Token使用超限(最大{preset.max_tokens})")

            # 2. 全局配额检查
            if self._api_calls_this_minute + request.estimated_api_calls > self.QUOTA_LIMITS["api_calls_per_min"]:
                reject_reasons.append("全局API配额不足")

            # 内存预警约束：超过70%时限制最大可用内存为80%
            memory_available = self.QUOTA_LIMITS["memory_mb"] - self._usage.memory_used_mb
            if self.state == QuotaState.RESOURCE_WARNING:
                allowed_memory = self.QUOTA_LIMITS["memory_mb"] * 0.8 - self._usage.memory_used_mb
                if request.estimated_memory_mb > allowed_memory:
                    reject_reasons.append(f"内存预警，单任务最大可用{allowed_memory:.1f}MB")
                else:
                    constraints["memory_limit_mb"] = allowed_memory
            elif memory_available < request.estimated_memory_mb:
                reject_reasons.append("全局内存配额不足")

            if self._usage.storage_used_kb + request.estimated_storage_kb > self.QUOTA_LIMITS["storage_kb"]:
                reject_reasons.append("全局存储配额不足")

            if request.estimated_tokens > 0 and self._usage.tokens_used_today + request.estimated_tokens > self.QUOTA_LIMITS["tokens_per_day"]:
                reject_reasons.append("全局Token配额不足")

            if self._usage.concurrent_connections >= self.QUOTA_LIMITS["max_concurrent"]:
                reject_reasons.append("并发连接数已满")

        if reject_reasons:
            self._send_check_result(request.instruction_id, False, "; ".join(reject_reasons))
        else:
            # 放行并原子化预扣所有资源
            with self._lock:
                self._api_calls_this_minute += request.estimated_api_calls
                self._usage.memory_used_mb += request.estimated_memory_mb
                self._usage.storage_used_kb += request.estimated_storage_kb
                self._usage.tokens_used_today += request.estimated_tokens
                self._usage.concurrent_connections += 1
            
            self._send_check_result(request.instruction_id, True, "", constraints)
            self._reassess_state()

    def _send_check_result(self, instruction_id: str, allowed: bool,
                           reason: str = "", constraints: Dict[str, Any] = None):
        if not self.bus:
            return
        if constraints is None:
            constraints = {}
        self.bus.publish_to_module(
            target_module="ag-mcc-01",
            event_type="quota_check_result",
            source_module=self.module_id,
            data={
                "instruction_id": instruction_id,
                "allowed": allowed,
                "reject_reason": reason,
                "constraints": constraints,
            }
        )

    # ====================== 资源释放 ======================
    def _apply_release(self, release: ResourceReleaseNotification):
        with self._lock:
            self._usage.memory_used_mb = max(0.0, self._usage.memory_used_mb - release.memory_released_mb)
            self._usage.storage_used_kb = max(0.0, self._usage.storage_used_kb - release.storage_released_kb)
            self._usage.tokens_used_today = max(0, self._usage.tokens_used_today - release.tokens_released)
            self._usage.concurrent_connections = max(0, self._usage.concurrent_connections - 1)
        self._reassess_state()

    # ====================== 状态评估与通知 ======================
    def _reassess_state(self):
        with self._lock:
            api_pct = self._api_calls_this_minute / self.QUOTA_LIMITS["api_calls_per_min"]
            mem_pct = self._usage.memory_used_mb / self.QUOTA_LIMITS["memory_mb"]
            storage_pct = self._usage.storage_used_kb / self.QUOTA_LIMITS["storage_kb"]
            tok_pct = self._usage.tokens_used_today / self.QUOTA_LIMITS["tokens_per_day"]
            conc_pct = self._usage.concurrent_connections / self.QUOTA_LIMITS["max_concurrent"]

            max_pct = max(api_pct, mem_pct, storage_pct, tok_pct, conc_pct)
            old_state = self.state

            if max_pct >= self.CRITICAL_THRESHOLD:
                new_state = QuotaState.RESOURCE_CRITICAL
            elif max_pct >= self.WARN_THRESHOLD:
                new_state = QuotaState.RESOURCE_WARNING
            else:
                new_state = QuotaState.NORMAL_FLOW

            self.state = new_state

        # 状态变化时发送通知和日志
        if new_state != old_state:
            self._send_limit_notice(
                "紧急" if new_state == QuotaState.RESOURCE_CRITICAL else "预警",
                max_pct
            )
            # 上报状态转换日志
            if self.bus:
                self.bus.publish_to_module(
                    target_module="ag-mcc-12",
                    event_type="state_change",
                    source_module=self.module_id,
                    data={
                        "old_state": old_state.value,
                        "new_state": new_state.value,
                        "max_usage_pct": round(max_pct, 3),
                        "timestamp": time.time()
                    }
                )

    def _send_limit_notice(self, level: str, usage_pct: float):
        if not self.bus:
            return
        self.bus.publish(
            topic="ag-mcc-03.limit_notice",
            source_module=self.module_id,
            data={
                "limit_type": level,
                "current_usage_pct": round(usage_pct, 3),
                "affected_modules": ["ag-mcc-06", "ag-mcc-07", "ag-mcc-08"]
            }
        )

    # ====================== 状态上报 ======================
    def _publish_usage_report(self):
        if not self.bus:
            return
        with self._lock:
            report = ResourceUsageReport(
                state=self.state.value,
                api_usage_pct=round(self._api_calls_this_minute / self.QUOTA_LIMITS["api_calls_per_min"], 3),
                memory_usage_pct=round(self._usage.memory_used_mb / self.QUOTA_LIMITS["memory_mb"], 3),
                storage_usage_pct=round(self._usage.storage_used_kb / self.QUOTA_LIMITS["storage_kb"], 3),
                token_usage_pct=round(self._usage.tokens_used_today / self.QUOTA_LIMITS["tokens_per_day"], 3),
                concurrent_usage_pct=round(self._usage.concurrent_connections / self.QUOTA_LIMITS["max_concurrent"], 3)
            )

        # 发送至日志模块
        self.bus.publish_to_module(
            target_module="ag-mcc-12",
            event_type="resource_usage_report",
            source_module=self.module_id,
            data={
                "state": report.state,
                "api_usage_pct": report.api_usage_pct,
                "memory_usage_pct": report.memory_usage_pct,
                "storage_usage_pct": report.storage_usage_pct,
                "token_usage_pct": report.token_usage_pct,
                "concurrent_usage_pct": report.concurrent_usage_pct,
            }
        )

    # ====================== 辅助方法 ======================
    def _reset_api_calls_per_minute(self):
        current_minute = int(time.time() / 60)
        with self._lock:
            if current_minute != self._last_api_minute:
                self._api_calls_this_minute = 0
                self._last_api_minute = current_minute

    def get_state(self) -> QuotaState:
        with self._lock:
            return self.state

    def emergency_shutdown(self):
        with self._lock:
            self.state = QuotaState.SYSTEM_PAUSED
            self._api_calls_this_minute = 0
            self._usage = ResourceUsageSnapshot()
        print(f"[{self.module_id}] 紧急熔断，资源计数器已清零")

    def shutdown(self):
        with self._lock:
            self.state = QuotaState.NORMAL_FLOW
        print(f"[{self.module_id}] 已安全关闭")


# ====================== 演示与测试 ======================
def demo_main():
    print("=" * 70)
    print("  ag-mcc-03 资源配额管控单元 V1.0 演示")
    print("=" * 70)

    from memory_bus import InternalBus
    bus = InternalBus()
    bus.register_module("ag-mcc-03")
    bus.register_module("ag-mcc-01")
    bus.register_module("ag-mcc-04")
    bus.register_module("ag-mcc-12")

    controller = ResourceQuotaController()
    controller.bus = bus
    bus.subscribe_to_module("ag-mcc-03", controller.handle_message)

    # 模拟配额检查请求
    print("\n[演示] 收到正常配额检查请求 (CMD-001)")
    bus.publish_to_module("ag-mcc-03", "quota_check", "ag-mcc-01", {
        "instruction_id": "CMD-001",
        "tool_name": "weather_api",
        "tool_type": "API",
        "estimated_api_calls": 1,
        "estimated_memory_mb": 10
    })
    bus.process_all()
    controller.quota_controller_main_loop()

    # 模拟资源即将告警
    print("\n[演示] 设置 API 使用率到 75%，触发预警")
    controller._api_calls_this_minute = 75
    controller._last_api_minute = int(time.time() / 60)
    # 模拟快照更新
    bus.publish_to_module("ag-mcc-03", "resource_snapshot", "ag-mcc-00", {
        "memory_used_mb": 100
    })
    bus.process_all()
    controller.quota_controller_main_loop()
    print(f"  当前状态: {controller.get_state().value}")

    # 模拟资源紧急拒绝
    print("\n[演示] 内存使用 490MB (95%), 请求内存 100MB -> 被拒绝")
    bus.publish_to_module("ag-mcc-03", "resource_snapshot", "ag-mcc-00", {
        "memory_used_mb": 490
    })
    bus.process_all()
    controller.quota_controller_main_loop()
    bus.publish_to_module("ag-mcc-03", "quota_check", "ag-mcc-01", {
        "instruction_id": "CMD-002",
        "tool_name": "heavy_tool",
        "tool_type": "CODE",
        "estimated_memory_mb": 100,
        "priority": "NORMAL"
    })
    bus.process_all()
    controller.quota_controller_main_loop()

    print("\n✅ 演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("ag-mcc-03 资源配额管控单元 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        def setup():
            from memory_bus import InternalBus
            bus = InternalBus()
            bus.register_module("ag-mcc-03")
            bus.register_module("ag-mcc-01")
            bus.register_module("ag-mcc-04")
            bus.register_module("ag-mcc-12")
            c = ResourceQuotaController()
            c.bus = bus
            bus.subscribe_to_module("ag-mcc-03", c.handle_message)
            return c, bus

        # TC01: 正常放行
        print("\n[TC01] 正常放行")
        try:
            c, bus = setup()
            bus.publish_to_module("ag-mcc-03", "quota_check", "ag-mcc-01", {
                "instruction_id": "T01", "tool_name": "test", "estimated_api_calls": 1
            })
            bus.process_all()
            c.quota_controller_main_loop()
            assert c._api_calls_this_minute == 1
            assert c._usage.concurrent_connections == 1
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC02: 预警状态放行并附加约束
        print("\n[TC02] 预警状态放行并附加约束")
        try:
            c, bus = setup()
            c._api_calls_this_minute = 75
            c._last_api_minute = int(time.time() / 60)
            c._reassess_state()
            assert c.get_state() == QuotaState.RESOURCE_WARNING
            # 内存接近上限，预警状态允许放行，附加约束
            c._usage.memory_used_mb = 360  # 70.3%
            bus.publish_to_module("ag-mcc-03", "quota_check", "ag-mcc-01", {
                "instruction_id": "T02", "tool_name": "test", "estimated_memory_mb": 10
            })
            bus.process_all()
            c.quota_controller_main_loop()
            assert c._usage.memory_used_mb == 370
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC03: 紧急拒绝低优先级
        print("\n[TC03] 紧急状态拒绝低优先级")
        try:
            c, bus = setup()
            c._usage.memory_used_mb = 480
            c._reassess_state()
            assert c.get_state() == QuotaState.RESOURCE_CRITICAL
            # 发送低优先级请求
            bus.publish_to_module("ag-mcc-03", "quota_check", "ag-mcc-01", {
                "instruction_id": "T03", "tool_name": "test", "priority": "NORMAL",
                "estimated_memory_mb": 100
            })
            bus.process_all()
            c.quota_controller_main_loop()
            # 此时应拒绝，可通过检查api计数未增来验证
            assert c._api_calls_this_minute == 0
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC04: 紧急放行高优先级
        print("\n[TC04] 紧急状态放行高优先级")
        try:
            c, bus = setup()
            c._usage.memory_used_mb = 480
            c._reassess_state()
            bus.publish_to_module("ag-mcc-03", "quota_check", "ag-mcc-01", {
                "instruction_id": "T04", "tool_name": "test", "priority": "HIGH",
                "estimated_api_calls": 1
            })
            bus.process_all()
            c.quota_controller_main_loop()
            assert c._api_calls_this_minute == 1
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC05: 并发满拒绝
        print("\n[TC05] 并发满拒绝")
        try:
            c, bus = setup()
            c._usage.concurrent_connections = 10
            bus.publish_to_module("ag-mcc-03", "quota_check", "ag-mcc-01", {
                "instruction_id": "T05", "tool_name": "test", "estimated_api_calls": 1
            })
            bus.process_all()
            c.quota_controller_main_loop()
            assert c._api_calls_this_minute == 0  # 被拒绝，未增加
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC06: API分钟重置
        print("\n[TC06] API分钟重置")
        try:
            c, bus = setup()
            # 模拟上一分钟大量调用
            c._api_calls_this_minute = 99
            c._last_api_minute = int(time.time() / 60) - 1
            bus.publish_to_module("ag-mcc-03", "quota_check", "ag-mcc-01", {
                "instruction_id": "T06", "tool_name": "test", "estimated_api_calls": 5
            })
            bus.process_all()
            c.quota_controller_main_loop()
            assert c._api_calls_this_minute == 5  # 重置后加5
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC07: 工具级配额限制
        print("\n[TC07] 工具级配额限制")
        try:
            c, bus = setup()
            # 更新工具预设：单次最大内存10MB
            bus.publish_to_module("ag-mcc-03", "tool_preset_update", "ag-mcc-04", {
                "tool_name": "heavy_tool",
                "max_memory_mb": 10
            })
            bus.process_all()
            # 请求20MB内存，应被拒绝
            bus.publish_to_module("ag-mcc-03", "quota_check", "ag-mcc-01", {
                "instruction_id": "T07", "tool_name": "heavy_tool", "estimated_memory_mb": 20
            })
            bus.process_all()
            c.quota_controller_main_loop()
            assert c._usage.memory_used_mb == 0  # 被拒绝
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC08: 资源释放
        print("\n[TC08] 资源释放")
        try:
            c, bus = setup()
            # 先申请资源
            bus.publish_to_module("ag-mcc-03", "quota_check", "ag-mcc-01", {
                "instruction_id": "T08", "tool_name": "test",
                "estimated_memory_mb": 50, "estimated_storage_kb": 100, "estimated_tokens": 100
            })
            bus.process_all()
            c.quota_controller_main_loop()
            assert c._usage.memory_used_mb == 50
            assert c._usage.storage_used_kb == 100
            assert c._usage.tokens_used_today == 100
            assert c._usage.concurrent_connections == 1
            
            # 释放资源
            bus.publish_to_module("ag-mcc-03", "resource_release", "ag-mcc-06", {
                "instruction_id": "T08",
                "memory_released_mb": 50,
                "storage_released_kb": 100,
                "tokens_released": 100
            })
            bus.process_all()
            c.quota_controller_main_loop()
            assert c._usage.memory_used_mb == 0
            assert c._usage.storage_used_kb == 0
            assert c._usage.tokens_used_today == 0
            assert c._usage.concurrent_connections == 0
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        print("\n" + "=" * 60)
        print(f"测试结果: {passed} PASS, {failed} FAIL")
        print("=" * 60)
    else:
        demo_main()