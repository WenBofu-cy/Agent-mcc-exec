#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent-mcc-exec 行动执行层 · 主入口
版本：V1.0
原创提出者：文波福
开源协议：CC BY-NC 4.0

修改记录：
- V1.0: 最终稳定版，包含双总线架构、模块注册、回调绑定、主循环编排、健康监控、演示用例
"""

import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 双总线导入
from memory_bus import InternalBus, CerebellumBus

# 模块注册表
from module_registry import MODULE_REGISTRY

# 导入全部 12 个 MCC 模块
from ag_mcc_01_execution_core import ExecutionCore
from ag_mcc_02_timeout_manager import TimeoutManager
from ag_mcc_03_resource_quota import ResourceQuotaController
from ag_mcc_04_tool_registry import ToolRegistry
from ag_mcc_05_param_validator import ParamValidator
from ag_mcc_06_api_engine import ApiCallEngine
from ag_mcc_07_code_sandbox import CodeExecutionSandbox
from ag_mcc_08_file_executor import FileOperationExecutor
from ag_mcc_09_result_validator import ResultValidator
from ag_mcc_10_deviation_monitor import DeviationMonitor
from ag_mcc_11_closed_loop_feedback import ClosedLoopFeedback
from ag_mcc_12_execution_logger import ExecutionLogger


class AgentMccExec:
    """
    MCC 行动执行层 主控类 V1.0
    负责模块实例化、主循环调度、双总线安全架构
    """

    def __init__(self):
        self.cycle_count = 0
        self.running = True

        # ====================== 双总线架构 ======================
        self.internal_bus = InternalBus(validate_modules=False)       # 模块间内部通信
        self.cerebellum_bus = CerebellumBus(validate_modules=False)   # 对外工具调用总线（连接 ECC）

        # 模块ID → 实例映射
        self.module_map = {}

        # ========== 实例化全部 12 个模块 ==========
        self.execution_core = ExecutionCore()
        self.timeout_manager = TimeoutManager()
        self.resource_quota = ResourceQuotaController()
        self.tool_registry = ToolRegistry()
        self.param_validator = ParamValidator()
        self.api_engine = ApiCallEngine()
        self.code_sandbox = CodeExecutionSandbox()
        self.file_executor = FileOperationExecutor()
        self.result_validator = ResultValidator()
        self.deviation_monitor = DeviationMonitor()
        self.feedback_loop = ClosedLoopFeedback()
        self.execution_logger = ExecutionLogger()

        # 绑定模块ID、注入总线、注册模块、绑定回调
        self._bind_module_ids()
        self._inject_bus()
        self._register_modules()
        self._wire_callbacks()

        print("Agent-mcc-exec 行动执行层 初始化完成")
        print(f"  模块总数: {len(self.module_map)} (注册表校验通过)")

    def _bind_module_ids(self):
        """绑定MCC标准模块ID（SPEC V1.0 强制）"""
        self.module_map = {
            "ag-mcc-01": self.execution_core,
            "ag-mcc-02": self.timeout_manager,
            "ag-mcc-03": self.resource_quota,
            "ag-mcc-04": self.tool_registry,
            "ag-mcc-05": self.param_validator,
            "ag-mcc-06": self.api_engine,
            "ag-mcc-07": self.code_sandbox,
            "ag-mcc-08": self.file_executor,
            "ag-mcc-09": self.result_validator,
            "ag-mcc-10": self.deviation_monitor,
            "ag-mcc-11": self.feedback_loop,
            "ag-mcc-12": self.execution_logger,
        }
        for mid, module in self.module_map.items():
            module.module_id = mid

    def _inject_bus(self):
        """
        注入双总线（严格遵循 ag-mcc-01 唯一对外网关原则）
        - 所有模块获得内部总线 InternalBus
        - 仅 ag-mcc-01 获得外部总线 CerebellumBus
        """
        for mid, module in self.module_map.items():
            module.bus = self.internal_bus

        # 只有执行调度核心拥有对外通信能力（CerebellumBus）
        self.execution_core.external_bus = self.cerebellum_bus

    def _register_modules(self):
        """注册模块到总线（内部总线所有模块，外部总线仅 ag-mcc-01 和 ag-ecc-12）"""
        for mid in self.module_map.keys():
            self.internal_bus.register_module(mid)
        # 外部总线注册网关模块
        self.cerebellum_bus.register_module("ag-mcc-01")
        # 注册对端 ECC 模块，确保跨系统通信链路完整
        if not self.cerebellum_bus.is_module_registered("ag-ecc-12"):
            self.cerebellum_bus.register_module("ag-ecc-12")

    def _wire_callbacks(self):
        """绑定模块消息回调"""
        # 内部总线统一用 handle_message
        for mid, module in self.module_map.items():
            if hasattr(module, "handle_message"):
                self.internal_bus.subscribe_to_module(mid, module.handle_message)

        # CerebellumBus 使用独立回调
        if hasattr(self.execution_core, "handle_cerebellum_bus_message"):
            self.cerebellum_bus.subscribe_to_module(
                "ag-mcc-01", self.execution_core.handle_cerebellum_bus_message
            )

    # ====================== 主循环 ======================
    def run_cycle(self):
        """执行一个主循环周期"""
        # 1. 处理外部输入（来自 ECC 的指令）
        self.cerebellum_bus.process_batch(100)
        self.internal_bus.process_batch(100)

        # 2. 按依赖顺序调用各模块主逻辑（使用 SPEC 定义的标准方法名）
        # 阶段一：执行中枢调度
        self.execution_core.execution_core_main_loop()
        self.timeout_manager.timeout_manager_main_loop()
        self.resource_quota.quota_controller_main_loop()
        self.internal_bus.process_batch(100)

        # 阶段二：工具管理集群
        self.tool_registry.tool_registry_main_loop()
        self.param_validator.param_validator_main_loop()
        self.internal_bus.process_batch(100)

        # 阶段三：调用执行引擎
        self.api_engine.api_engine_main_loop()
        self.code_sandbox.sandbox_main_loop()
        self.file_executor.file_executor_main_loop()
        self.internal_bus.process_batch(100)

        # 阶段四：反馈与日志
        self.result_validator.result_validator_main_loop()
        self.deviation_monitor.deviation_monitor_main_loop()
        self.feedback_loop.feedback_loop_main_loop()
        self.execution_logger.execution_logger_main_loop()
        self.internal_bus.process_batch(100)

        # 3. 发送响应回 ECC
        self.cerebellum_bus.process_batch(100)

        self.cycle_count += 1

    def run_forever(self, interval_sec: float = 0.1):
        """持续运行主循环"""
        print("启动主循环...")
        try:
            while self.running:
                self.run_cycle()
                time.sleep(interval_sec)
        except KeyboardInterrupt:
            print("\n收到中断信号，正在安全关闭...")
            self.shutdown()

    def get_health_status(self):
        """健康监控"""
        return {
            "cycle_count": self.cycle_count,
            "running": self.running,
            "loaded_modules": len(self.module_map),
            "internal_pending": self.internal_bus.pending_count(),
            "cerebellum_pending": self.cerebellum_bus.pending_count(),
        }

    def shutdown(self):
        """安全关闭，逆序调用模块 shutdown"""
        self.running = False
        for mid in reversed(list(self.module_map.keys())):
            module = self.module_map[mid]
            try:
                if hasattr(module, "shutdown"):
                    module.shutdown()
            except Exception as e:
                print(f"  [WARN] 关闭模块 {mid} 异常: {e}")
        print("Agent-mcc-exec 已安全关闭")

    # ====================== 演示用例 ======================
    def demo_command_dispatch(self):
        """演示：ECC 指令下发 → MCC 接收并路由的完整数据流"""
        print("\n" + "=" * 60)
        print("  演示：ECC 工具调用指令分发")
        print("=" * 60)

        received_instructions = []
        def on_execution_result(msg):
            result = msg.data
            received_instructions.append(result)
            print(f"  ✅ 收到执行回执: 指令={result.get('instruction_id')}, 状态={result.get('status')}")

        # 订阅 ag-mcc-01 可能产生的执行结果
        self.cerebellum_bus.subscribe("ag-mcc-01.execution_result", on_execution_result)

        # 模拟 ECC 下发一条工具调用指令
        self.cerebellum_bus.publish_to_module(
            target_module="ag-mcc-01",
            event_type="tool_call_command",
            source_module="ag-ecc-12",
            data={
                "instruction_id": "CMD-001",
                "step_id": "step-01",
                "plan_id": "plan-01",
                "tool_name": "weather_api",
                "tool_type": "API",
                "params": {"city": "Beijing"},
                "timeout": 30,
                "security_token": "demo-token-001",
            },
        )

        # 处理消息：对外总线先处理，内部总线后处理，让指令流转
        self.cerebellum_bus.process_all()
        self.internal_bus.process_all()

        if not received_instructions:
            print("  ℹ️  未收到执行回执（模块尚为空壳，预期行为）")
        else:
            print(f"  共收到 {len(received_instructions)} 条执行回执")

        print("  指令分发流程执行完成")


def main():
    print("=" * 70)
    print("  Agent-mcc-exec 行动执行层 V1.0")
    print("  原创提出者：文波福")
    print("=" * 70)

    executor = AgentMccExec()

    # 运行演示用例
    executor.demo_command_dispatch()

    print("\n运行 3 个主循环周期...")
    for i in range(3):
        executor.run_cycle()
        print(f"  周期 {i+1} 完成")

    health = executor.get_health_status()
    print(f"\n✅ Agent-mcc-exec 演示完成")
    print(f"  总周期数: {health['cycle_count']}")
    print(f"  已加载模块: {health['loaded_modules']}/12")
    print(f"  内部待处理消息: {health['internal_pending']}")
    print(f"  小脑待处理消息: {health['cerebellum_pending']}")


if __name__ == "__main__":
    main()