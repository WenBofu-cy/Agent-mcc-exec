#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent-mcc-exec 行动执行层 · 主入口
版本：V1.0
原创提出者：文波福
开源协议：CC BY-NC 4.0

职责：
  - 实例化全部 12 个 MCC 行动执行层模块
  - 实现主循环：逐模块调用 run_xxx_cycle()
  - 提供端到端演示场景
"""

import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

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
    MCC 行动执行层 主控类
    负责模块实例化与主循环调度
    """

    def __init__(self):
        self.cycle_count = 0
        self.running = True

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

        print("Agent-mcc-exec 行动执行层 初始化完成")
        print(f"  模块总数: 12")

    def run_cycle(self):
        """执行一个主循环周期"""
        self.execution_core.run_execution_cycle()
        self.timeout_manager.run_timeout_cycle()
        self.resource_quota.run_quota_cycle()
        self.tool_registry.run_registry_cycle()
        self.param_validator.run_validation_cycle()
        self.api_engine.run_engine_cycle()
        self.code_sandbox.run_sandbox_cycle()
        self.file_executor.run_executor_cycle()
        self.result_validator.run_validation_cycle()
        self.deviation_monitor.run_monitor_cycle()
        self.feedback_loop.run_feedback_cycle()
        self.execution_logger.run_logger_cycle()

        self.cycle_count += 1

    def shutdown(self):
        """安全关闭"""
        self.running = False
        print("Agent-mcc-exec 已关闭")


def main():
    print("=" * 70)
    print("  Agent-mcc-exec 行动执行层 V1.0")
    print("  原创提出者：文波福")
    print("=" * 70)

    executor = AgentMccExec()

    print("\n运行 3 个主循环周期...")
    for i in range(3):
        executor.run_cycle()
        print(f"  周期 {i+1} 完成")

    print(f"\n✅ Agent-mcc-exec 演示完成, 总周期数: {executor.cycle_count}")


if __name__ == "__main__":
    main()