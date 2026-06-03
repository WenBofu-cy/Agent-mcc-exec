#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent-mcc-exec 模块注册表
行动执行层 · AI Agent 专项实现

版本：V1.0
原创提出者：文波福
开源协议：CC BY-NC 4.0

模块编号采用 ag-mcc-01 至 ag-mcc-12，连续无断号。
每个条目包含：模块编号、中文名称、所属分区、核心职责摘要。
与 Agent-ecc-brain、Agent-mlnf-mem 的 module_registry 风格完全统一。
"""

from typing import Dict, Optional, List, Tuple

MODULE_REGISTRY: Dict[str, Tuple[str, str, str]] = {
    # ========================
    # 分区一：执行中枢调度
    # ========================
    "ag-mcc-01": (
        "执行调度核心",
        "一、执行中枢调度",
        "接收ECC认知大脑下发的工具调用指令，统一分发至各执行模块，汇总执行状态"
    ),
    "ag-mcc-02": (
        "工具超时管理器",
        "一、执行中枢调度",
        "监控每个工具调用的执行时长，超时自动中断并上报"
    ),
    "ag-mcc-03": (
        "资源配额管控单元",
        "一、执行中枢调度",
        "管控API调用频次、代码执行内存上限、文件操作路径白名单等资源配额"
    ),

    # ========================
    # 分区二：工具管理集群
    # ========================
    "ag-mcc-04": (
        "工具注册中心",
        "二、工具管理集群",
        "管理可用工具目录及其参数约束，支持动态注册、注销与版本管理"
    ),
    "ag-mcc-05": (
        "工具参数校验器",
        "二、工具管理集群",
        "验证ECC下发的工具调用参数是否符合工具注册的约束规范"
    ),

    # ========================
    # 分区三：调用执行引擎
    # ========================
    "ag-mcc-06": (
        "API调用引擎",
        "三、调用执行引擎",
        "安全地执行外部API请求，管理请求头、超时、重试与错误处理"
    ),
    "ag-mcc-07": (
        "代码执行沙箱",
        "三、调用执行引擎",
        "在隔离环境中运行用户或系统生成的代码，限制系统资源访问"
    ),
    "ag-mcc-08": (
        "文件操作执行器",
        "三、调用执行引擎",
        "在用户授权路径范围内执行文件读写、创建、删除等操作"
    ),

    # ========================
    # 分区四：反馈与日志
    # ========================
    "ag-mcc-09": (
        "结果校验器",
        "四、反馈与日志",
        "验证工具执行结果是否符合预期格式与约束，标记异常结果"
    ),
    "ag-mcc-10": (
        "执行偏差监控",
        "四、反馈与日志",
        "对比目标结果与实际结果，计算偏差量并上报ECC认知大脑"
    ),
    "ag-mcc-11": (
        "闭环反馈单元",
        "四、反馈与日志",
        "汇总每次工具调用的完整执行结果，形成结构化闭环回执"
    ),
    "ag-mcc-12": (
        "执行日志记录单元",
        "四、反馈与日志",
        "全链路记录工具调用指令、实际执行、偏差、异常事件，生成不可变审计日志"
    ),
}


def get_module_info(module_id: str) -> Optional[Tuple[str, str, str]]:
    return MODULE_REGISTRY.get(module_id)

def list_all_modules() -> List[str]:
    return sorted(MODULE_REGISTRY.keys())

def get_module_count() -> int:
    return len(MODULE_REGISTRY)

def get_modules_by_zone(zone: str) -> Dict[str, Tuple[str, str, str]]:
    return {
        mid: info for mid, info in MODULE_REGISTRY.items()
        if zone in info[1]
    }


if __name__ == "__main__":
    print("=" * 60)
    print("Agent-mcc-exec 模块注册表 单元测试")
    print("=" * 60)
    passed, failed = 0, 0

    print("\n[TC-REG-01] 注册表应包含12个模块")
    try:
        assert get_module_count() == 12
        print("   ✅ PASS")
        passed += 1
    except Exception as e:
        print(f"   ❌ FAIL: {e}")
        failed += 1

    print("\n[TC-REG-02] 查询ag-mcc-01模块信息")
    try:
        info = get_module_info("ag-mcc-01")
        assert info is not None
        name, zone, role = info
        assert "执行调度" in name
        assert "执行中枢调度" in zone
        print("   ✅ PASS")
        passed += 1
    except Exception as e:
        print(f"   ❌ FAIL: {e}")
        failed += 1

    print("\n[TC-REG-03] 编号ag-mcc-01至ag-mcc-12连续")
    try:
        all_ids = list_all_modules()
        expected = [f"ag-mcc-{i:02d}" for i in range(1, 13)]
        assert all_ids == expected
        print("   ✅ PASS")
        passed += 1
    except Exception as e:
        print(f"   ❌ FAIL: {e}")
        failed += 1

    print("\n[TC-REG-04] 关键模块职责验证")
    try:
        _, _, role04 = get_module_info("ag-mcc-04")
        assert "工具注册" in role04
        _, _, role07 = get_module_info("ag-mcc-07")
        assert "沙箱" in role07 or "隔离" in role07
        _, _, role11 = get_module_info("ag-mcc-11")
        assert "闭环" in role11 or "回执" in role11
        print("   ✅ PASS")
        passed += 1
    except Exception as e:
        print(f"   ❌ FAIL: {e}")
        failed += 1

    print("\n" + "=" * 60)
    print(f"测试结果: {passed} PASS, {failed} FAIL")
    print("=" * 60)