#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-09
模块名称: 结果校验器
所属分区: 四、反馈与日志
版本: V1.0
原创提出者: 文波福
开源协议: CC BY-NC 4.0

核心职责:
    在各执行模块（API调用引擎、代码执行沙箱、文件操作执行器）返回执行结果后，对结果
    的格式合规性、字段完整性、数据合理性与安全合规性进行多维度校验。确保返回给 ECC
    认知大脑的数据符合预期的结构化规范，过滤掉异常数据、截断超大数据、标记不完整结果。
    校验通过的结果放行至闭环反馈单元（ag-mcc-11）进行最终汇总；校验不通过的结果标记
    错误原因后仍返回，但附带详细的校验失败报告。不参与工具的实际调用或数据修改，仅负责
    结果质量的客观校验。

依赖模块:
    ag-mcc-01(执行调度核心), ag-mcc-04(工具注册中心)
被依赖模块:
    ag-mcc-11(闭环反馈单元), ag-mcc-12(执行日志记录单元)

安全约束:
  V-01: 本模块仅校验结果质量，不得修改工具返回的原始业务数据内容（脱敏与截断除外）
  V-02: 敏感信息检测为强制性安全检查，发现敏感信息必须脱敏后方可放行
  V-03: 检测到攻击载荷模式时，必须立即发送安全告警，不得仅标记后放行
  V-04: 校验过程中不得将原始输出数据缓存或转发至任何非授权的第三方模块
  V-05: 校验失败的详细原因仅记录于内部日志，返回给 ECC 的错误信息应简洁明了
"""

from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid
import re
import json
import threading
import base64

# ====================== 枚举定义 ======================
class ValidatorState(Enum):
    WAITING_RESULT = "WAITING_RESULT"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    SYSTEM_PAUSED = "SYSTEM_PAUSED"

# ====================== 数据模型 ======================
@dataclass
class ExecutionResultToValidate:
    instruction_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    tool_name: str = ""
    tool_type: str = ""
    execution_status: str = "success"
    raw_output_data: Any = None
    duration_sec: float = 0.0
    error_code: str = ""

@dataclass
class ExpectedResponseTemplate:
    tool_name: str = ""
    required_fields: List[str] = field(default_factory=list)
    # 修复语法错误：约束配置为字典，不是列表
    field_constraints: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    max_response_size: int = 10 * 1024 * 1024  # 10MB

@dataclass
class ValidatedResult:
    instruction_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    original_status: str = "success"
    validation_flag: str = "通过"  # 通过 / FORMAT_ERROR / FIELD_MISSING / DATA_TRUNCATED / SECURITY_ALERT (多值|分隔)
    validation_details: Dict[str, Any] = field(default_factory=dict)
    raw_output_data: Any = None
    cleaned_output_data: Any = None
    validation_duration_ms: float = 0.0

# ====================== 主校验器 ======================
class ResultValidator:
    # 基础配置
    MAX_CONCURRENT = 3
    STATS_REPORT_INTERVAL_SEC = 60
    DEDUP_CACHE_TTL_SEC = 5

    # 敏感信息规则 (V-02: 检测后脱敏放行)
    SENSITIVE_PATTERNS = [
        re.compile(r'sk-[a-zA-Z0-9]{32,}'),
        re.compile(r'Bearer\s+[a-zA-Z0-9_\-\.]+'),
        re.compile(r'password["\']?\s*[:=]\s*["\']?\S+'),
        re.compile(r'secret["\']?\s*[:=]\s*["\']?\S+'),
        re.compile(r'token["\']?\s*[:=]\s*["\']?\S+'),
        re.compile(r'[1-9]\d{14,17}')
    ]

    # 攻击载荷规则 (V-03: 检测后强制上报告警)
    ATTACK_PATTERNS = [
        re.compile(r'(?i)drop\s+table'),
        re.compile(r'(?i)union\s+select'),
        re.compile(r'(?i)<script.*?>'),
        re.compile(r'(?i)javascript\s*:'),
        re.compile(r'(?i)exec\s*\(.*\)'),
        re.compile(r'(?i)system\s*\(.*\)')
    ]

    def __init__(self):
        self.module_id = "ag-mcc-09"
        self.module_name = "结果校验器"
        self.version = "V1.0"
        self.bus = None

        self.state = ValidatorState.WAITING_RESULT
        self._lock = threading.Lock()
        self._running_count = 0
        self._waiting_queue: List[ExecutionResultToValidate] = []

        # 运行统计
        self._total_validations = 0
        self._passed_count = 0
        self._failure_distribution: Dict[str, int] = {}
        self._total_duration = 0.0
        self._last_stats_time = time.time()

        # 去重缓存: instruction_id -> (结果对象, 时间戳)
        self._dedup_cache: Dict[str, Tuple[ValidatedResult, float]] = {}

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ====================== 主循环（标准SPEC接口） ======================
    def result_validator_main_loop(self):
        now = time.time()
        if self.state == ValidatorState.SYSTEM_PAUSED:
            return

        # 定时上报统计信息
        if now - self._last_stats_time >= self.STATS_REPORT_INTERVAL_SEC:
            self._publish_stats()
            self._last_stats_time = now

        # 消费等待队列任务
        with self._lock:
            if self._waiting_queue and self._running_count < self.MAX_CONCURRENT:
                task = self._waiting_queue.pop(0)
                self._running_count += 1
                self._handle_single_validation(task)

    # ====================== 总线消息处理 ======================
    def handle_message(self, message):
        if not self.bus or not message:
            return

        data = message.data or {}
        topic = message.topic

        # 接收校验请求
        if topic == "ag-mcc-09.validation_request":
            try:
                raw_task = ExecutionResultToValidate(
                    instruction_id=data.get("instruction_id", ""),
                    step_id=data.get("step_id", ""),
                    plan_id=data.get("plan_id", ""),
                    tool_name=data.get("tool_name", ""),
                    tool_type=data.get("tool_type", ""),
                    execution_status=data.get("execution_status", "success"),
                    raw_output_data=data.get("raw_output_data"),
                    duration_sec=data.get("duration_sec", 0.0),
                    error_code=data.get("error_code", "")
                )
            except Exception:
                return

            # 5秒内重复请求直接复用缓存
            now = time.time()
            cache_key = raw_task.instruction_id
            if cache_key in self._dedup_cache:
                cached_res, cache_ts = self._dedup_cache[cache_key]
                if now - cache_ts < self.DEDUP_CACHE_TTL_SEC:
                    self._send_validated_result(cached_res)
                    return

            # 任务入队/执行
            with self._lock:
                if self._running_count < self.MAX_CONCURRENT:
                    self._running_count += 1
                    self._handle_single_validation(raw_task)
                else:
                    self._waiting_queue.append(raw_task)

        # 全局指令
        elif topic == "ag-mcc-09.global_command":
            cmd = data.get("command", "")
            if cmd == "emergency_shutdown":
                self.emergency_shutdown()

    # ====================== 单任务校验入口 ======================
    def _handle_single_validation(self, raw: ExecutionResultToValidate):
        self.state = ValidatorState.VALIDATING
        start_time = time.time()
        validated = ValidatedResult()

        try:
            validated = self._validate_core(raw)
        except Exception as e:
            # 全局异常兜底
            validated.instruction_id = raw.instruction_id
            validated.step_id = raw.step_id
            validated.plan_id = raw.plan_id
            validated.original_status = raw.execution_status
            validated.validation_flag = "FORMAT_ERROR"
            validated.validation_details = {"inner_error": f"校验异常: {str(e)}"}
            validated.raw_output_data = raw.raw_output_data
            validated.cleaned_output_data = raw.raw_output_data

        # 计算耗时
        validated.validation_duration_ms = (time.time() - start_time) * 1000
        now = time.time()

        # 更新缓存 + 清理过期缓存（加锁保证线程安全）
        with self._lock:
            self._dedup_cache[validated.instruction_id] = (validated, now)
            expired_keys = [k for k, (_, ts) in self._dedup_cache.items() if now - ts > self.DEDUP_CACHE_TTL_SEC]
            for key in expired_keys:
                del self._dedup_cache[key]

        # 更新统计
        self._update_statistics(validated)

        # 分发结果、日志、告警
        self._send_validated_result(validated)
        if validated.validation_flag != "通过":
            self._send_validation_failure_log(validated)
        if "SECURITY_ALERT" in validated.validation_flag:
            self._send_security_alert(validated)

        # 计数递减 + 状态复位
        with self._lock:
            self._running_count -= 1
        self._reset_state_if_idle()

    # ====================== 核心校验逻辑 ======================
    def _validate_core(self, raw: ExecutionResultToValidate) -> ValidatedResult:
        flags: List[str] = []
        details: Dict[str, Any] = {}
        raw_data = raw.raw_output_data
        clean_data = raw_data
        has_attack = False

        # 获取工具校验模板
        template = self._fetch_response_template(raw.tool_name)

        # 1. 格式校验
        if raw_data is not None and not self._check_data_format(raw_data):
            flags.append("FORMAT_ERROR")
            details["format_error"] = "数据格式非法，非标准文本/JSON结构"

        # 2. 必填字段校验
        missing_fields = self._check_required_fields(raw_data, template)
        if missing_fields:
            flags.append("FIELD_MISSING")
            details["missing_fields"] = missing_fields
            details.setdefault("errors", []).append({
                "dimension": "FIELD_MISSING",
                "detail": f"缺失字段: {missing_fields}"
            })

        # 3. 字段规则校验
        invalid_fields = self._check_field_constraints(raw_data, template)
        if invalid_fields:
            flags.append("DATA_INVALID")
            details["invalid_fields"] = invalid_fields
            details.setdefault("errors", []).append({
                "dimension": "DATA_INVALID",
                "detail": f"无效字段: {invalid_fields}"
            })

        # 4. 数据大小校验 & 字节级截断（修复编码乱码问题 V-01）
        data_str = self._any_to_string(raw_data)
        data_bytes = data_str.encode("utf-8", errors="replace")
        data_size = len(data_bytes)

        if data_size > template.max_response_size:
            # 按字节截断，避免中文乱码
            trunc_bytes = data_bytes[:template.max_response_size]
            clean_data = trunc_bytes.decode("utf-8", errors="replace")
            flags.append("DATA_TRUNCATED")
            details["original_size_bytes"] = data_size
            details["limit_size_bytes"] = template.max_response_size

        # 5. 安全扫描：敏感脱敏 + 攻击检测 (V-02 / V-03)
        scan_text = clean_data if isinstance(clean_data, str) else str(clean_data)
        security_res = self._full_security_scan(scan_text)
        if security_res["has_sensitive"] or security_res["has_attack"]:
            flags.append("SECURITY_ALERT")
            details["security_detail"] = security_res["detail"]
            clean_data = security_res["sanitized_data"]
            details.setdefault("errors", []).append({
                "dimension": "SECURITY_ALERT",
                "detail": "检测到安全风险，已完成处理"
            })
            has_attack = security_res["has_attack"]

        # 拼接多标签
        flag_str = "|".join(flags) if flags else "通过"

        # 标记是否存在攻击载荷（用于区分告警级别）
        details["has_attack_payload"] = has_attack

        return ValidatedResult(
            instruction_id=raw.instruction_id,
            step_id=raw.step_id,
            plan_id=raw.plan_id,
            original_status=raw.execution_status,
            validation_flag=flag_str,
            validation_details=details,
            raw_output_data=raw_data,
            cleaned_output_data=clean_data
        )

    # ====================== 工具模板查询 ======================
    def _fetch_response_template(self, tool_name: str) -> ExpectedResponseTemplate:
        if not self.bus:
            return ExpectedResponseTemplate(tool_name=tool_name)
        try:
            resp = self.bus.request(
                topic="ag-mcc-04.tool_query",
                source_module=self.module_id,
                data={
                    "query_type": "single",
                    "tool_name": tool_name,
                    "requester_module": self.module_id
                },
                target_module="ag-mcc-04",
                timeout_ms=500
            )
            if resp and resp.data:
                tools = resp.data.get("tools", [])
                if tools:
                    tool_cfg = tools[0]
                    return ExpectedResponseTemplate(
                        tool_name=tool_name,
                        required_fields=tool_cfg.get("required_fields", []),
                        field_constraints=tool_cfg.get("field_constraints", {}),
                        max_response_size=tool_cfg.get("max_response_size_bytes", 10 * 1024 * 1024)
                    )
        except Exception:
            pass
        return ExpectedResponseTemplate(tool_name=tool_name)

    # ====================== 通用数据工具方法 ======================
    def _any_to_string(self, data: Any) -> str:
        """任意类型转为字符串，兼容字典/列表/二进制"""
        if isinstance(data, (dict, list)):
            return json.dumps(data, ensure_ascii=False)
        if isinstance(data, bytes):
            return base64.b64encode(data).decode("utf-8")
        if data is None:
            return ""
        return str(data)

    def _check_data_format(self, data: Any) -> bool:
        """基础格式校验：字符串尝试解析JSON"""
        if isinstance(data, str):
            try:
                json.loads(data)
            except json.JSONDecodeError:
                return False
        return True

    def _check_required_fields(self, data: Any, template: ExpectedResponseTemplate) -> List[str]:
        """一级必填字段校验"""
        missing = []
        req_fields = template.required_fields
        if not req_fields or not isinstance(data, dict):
            return missing
        for field in req_fields:
            if field not in data or data[field] is None:
                missing.append(field)
        return missing

    def _check_field_constraints(self, data: Any, template: ExpectedResponseTemplate) -> List[str]:
        """字段类型、数值范围校验"""
        invalid = []
        if not isinstance(data, dict):
            return invalid
        for field, rule in template.field_constraints.items():
            if field not in data:
                continue
            val = data[field]
            rule_type = rule.get("type")

            if rule_type == "int" and not isinstance(val, int):
                invalid.append(f"{field}: 类型错误，要求整数")
            elif rule_type == "str" and not isinstance(val, str):
                invalid.append(f"{field}: 类型错误，要求字符串")

            if isinstance(val, (int, float)):
                if "min" in rule and val < rule["min"]:
                    invalid.append(f"{field}: 小于最小值 {rule['min']}")
                if "max" in rule and val > rule["max"]:
                    invalid.append(f"{field}: 大于最大值 {rule['max']}")
        return invalid

    def _full_security_scan(self, text: str) -> Dict[str, Any]:
        """安全扫描：区分敏感信息、攻击载荷，严格落地 V-02 / V-03"""
        result = {
            "has_sensitive": False,
            "has_attack": False,
            "detail": "",
            "sanitized_data": text
        }
        sanitized = text

        # V-02 敏感信息：检测并脱敏
        for pat in self.SENSITIVE_PATTERNS:
            if pat.search(text):
                result["has_sensitive"] = True
                result["detail"] += "检测到敏感信息并脱敏; "
                sanitized = pat.sub("[REDACTED]", sanitized)

        # V-03 攻击载荷：检测后必须告警
        for pat in self.ATTACK_PATTERNS:
            if pat.search(text):
                result["has_attack"] = True
                result["detail"] += "检测到恶意攻击载荷; "

        result["sanitized_data"] = sanitized
        return result

    # ====================== 统计与状态管理 ======================
    def _update_statistics(self, validated: ValidatedResult):
        with self._lock:
            self._total_validations += 1
            self._total_duration += validated.validation_duration_ms
            if validated.validation_flag == "通过":
                self._passed_count += 1
            else:
                for flag in validated.validation_flag.split("|"):
                    self._failure_distribution[flag] = self._failure_distribution.get(flag, 0) + 1

    def _reset_state_if_idle(self):
        """无任务时恢复空闲状态"""
        with self._lock:
            if self._running_count <= 0 and len(self._waiting_queue) == 0:
                self.state = ValidatorState.WAITING_RESULT

    # ====================== 总线消息发送 ======================
    def _send_validated_result(self, validated: ValidatedResult):
        """下发结果到 ag-mcc-11，对外精简错误 (V-05)"""
        if not self.bus:
            return
        brief_info = {}
        if validated.validation_flag != "通过":
            brief_info["brief_error"] = "数据校验不通过，详情查看内部日志"

        self.bus.publish_to_module(
            target_module="ag-mcc-11",
            event_type="validated_result",
            source_module=self.module_id,
            data={
                "instruction_id": validated.instruction_id,
                "step_id": validated.step_id,
                "plan_id": validated.plan_id,
                "original_status": validated.original_status,
                "validation_flag": validated.validation_flag,
                "validation_brief": brief_info,
                "cleaned_output_data": validated.cleaned_output_data
            }
        )

    def _send_validation_failure_log(self, validated: ValidatedResult):
        """校验详情写入内部日志 ag-mcc-12 (V-05)"""
        if not self.bus:
            return
        self.bus.publish_to_module(
            target_module="ag-mcc-12",
            event_type="validation_failure",
            source_module=self.module_id,
            data={
                "log_id": f"log-{uuid.uuid4().hex[:8]}",
                "instruction_id": validated.instruction_id,
                "validation_flag": validated.validation_flag,
                "full_details": validated.validation_details,
                "timestamp": time.time()
            }
        )

    def _send_security_alert(self, validated: ValidatedResult):
        """安全告警上报 ag-mcc-01 (V-03：攻击载荷强制高等级告警)"""
        if not self.bus:
            return
        detail = validated.validation_details
        # 攻击载荷使用最高级别，纯敏感信息使用普通级别
        alert_level = "高" if detail.get("has_attack_payload", False) else "中"

        self.bus.publish_to_module(
            target_module="ag-mcc-01",
            event_type="security_alert",
            source_module=self.module_id,
            data={
                "instruction_id": validated.instruction_id,
                "alert_level": alert_level,
                "alert_type": "结果数据安全风险",
                "risk_detail": detail.get("security_detail", ""),
                "timestamp": time.time()
            }
        )

    # ====================== 状态上报 & 运维接口 ======================
    def _publish_stats(self):
        """定时上报运行状态与统计"""
        if not self.bus:
            return
        total = max(self._total_validations, 1)
        pass_rate = round(self._passed_count / total, 3)
        avg_ms = round(self._total_duration / total, 2)

        self.bus.publish_to_module(
            target_module="ag-mcc-12",
            event_type="validator_status",
            source_module=self.module_id,
            data={
                "state": self.state.value,
                "running_tasks": self._running_count,
                "pending_queue": len(self._waiting_queue),
                "total_validations": self._total_validations,
                "pass_rate": pass_rate,
                "failure_dist": self._failure_distribution.copy(),
                "avg_cost_ms": avg_ms
            }
        )

    def get_state(self) -> ValidatorState:
        return self.state

    def emergency_shutdown(self):
        """紧急熔断：清空队列、暂停服务"""
        self.state = ValidatorState.SYSTEM_PAUSED
        with self._lock:
            self._waiting_queue.clear()
            self._running_count = 0
        print(f"[{self.module_id}] 紧急熔断，等待队列已清空")

    def shutdown(self):
        """优雅关闭"""
        self.state = ValidatorState.WAITING_RESULT
        print(f"[{self.module_id}] 已安全关闭")

# ====================== 演示与测试入口 ======================
def demo_main():
    print("=" * 70)
    print("  ag-mcc-09 结果校验器 V1.0 演示")
    print("=" * 70)

    from memory_bus import InternalBus
    bus = InternalBus()
    bus.register_module("ag-mcc-09")
    bus.register_module("ag-mcc-01")
    bus.register_module("ag-mcc-04")
    bus.register_module("ag-mcc-11")
    bus.register_module("ag-mcc-12")

    validator = ResultValidator()
    validator.bus = bus
    bus.subscribe_to_module("ag-mcc-09", validator.handle_message)

    # 模拟 ag-mcc-04 工具查询响应
    def mock_tool_query(msg):
        bus.publish_reply(
            topic="ag-mcc-04.tool_query_result",
            source_module="ag-mcc-04",
            data={
                "tools": [{
                    "tool_name": "weather_api",
                    "required_fields": ["status", "data"],
                    "field_constraints": {"status": {"type": "str"}}
                }]
            },
            correlation_id=msg.correlation_id,
            target_module=msg.source_module
        )
    bus.subscribe_to_module("ag-mcc-04", mock_tool_query)

    # 用例1：正常合规数据
    print("\n[用例1] 数据完全合规")
    bus.publish_to_module("ag-mcc-09", "validation_request", "ag-mcc-01", {
        "instruction_id": "VLD-001",
        "tool_name": "weather_api",
        "tool_type": "API",
        "execution_status": "success",
        "raw_output_data": {"status": "ok", "data": "多云"}
    })
    bus.process_all()
    validator.result_validator_main_loop()

    # 用例2：包含敏感信息（自动脱敏）
    print("\n[用例2] 检测敏感信息，自动脱敏+安全告警")
    bus.publish_to_module("ag-mcc-09", "validation_request", "ag-mcc-01", {
        "instruction_id": "VLD-002",
        "tool_name": "weather_api",
        "execution_status": "success",
        "raw_output_data": "接口密钥：sk-1234567890abcdef1234567890abcdef"
    })
    bus.process_all()
    validator.result_validator_main_loop()

    # 用例3：包含攻击载荷（触发安全告警）
    print("\n[用例3] 检测SQL注入攻击载荷，触发高等级告警")
    bus.publish_to_module("ag-mcc-09", "validation_request", "ag-mcc-01", {
        "instruction_id": "VLD-003",
        "tool_name": "weather_api",
        "execution_status": "success",
        "raw_output_data": "test'; drop table user;"
    })
    bus.process_all()
    validator.result_validator_main_loop()

    # 用例4：重复指令去重测试
    print("\n[用例4] 重复指令去重")
    bus.publish_to_module("ag-mcc-09", "validation_request", "ag-mcc-01", {
        "instruction_id": "VLD-001",
        "tool_name": "weather_api",
        "raw_output_data": {"status": "ok", "data": "多云"}
    })
    bus.process_all()
    validator.result_validator_main_loop()

    print(f"\n总校验次数: {validator._total_validations}, 校验通过: {validator._passed_count}")
    print("\n✅ 所有演示执行完毕")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("单元测试入口已就绪，可扩展测试用例")
    else:
        demo_main()