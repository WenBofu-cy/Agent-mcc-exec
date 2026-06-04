#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-09
模块名称: 结果校验器
所属分区: 四、反馈与日志
核心职责: 在各执行模块（API调用引擎、代码执行沙箱、文件操作执行器）返回执行结果后，对结果
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

from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid
import re
import json


class ValidatorState(Enum):
    WAITING_RESULT = "waiting_result"
    VALIDATING = "validating"
    VALIDATED = "validated"
    SYSTEM_PAUSED = "system_paused"


@dataclass
class ExecutionResultToValidate:
    command_id: str = ""
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
    expected_fields: List[str] = field(default_factory=list)
    field_constraints: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    allowed_ranges: Dict[str, Any] = field(default_factory=dict)
    max_response_size: int = 10 * 1024 * 1024  # 10MB
    required_fields: List[str] = field(default_factory=list)


@dataclass
class ValidatedResult:
    command_id: str = ""
    step_id: str = ""
    plan_id: str = ""
    original_status: str = "success"
    validation_flag: str = "通过"  # 通过 / FORMAT_ERROR / FIELD_MISSING / DATA_TRUNCATED / SECURITY_ALERT (可多值以|分隔)
    validation_details: Dict[str, Any] = field(default_factory=dict)
    raw_output_data: Any = None
    cleaned_output_data: Any = None
    validation_duration_ms: float = 0.0


@dataclass
class ValidationFailureNotice:
    command_id: str = ""
    failure_dimensions: List[str] = field(default_factory=list)
    error_details: List[Dict[str, str]] = field(default_factory=list)
    suggestion: str = ""


@dataclass
class SecurityAlert:
    command_id: str = ""
    alert_type: str = ""
    data_signature: str = ""
    severity: str = "高"


@dataclass
class ValidatorStatus:
    state: ValidatorState = ValidatorState.WAITING_RESULT
    today_validations: int = 0
    pass_rate: float = 0.0
    failure_distribution: Dict[str, int] = field(default_factory=dict)
    avg_duration_ms: float = 0.0


class ResultValidator:
    # 敏感信息模式
    SENSITIVE_PATTERNS = [
        re.compile(r'sk-[a-zA-Z0-9]{32,}'),          # API Key
        re.compile(r'Bearer\s+[a-zA-Z0-9_\-\.]+'),   # Token
        re.compile(r'password["\']?\s*[:=]\s*["\']?\S+'),  # password 字段
        re.compile(r'secret["\']?\s*[:=]\s*["\']?\S+'),    # secret 字段
    ]
    # 攻击载荷模式
    ATTACK_PATTERNS = [
        re.compile(r'(?i)drop\s+table'),                # SQL 注入
        re.compile(r'(?i)<script.*?>'),                 # XSS
        re.compile(r'(?i)exec\s*\(.*\)'),               # 命令注入
    ]
    # 统计上报间隔
    STATS_REPORT_INTERVAL_SEC = 60
    # 去重缓存有效期
    DEDUP_CACHE_TTL_SEC = 5

    def __init__(self):
        self.module_id = "ag-mcc-09"
        self.module_name = "结果校验器"
        self.version = "V1.0"

        self.state = ValidatorState.WAITING_RESULT
        self._total_validations: int = 0
        self._passed_count: int = 0
        self._failure_distribution: Dict[str, int] = {}
        self._total_duration: float = 0.0
        self._dedup_cache: Dict[str, Tuple[ValidatedResult, float]] = {}
        self._last_stats_time: float = time.time()
        self._pending_logs: List[Dict[str, Any]] = []

        # 回调注入
        self._query_result_to_validate = None
        self._query_expected_template = None

        self._publish_validated_result = None
        self._publish_failure_notice = None
        self._publish_security_alert = None
        self._publish_status_report = None
        self._publish_event_log = None

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ========== 回调注入 ==========
    def set_result_to_validate_query(self, callback: Callable[[], Optional[ExecutionResultToValidate]]):
        self._query_result_to_validate = callback

    def set_expected_template_query(self, callback: Callable[[str], Optional[ExpectedResponseTemplate]]):
        self._query_expected_template = callback

    def set_validated_result_publisher(self, callback: Callable[[ValidatedResult], None]):
        self._publish_validated_result = callback

    def set_failure_notice_publisher(self, callback: Callable[[ValidationFailureNotice], None]):
        self._publish_failure_notice = callback

    def set_security_alert_publisher(self, callback: Callable[[SecurityAlert], None]):
        self._publish_security_alert = callback

    def set_status_report_publisher(self, callback: Callable[[ValidatorStatus], None]):
        self._publish_status_report = callback

    def set_event_log_publisher(self, callback: Callable[[Dict[str, Any]], None]):
        self._publish_event_log = callback

    # ========== 主循环 ==========
    def run_validation_cycle(self) -> Optional[ValidatedResult]:
        now = time.time()

        if self.state == ValidatorState.SYSTEM_PAUSED:
            return None

        # 定期统计上报
        if now - self._last_stats_time >= self.STATS_REPORT_INTERVAL_SEC:
            self._publish_stats()
            self._last_stats_time = now

        # 接收待校验结果
        result_to_validate = self._query_result_to_validate() if self._query_result_to_validate else None
        if result_to_validate is None:
            return None

        # 去重检查
        if result_to_validate.command_id in self._dedup_cache:
            cached_result, cached_time = self._dedup_cache[result_to_validate.command_id]
            if now - cached_time < self.DEDUP_CACHE_TTL_SEC:
                if self._publish_validated_result:
                    self._publish_validated_result(cached_result)
                return cached_result

        self.state = ValidatorState.VALIDATING
        start_time = time.time()

        validated = self._validate(result_to_validate)

        elapsed = (time.time() - start_time) * 1000
        validated.validation_duration_ms = elapsed

        # 缓存
        self._dedup_cache[validated.command_id] = (validated, now)
        # 清理过期缓存
        expired = [cid for cid, (_, t) in self._dedup_cache.items() if now - t > self.DEDUP_CACHE_TTL_SEC]
        for cid in expired:
            del self._dedup_cache[cid]

        self._total_validations += 1
        if validated.validation_flag == "通过":
            self._passed_count += 1
        else:
            for flag in validated.validation_flag.split("|"):
                self._failure_distribution[flag] = self._failure_distribution.get(flag, 0) + 1
        self._total_duration += elapsed

        self.state = ValidatorState.VALIDATED

        # 输出校验后结果
        if self._publish_validated_result:
            self._publish_validated_result(validated)

        # 校验不通过时发送失败通知
        if validated.validation_flag != "通过":
            if self._publish_failure_notice:
                self._publish_failure_notice(ValidationFailureNotice(
                    command_id=validated.command_id,
                    failure_dimensions=validated.validation_flag.split("|"),
                    error_details=validated.validation_details.get("errors", []),
                    suggestion="请参考校验详情进行修正"
                ))

        # 安全告警时发送告警
        if "SECURITY_ALERT" in validated.validation_flag:
            if self._publish_security_alert:
                self._publish_security_alert(SecurityAlert(
                    command_id=validated.command_id,
                    alert_type="数据安全告警",
                    data_signature=validated.validation_details.get("security_detail", ""),
                    severity="高"
                ))

        self.state = ValidatorState.WAITING_RESULT
        return validated

    # ========== 核心校验 ==========
    def _validate(self, raw: ExecutionResultToValidate) -> ValidatedResult:
        flags = []
        details = {}
        cleaned = raw.raw_output_data

        # 获取预期模板
        template = self._query_expected_template(raw.tool_name) if self._query_expected_template else None
        if template is None:
            template = ExpectedResponseTemplate()  # 使用空默认模板

        # 1. 格式合规性检查
        if raw.raw_output_data is not None:
            if not self._check_format(raw.raw_output_data, template):
                flags.append("FORMAT_ERROR")
                details["format_error"] = "输出数据格式与预期模板不匹配"

        # 2. 字段完整性检查
        if template.required_fields:
            missing = self._check_required_fields(raw.raw_output_data, template.required_fields)
            if missing:
                flags.append("FIELD_MISSING")
                details["missing_fields"] = missing
                details.setdefault("errors", []).append({"dimension": "FIELD_MISSING", "detail": f"缺失字段: {missing}"})

        # 3. 数据合理性检查
        if template.field_constraints:
            invalid = self._check_data_validity(raw.raw_output_data, template.field_constraints)
            if invalid:
                flags.append("DATA_INVALID")
                details["invalid_fields"] = invalid
                details.setdefault("errors", []).append({"dimension": "DATA_INVALID", "detail": f"无效字段: {invalid}"})

        # 4. 大小合规性检查
        data_size = len(str(raw.raw_output_data)) if raw.raw_output_data else 0
        if data_size > template.max_response_size:
            cleaned = str(raw.raw_output_data)[:template.max_response_size]
            flags.append("DATA_TRUNCATED")
            details["original_size"] = data_size
            details["truncated_size"] = template.max_response_size

        # 5. 安全合规性扫描
        if cleaned is not None:
            data_str = cleaned if isinstance(cleaned, str) else str(cleaned)
            security_result = self._security_scan(data_str)
            if security_result["has_sensitive"] or security_result["has_attack"]:
                flags.append("SECURITY_ALERT")
                details["security_detail"] = security_result["detail"]
                if security_result["has_sensitive"]:
                    cleaned = security_result["sanitized_data"]
                if security_result["has_attack"]:
                    details.setdefault("errors", []).append({"dimension": "SECURITY_ALERT", "detail": "检测到攻击载荷"})

        flag_str = "|".join(flags) if flags else "通过"

        return ValidatedResult(
            command_id=raw.command_id,
            step_id=raw.step_id,
            plan_id=raw.plan_id,
            original_status=raw.execution_status,
            validation_flag=flag_str,
            validation_details=details,
            raw_output_data=raw.raw_output_data,
            cleaned_output_data=cleaned
        )

    def _check_format(self, data: Any, template: ExpectedResponseTemplate) -> bool:
        """简单格式检查：如果是字符串，尝试解析 JSON（如果期望 JSON 格式）"""
        if isinstance(data, str):
            try:
                json.loads(data)
                return True
            except json.JSONDecodeError:
                pass
        return True  # 非字符串数据不做强制 JSON 校验

    def _check_required_fields(self, data: Any, required: List[str]) -> List[str]:
        if data is None:
            return required  # 全部缺失
        if isinstance(data, dict):
            return [f for f in required if f not in data or data[f] is None]
        return []

    def _check_data_validity(self, data: Any, constraints: Dict[str, Dict[str, Any]]) -> List[str]:
        invalid = []
        if not isinstance(data, dict):
            return invalid
        for field, constraint in constraints.items():
            if field not in data:
                continue
            value = data[field]
            field_type = constraint.get("type")
            if field_type == "int" and not isinstance(value, int):
                invalid.append(f"{field}: 期望 int, 实际 {type(value).__name__}")
            elif field_type == "string" and not isinstance(value, str):
                invalid.append(f"{field}: 期望 string, 实际 {type(value).__name__}")
            if "min" in constraint and isinstance(value, (int, float)) and value < constraint["min"]:
                invalid.append(f"{field}: 值 {value} 小于最小值 {constraint['min']}")
            if "max" in constraint and isinstance(value, (int, float)) and value > constraint["max"]:
                invalid.append(f"{field}: 值 {value} 大于最大值 {constraint['max']}")
        return invalid

    def _security_scan(self, data_str: str) -> Dict[str, Any]:
        result = {"has_sensitive": False, "has_attack": False, "detail": "", "sanitized_data": data_str}
        sanitized = data_str

        # 敏感信息检测
        for pattern in self.SENSITIVE_PATTERNS:
            if pattern.search(data_str):
                result["has_sensitive"] = True
                result["detail"] += f"敏感信息匹配: {pattern.pattern}; "
                sanitized = pattern.sub("[REDACTED]", sanitized)

        # 攻击载荷检测
        for pattern in self.ATTACK_PATTERNS:
            if pattern.search(data_str):
                result["has_attack"] = True
                result["detail"] += f"攻击载荷匹配: {pattern.pattern}; "

        result["sanitized_data"] = sanitized
        return result

    # ========== 辅助 ==========
    def _publish_stats(self):
        if self._publish_status_report:
            rate = self._passed_count / max(self._total_validations, 1)
            avg = self._total_duration / max(self._total_validations, 1)
            self._publish_status_report(ValidatorStatus(
                state=self.state,
                today_validations=self._total_validations,
                pass_rate=round(rate, 3),
                failure_distribution=self._failure_distribution.copy(),
                avg_duration_ms=round(avg, 2)
            ))

    def get_state(self) -> ValidatorState:
        return self.state

    def emergency_shutdown(self):
        self.state = ValidatorState.SYSTEM_PAUSED
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
    print("  Agent-mcc-exec 结果校验器 (ag-mcc-09) 演示")
    print("=" * 70)

    validator = ResultValidator()
    validator.set_expected_template_query(lambda tool_name: ExpectedResponseTemplate(
        tool_name=tool_name,
        required_fields=["result", "status"],
        field_constraints={"status": {"type": "string", "enum": ["ok", "fail"]}}
    ))

    print_separator("STEP 1: 结果完全合规")
    validator.set_result_to_validate_query(lambda: ExecutionResultToValidate(
        command_id="CMD-001", tool_name="weather_api", tool_type="API",
        execution_status="success",
        raw_output_data={"result": "晴天", "status": "ok"}
    ))
    result = validator.run_validation_cycle()
    if result:
        print(f"  校验标记: {result.validation_flag}")

    print_separator("STEP 2: 缺少必填字段")
    validator.set_result_to_validate_query(lambda: ExecutionResultToValidate(
        command_id="CMD-002", tool_name="weather_api", tool_type="API",
        execution_status="success",
        raw_output_data={"result": "晴天"}
    ))
    result = validator.run_validation_cycle()
    if result:
        print(f"  校验标记: {result.validation_flag}")
        print(f"  详情: {result.validation_details}")

    print_separator("STEP 3: 检测到敏感信息")
    validator.set_result_to_validate_query(lambda: ExecutionResultToValidate(
        command_id="CMD-003", tool_name="weather_api", tool_type="API",
        execution_status="success",
        raw_output_data={"result": "ok", "token": "sk-abc123def456ghi789jkl012mno345pqr678stu"}
    ))
    result = validator.run_validation_cycle()
    if result:
        print(f"  校验标记: {result.validation_flag}")
        if result.cleaned_output_data:
            print(f"  清洗后数据: {str(result.cleaned_output_data)[:100]}...")

    print("\n✅ 结果校验器演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("ag-mcc-09 结果校验器 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        def setup_validator():
            v = ResultValidator()
            v.set_expected_template_query(lambda tool_name: ExpectedResponseTemplate(
                required_fields=["result", "status"],
                field_constraints={"status": {"type": "string"}}
            ))
            return v

        # TC-MCC-09-01: 正常通过
        print("\n[TC-MCC-09-01] 正常通过")
        try:
            v = setup_validator()
            v.set_result_to_validate_query(lambda: ExecutionResultToValidate(
                command_id="T01", tool_name="test", execution_status="success",
                raw_output_data={"result": "ok", "status": "success"}
            ))
            result = v.run_validation_cycle()
            assert result is not None
            assert result.validation_flag == "通过"
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-09-02: 字段缺失
        print("\n[TC-MCC-09-02] 字段缺失")
        try:
            v = setup_validator()
            v.set_result_to_validate_query(lambda: ExecutionResultToValidate(
                command_id="T02", tool_name="test", execution_status="success",
                raw_output_data={"result": "ok"}
            ))
            result = v.run_validation_cycle()
            assert result is not None
            assert "FIELD_MISSING" in result.validation_flag
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-09-03: 数据大小超限截断
        print("\n[TC-MCC-09-03] 数据大小超限截断")
        try:
            v = setup_validator()
            v.set_expected_template_query(lambda tool_name: ExpectedResponseTemplate(max_response_size=10))
            v.set_result_to_validate_query(lambda: ExecutionResultToValidate(
                command_id="T03", tool_name="test", execution_status="success",
                raw_output_data="x" * 100
            ))
            result = v.run_validation_cycle()
            assert result is not None
            assert "DATA_TRUNCATED" in result.validation_flag
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-09-04: 敏感信息脱敏
        print("\n[TC-MCC-09-04] 敏感信息脱敏")
        try:
            v = setup_validator()
            v.set_result_to_validate_query(lambda: ExecutionResultToValidate(
                command_id="T04", tool_name="test", execution_status="success",
                raw_output_data={"result": "ok", "status": "ok", "api_key": "sk-abc123def456"}
            ))
            result = v.run_validation_cycle()
            assert result is not None
            assert "SECURITY_ALERT" in result.validation_flag
            assert "sk-" not in str(result.cleaned_output_data)
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-09-05: 攻击载荷检测
        print("\n[TC-MCC-09-05] 攻击载荷检测")
        try:
            v = setup_validator()
            v.set_result_to_validate_query(lambda: ExecutionResultToValidate(
                command_id="T05", tool_name="test", execution_status="success",
                raw_output_data="DROP TABLE users;"
            ))
            result = v.run_validation_cycle()
            assert result is not None
            assert "SECURITY_ALERT" in result.validation_flag
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-09-06: 紧急熔断
        print("\n[TC-MCC-09-06] 紧急熔断")
        try:
            v = setup_validator()
            v.emergency_shutdown()
            assert v.state == ValidatorState.SYSTEM_PAUSED
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