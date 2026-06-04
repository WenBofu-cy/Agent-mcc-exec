#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-05
模块名称: 工具参数校验器
所属分区: 二、工具管理集群
核心职责: 在工具调用指令下发至具体执行模块之前，对指令中携带的参数进行合法性校验。
          基于 ag-mcc-04（工具注册中心）中存储的各工具参数模板与约束规则，逐一检查每个
          参数的类型、格式、取值范围、依赖关系是否合规。校验通过则放行至执行模块；校验
          不通过则向 ag-mcc-01（执行调度核心）返回详细的参数错误报告，阻止无效调用进入
          执行层。同时支持为 ag-ecc-03（工具选择模块）提供参数预校验能力，辅助工具选择
          决策。不参与工具的实际调用，仅负责参数的合法性检查。

依赖模块:
    ag-mcc-04(工具注册中心)
被依赖模块:
    ag-mcc-01(执行调度核心), ag-ecc-03(工具选择模块)

安全约束:
  V-01: 本模块仅校验参数合法性，不缓存、不存储、不转发任何工具参数的实际值
  V-02: 安全敏感参数检查必须在标准及以上严格度强制执行，不得跳过
  V-03: 检测到攻击特征时，必须立即拒绝并记录安全事件日志，不得仅返回警告
  V-04: 参数校验结果中的错误详情不得泄露工具模板的内部实现细节
  V-05: 参数预校验仅检查格式合法性，不得向请求方返回工具的完整参数模板
"""

from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid
import re


class ValidatorState(Enum):
    WAITING_REQUEST = "waiting_request"
    VALIDATING = "validating"
    VALIDATED = "validated"
    SYSTEM_PAUSED = "system_paused"


class Strictness(Enum):
    LOOSE = "宽松"
    STANDARD = "标准"
    STRICT = "严格"


@dataclass
class ParamValidationRequest:
    command_id: str = ""
    tool_name: str = ""
    tool_type: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    strictness: Strictness = Strictness.STANDARD
    requester_module: str = ""


@dataclass
class ParamTemplate:
    param_name: str = ""
    param_type: str = "string"
    required: bool = False
    default_value: Any = None
    allowed_range: Optional[Dict[str, Any]] = None
    format_regex: Optional[str] = None
    dependencies: Dict[str, Any] = field(default_factory=dict)
    security_sensitive: bool = False


@dataclass
class ValidationError:
    param_name: str = ""
    error_code: str = ""
    reason: str = ""


@dataclass
class ValidationResult:
    command_id: str = ""
    passed: bool = True
    errors: List[ValidationError] = field(default_factory=list)
    corrections: List[str] = field(default_factory=list)
    validation_duration_ms: float = 0.0


@dataclass
class ValidationStatistics:
    state: ValidatorState = ValidatorState.WAITING_REQUEST
    today_validations: int = 0
    pass_rate: float = 0.0
    common_errors: Dict[str, int] = field(default_factory=dict)
    avg_duration_ms: float = 0.0


class ParamValidator:
    # 安全敏感参数检测规则
    PATH_TRAVERSAL_PATTERN = re.compile(r'\.\./|\.\.\\')
    COMMAND_INJECTION_PATTERN = re.compile(r'[;&|`$()]')
    SQL_INJECTION_PATTERN = re.compile(r'(?i)(drop\s+table|union\s+select|--|/\*)')
    XSS_PATTERN = re.compile(r'(?i)(<script|javascript:)')
    
    STATS_REPORT_INTERVAL_SEC = 60
    DEDUP_CACHE_TTL_SEC = 5

    def __init__(self):
        self.module_id = "ag-mcc-05"
        self.module_name = "工具参数校验器"
        self.version = "V1.0"

        self.state = ValidatorState.WAITING_REQUEST
        self._total_validations: int = 0
        self._passed_count: int = 0
        self._total_duration: float = 0.0
        self._error_distribution: Dict[str, int] = {}
        self._dedup_cache: Dict[str, Tuple[ValidationResult, float]] = {}
        self._last_stats_time: float = time.time()
        self._pending_logs: List[Dict[str, Any]] = []

        # 回调注入
        self._query_validation_request = None
        self._query_param_template = None

        self._publish_validation_result = None
        self._publish_statistics = None
        self._publish_event_log = None

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ========== 回调注入 ==========
    def set_validation_request_query(self, callback: Callable[[], Optional[ParamValidationRequest]]):
        self._query_validation_request = callback

    def set_param_template_query(self, callback: Callable[[str], Optional[List[ParamTemplate]]]):
        self._query_param_template = callback

    def set_validation_result_publisher(self, callback: Callable[[ValidationResult], None]):
        self._publish_validation_result = callback

    def set_statistics_publisher(self, callback: Callable[[ValidationStatistics], None]):
        self._publish_statistics = callback

    def set_event_log_publisher(self, callback: Callable[[Dict[str, Any]], None]):
        self._publish_event_log = callback

    # ========== 主循环 ==========
    def run_validation_cycle(self) -> Optional[ValidationResult]:
        now = time.time()

        if self.state == ValidatorState.SYSTEM_PAUSED:
            return None

        if now - self._last_stats_time >= self.STATS_REPORT_INTERVAL_SEC:
            self._publish_statistics_internal()
            self._last_stats_time = now

        request = self._query_validation_request() if self._query_validation_request else None
        if request is None:
            return None

        self.state = ValidatorState.VALIDATING
        start_time = time.time()

        templates = self._query_param_template(request.tool_name) if self._query_param_template else None
        if templates is None:
            result = ValidationResult(
                command_id=request.command_id,
                passed=False,
                errors=[ValidationError(param_name="", error_code="TEMPLATE_NOT_FOUND", reason="工具未注册或参数模板不存在")]
            )
        else:
            result = self._validate(request, templates)

        elapsed = (time.time() - start_time) * 1000
        result.validation_duration_ms = elapsed

        self._total_validations += 1
        if result.passed:
            self._passed_count += 1
        self._total_duration += elapsed

        for err in result.errors:
            self._error_distribution[err.error_code] = self._error_distribution.get(err.error_code, 0) + 1

        self.state = ValidatorState.VALIDATED

        if self._publish_validation_result:
            self._publish_validation_result(result)

        for err in result.errors:
            if err.error_code == "SECURITY_ERROR":
                self._log_event("SECURITY_VIOLATION", {
                    "command_id": request.command_id,
                    "tool_name": request.tool_name,
                    "param_name": err.param_name,
                    "reason": err.reason
                })

        self.state = ValidatorState.WAITING_REQUEST
        return result

    # ========== 核心校验 ==========
    def _validate(self, request: ParamValidationRequest, templates: List[ParamTemplate]) -> ValidationResult:
        errors = []
        corrections = []
        params = request.parameters
        strictness = request.strictness
        template_map = {t.param_name: t for t in templates}

        # 必填参数检查（所有严格度）
        for template in templates:
            if template.required and template.param_name not in params:
                errors.append(ValidationError(
                    param_name=template.param_name,
                    error_code="MISSING_PARAM",
                    reason="必填参数缺失"
                ))
                corrections.append(f"请提供参数: {template.param_name}")

        # 宽松模式仅检查必填
        if strictness == Strictness.LOOSE:
            return ValidationResult(
                command_id=request.command_id,
                passed=len(errors) == 0,
                errors=errors,
                corrections=corrections
            )

        # 逐参数校验
        for param_name, param_value in params.items():
            template = template_map.get(param_name)
            if template is None:
                if strictness == Strictness.STRICT:
                    errors.append(ValidationError(
                        param_name=param_name,
                        error_code="UNKNOWN_PARAM",
                        reason="未定义的参数"
                    ))
                continue

            # 类型匹配检查
            if not self._check_type(param_value, template.param_type):
                errors.append(ValidationError(
                    param_name=param_name,
                    error_code="TYPE_MISMATCH",
                    reason=f"期望类型={template.param_type}, 实际类型={type(param_value).__name__}"
                ))
                corrections.append(f"参数 {param_name} 应为 {template.param_type} 类型")
                continue

            # 格式正则检查
            if template.format_regex:
                if isinstance(param_value, str) and not re.match(template.format_regex, param_value):
                    errors.append(ValidationError(
                        param_name=param_name,
                        error_code="FORMAT_ERROR",
                        reason="格式不符合要求"
                    ))

            # 取值范围检查
            if template.allowed_range:
                if "enum" in template.allowed_range:
                    if param_value not in template.allowed_range["enum"]:
                        errors.append(ValidationError(
                            param_name=param_name,
                            error_code="RANGE_ERROR",
                            reason=f"值不在允许范围内: {template.allowed_range['enum']}"
                        ))
                else:
                    if "min" in template.allowed_range and param_value < template.allowed_range["min"]:
                        errors.append(ValidationError(
                            param_name=param_name,
                            error_code="RANGE_ERROR",
                            reason=f"值小于最小值 {template.allowed_range['min']}"
                        ))
                    if "max" in template.allowed_range and param_value > template.allowed_range["max"]:
                        errors.append(ValidationError(
                            param_name=param_name,
                            error_code="RANGE_ERROR",
                            reason=f"值大于最大值 {template.allowed_range['max']}"
                        ))

            # 安全敏感参数检查
            if template.security_sensitive:
                security_error = self._check_security(param_name, param_value)
                if security_error:
                    errors.append(security_error)

        # 依赖关系检查（修复：严格模式专属）
        if strictness == Strictness.STRICT:
            for template in templates:
                if template.dependencies and template.param_name in params:
                    dep_errors = self._check_dependencies(template, params, template_map)
                    errors.extend(dep_errors)

        return ValidationResult(
            command_id=request.command_id,
            passed=len(errors) == 0,
            errors=errors,
            corrections=corrections
        )

    def _check_dependencies(self, template: ParamTemplate, params: Dict[str, Any], template_map: Dict[str, ParamTemplate]) -> List[ValidationError]:
        """检查参数间的依赖关系"""
        errors = []
        current_value = params.get(template.param_name)

        for condition_value, required_params in template.dependencies.items():
            # 条件值匹配
            condition_met = False
            if isinstance(condition_value, list):
                condition_met = str(current_value) in [str(v) for v in condition_value]
            else:
                condition_met = str(current_value) == str(condition_value)

            if condition_met:
                # 检查依赖参数是否存在
                if isinstance(required_params, list):
                    for dep_param in required_params:
                        if dep_param not in params:
                            errors.append(ValidationError(
                                param_name=dep_param,
                                error_code="DEPENDENCY_ERROR",
                                reason=f"当 {template.param_name}={current_value} 时，参数 {dep_param} 为必填"
                            ))
                elif isinstance(required_params, dict):
                    for dep_param, dep_rule in required_params.items():
                        if dep_param not in params:
                            errors.append(ValidationError(
                                param_name=dep_param,
                                error_code="DEPENDENCY_ERROR",
                                reason=f"当 {template.param_name}={current_value} 时，参数 {dep_param} 为必填"
                            ))
                        elif "equals" in dep_rule and params[dep_param] != dep_rule["equals"]:
                            errors.append(ValidationError(
                                param_name=dep_param,
                                error_code="DEPENDENCY_ERROR",
                                reason=f"当 {template.param_name}={current_value} 时，参数 {dep_param} 必须等于 {dep_rule['equals']}"
                            ))
        return errors

    # ========== 类型检查 ==========
    def _check_type(self, value: Any, expected_type: str) -> bool:
        # 修复：bool 不应被 int 类型接受
        if expected_type == "int" and isinstance(value, bool):
            return False

        type_map = {
            "string": str,
            "int": int,
            "float": (int, float),
            "bool": bool,
            "array": list,
            "object": dict,
        }
        expected = type_map.get(expected_type)
        if expected is None:
            return True
        if isinstance(expected, tuple):
            return isinstance(value, expected)
        return isinstance(value, expected)

    # ========== 安全检查 ==========
    def _check_security(self, param_name: str, param_value: Any) -> Optional[ValidationError]:
        if not isinstance(param_value, str):
            return None

        name_lower = param_name.lower()

        if any(kw in name_lower for kw in ("path", "file", "dir")):
            if self.PATH_TRAVERSAL_PATTERN.search(param_value):
                return ValidationError(
                    param_name=param_name,
                    error_code="SECURITY_ERROR",
                    reason="检测到路径穿越攻击特征"
                )

        if any(kw in name_lower for kw in ("command", "cmd", "exec")):
            if self.COMMAND_INJECTION_PATTERN.search(param_value):
                return ValidationError(
                    param_name=param_name,
                    error_code="SECURITY_ERROR",
                    reason="检测到命令注入特征"
                )

        if "url" in name_lower:
            if not param_value.startswith("https://"):
                return ValidationError(
                    param_name=param_name,
                    error_code="SECURITY_ERROR",
                    reason="仅允许 HTTPS 协议的 URL"
                )

        if any(kw in name_lower for kw in ("sql", "query", "db")):
            if self.SQL_INJECTION_PATTERN.search(param_value):
                return ValidationError(
                    param_name=param_name,
                    error_code="SECURITY_ERROR",
                    reason="检测到 SQL 注入特征"
                )

        return None

    # ========== 辅助 ==========
    def _publish_statistics_internal(self):
        if self._publish_statistics:
            rate = self._passed_count / max(self._total_validations, 1)
            avg = self._total_duration / max(self._total_validations, 1)
            self._publish_statistics(ValidationStatistics(
                state=self.state,
                today_validations=self._total_validations,
                pass_rate=round(rate, 3),
                common_errors=self._error_distribution.copy(),
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
    print("  Agent-mcc-exec 工具参数校验器 (ag-mcc-05) 演示")
    print("=" * 70)

    validator = ParamValidator()
    validator.set_param_template_query(lambda tool_name: [
        ParamTemplate(param_name="city", param_type="string", required=True),
        ParamTemplate(param_name="days", param_type="int", required=False, allowed_range={"min": 1, "max": 7}),
        ParamTemplate(param_name="format", param_type="string", required=False, allowed_range={"enum": ["json", "xml"]}),
    ])

    print_separator("STEP 1: 参数完全合规")
    validator.set_validation_request_query(lambda: ParamValidationRequest(
        command_id="CMD-001", tool_name="weather_api", tool_type="API",
        parameters={"city": "北京", "days": 3, "format": "json"},
        strictness=Strictness.STANDARD
    ))
    result = validator.run_validation_cycle()
    if result:
        print(f"  校验结果: {'通过' if result.passed else '失败'}")

    print_separator("STEP 2: 严格模式依赖关系检查")
    validator.set_param_template_query(lambda tool_name: [
        ParamTemplate(param_name="operation", param_type="string", required=True,
                      dependencies={"delete": ["confirm_token"]}),
        ParamTemplate(param_name="confirm_token", param_type="string", required=False),
    ])
    validator.set_validation_request_query(lambda: ParamValidationRequest(
        command_id="CMD-004", tool_name="file_op", tool_type="FILE",
        parameters={"operation": "delete"},
        strictness=Strictness.STRICT
    ))
    result = validator.run_validation_cycle()
    if result:
        print(f"  校验结果: {'通过' if result.passed else '失败'}")
        for e in result.errors:
            print(f"    - {e.param_name}: {e.error_code} - {e.reason}")

    print("\n✅ 工具参数校验器演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("ag-mcc-05 工具参数校验器 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        def setup_validator():
            v = ParamValidator()
            v.set_param_template_query(lambda tool_name: [
                ParamTemplate(param_name="city", param_type="string", required=True),
                ParamTemplate(param_name="days", param_type="int", required=False, allowed_range={"min": 1, "max": 7}),
                ParamTemplate(param_name="file_path", param_type="string", required=True, security_sensitive=True),
                ParamTemplate(param_name="operation", param_type="string", required=True,
                              dependencies={"delete": ["confirm_token"]}),
                ParamTemplate(param_name="confirm_token", param_type="string", required=False),
            ])
            return v

        # TC-MCC-05-01: 参数完全合规
        print("\n[TC-MCC-05-01] 参数完全合规")
        try:
            v = setup_validator()
            v.set_validation_request_query(lambda: ParamValidationRequest(
                command_id="T01", tool_name="weather_api", tool_type="API",
                parameters={"city": "北京", "days": 3}, strictness=Strictness.STANDARD
            ))
            result = v.run_validation_cycle()
            assert result is not None and result.passed
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-05-02: 缺少必填参数
        print("\n[TC-MCC-05-02] 缺少必填参数")
        try:
            v = setup_validator()
            v.set_validation_request_query(lambda: ParamValidationRequest(
                command_id="T02", tool_name="weather_api", tool_type="API",
                parameters={"days": 3}, strictness=Strictness.STANDARD
            ))
            result = v.run_validation_cycle()
            assert result is not None and not result.passed
            assert any(e.error_code == "MISSING_PARAM" for e in result.errors)
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-05-03: 取值范围超限
        print("\n[TC-MCC-05-03] 取值范围超限")
        try:
            v = setup_validator()
            v.set_validation_request_query(lambda: ParamValidationRequest(
                command_id="T03", tool_name="weather_api", tool_type="API",
                parameters={"city": "北京", "days": 10}, strictness=Strictness.STANDARD
            ))
            result = v.run_validation_cycle()
            assert result is not None and not result.passed
            assert any(e.error_code == "RANGE_ERROR" for e in result.errors)
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-05-04: 安全敏感参数检测
        print("\n[TC-MCC-05-04] 安全敏感参数检测（路径穿越）")
        try:
            v = setup_validator()
            v.set_validation_request_query(lambda: ParamValidationRequest(
                command_id="T04", tool_name="file_read", tool_type="FILE",
                parameters={"file_path": "../../../etc/passwd"}, strictness=Strictness.STANDARD
            ))
            result = v.run_validation_cycle()
            assert result is not None and not result.passed
            assert any(e.error_code == "SECURITY_ERROR" for e in result.errors)
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-05-05: 严格模式依赖关系检查（修复验证）
        print("\n[TC-MCC-05-05] 严格模式依赖关系检查")
        try:
            v = setup_validator()
            v.set_validation_request_query(lambda: ParamValidationRequest(
                command_id="T05", tool_name="file_op", tool_type="FILE",
                parameters={"operation": "delete"},
                strictness=Strictness.STRICT
            ))
            result = v.run_validation_cycle()
            assert result is not None and not result.passed
            assert any(e.error_code == "DEPENDENCY_ERROR" for e in result.errors)
            print("   ✅ PASS")
            passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}")
            failed += 1

        # TC-MCC-05-06: bool 不被 int 误接受（修复验证）
        print("\n[TC-MCC-05-06] bool 不被 int 误接受")
        try:
            v = ParamValidator()
            assert v._check_type(True, "int") == False
            assert v._check_type(5, "int") == True
            assert v._check_type(False, "bool") == True
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