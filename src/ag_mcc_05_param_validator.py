#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块编号: ag-mcc-05
模块名称: 工具参数校验器
所属分区: 二、工具管理集群
版本: V1.0
原创提出者: 文波福
开源协议: CC BY-NC 4.0

核心职责:
    在工具调用指令下发至具体执行模块之前，对指令中携带的参数进行合法性校验。
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

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid
import re
import threading


class ValidatorState(Enum):
    WAITING_REQUEST = "WAITING_REQUEST"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    SYSTEM_PAUSED = "SYSTEM_PAUSED"


class Strictness(Enum):
    LOOSE = "宽松"
    STANDARD = "标准"
    STRICT = "严格"


@dataclass
class ParamValidationRequest:
    instruction_id: str = ""
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
    instruction_id: str = ""
    passed: bool = True
    errors: List[ValidationError] = field(default_factory=list)
    corrections: List[str] = field(default_factory=list)
    validation_duration_ms: float = 0.0


class ParamValidator:
    # 安全敏感参数检测规则
    PATH_TRAVERSAL_PATTERN = re.compile(r'\.\./|\.\.\\')
    COMMAND_INJECTION_PATTERN = re.compile(r'[;&|`$()]')
    SQL_INJECTION_PATTERN = re.compile(r'(?i)(drop\s+table|union\s+select|--|/\*)')
    XSS_PATTERN = re.compile(r'(?i)(<script|javascript:)')
    
    STATS_REPORT_INTERVAL_SEC = 60

    def __init__(self):
        self.module_id = "ag-mcc-05"
        self.module_name = "工具参数校验器"
        self.version = "V1.0"

        # 总线引用（由主入口注入）
        self.bus = None                 # InternalBus

        self.state = ValidatorState.WAITING_REQUEST
        self._lock = threading.Lock()
        self._total_validations: int = 0
        self._passed_count: int = 0
        self._total_duration: float = 0.0
        self._error_distribution: Dict[str, int] = {}
        self._last_stats_time: float = time.time()

        print(f"[{self.module_id}] {self.module_name} {self.version} 初始化完成")

    # ====================== 主循环（SPEC 定义的标准方法名） ======================
    def param_validator_main_loop(self):
        """执行一个主循环周期"""
        with self._lock:
            if self.state == ValidatorState.SYSTEM_PAUSED:
                return

        now = time.time()
        if now - self._last_stats_time >= self.STATS_REPORT_INTERVAL_SEC:
            self._publish_statistics()
            self._last_stats_time = now

    # ====================== 消息处理（InternalBus） ======================
    def handle_message(self, message):
        """处理来自 InternalBus 的消息"""
        if not self.bus:
            return

        data = message.data if message.data else {}
        topic = message.topic

        # 接收参数校验请求（来自 ag-mcc-01 或 ag-ecc-03）
        if topic == "ag-mcc-05.validation_request":
            request = ParamValidationRequest(
                instruction_id=data.get("instruction_id", ""),
                tool_name=data.get("tool_name", ""),
                tool_type=data.get("tool_type", ""),
                parameters=data.get("parameters", {}),
                strictness=Strictness(data.get("strictness", "标准")),
                requester_module=message.source_module
            )
            self._handle_validation(request)

        # 接收全局调度指令（来自 ag-mcc-01）
        elif topic == "ag-mcc-05.global_command":
            command = data.get("command", "")
            if command == "emergency_shutdown":
                self.emergency_shutdown()

    # ====================== 校验执行 ======================
    def _handle_validation(self, request: ParamValidationRequest):
        """执行参数校验并返回结果"""
        with self._lock:
            self.state = ValidatorState.VALIDATING

        start_time = time.time()

        # 从 ag-mcc-04 同步查询参数模板
        templates = self._fetch_param_template(request.tool_name)
        if templates is None:
            result = ValidationResult(
                instruction_id=request.instruction_id,
                passed=False,
                errors=[ValidationError(param_name="", error_code="TEMPLATE_NOT_FOUND", reason="工具未注册或参数模板不存在")]
            )
        else:
            result = self._validate(request, templates)

        elapsed = (time.time() - start_time) * 1000
        result.validation_duration_ms = elapsed

        # 更新统计
        with self._lock:
            self._total_validations += 1
            if result.passed:
                self._passed_count += 1
            self._total_duration += elapsed
            for err in result.errors:
                self._error_distribution[err.error_code] = self._error_distribution.get(err.error_code, 0) + 1
            self.state = ValidatorState.VALIDATED

        # 返回校验结果
        if self.bus:
            self.bus.publish_to_module(
                target_module=request.requester_module,
                event_type="validation_result",
                source_module=self.module_id,
                data={
                    "instruction_id": result.instruction_id,
                    "passed": result.passed,
                    "errors": [{"param_name": e.param_name, "error_code": e.error_code, "reason": e.reason} for e in result.errors],
                    "corrections": result.corrections,
                    "validation_duration_ms": result.validation_duration_ms
                }
            )

        # 安全事件记录
        for err in result.errors:
            if err.error_code == "SECURITY_ERROR":
                self._log_security_event(request.instruction_id, request.tool_name, err)

        with self._lock:
            self.state = ValidatorState.WAITING_REQUEST

    def _fetch_param_template(self, tool_name: str) -> Optional[List[ParamTemplate]]:
        """通过总线同步请求 ag-mcc-04 获取参数模板"""
        if not self.bus:
            return None

        # 使用同步请求-响应模式
        response = self.bus.request(
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

        if not response or not response.data:
            return None

        tools = response.data.get("tools", [])
        if not tools:
            return None

        # 解析参数模板
        tool = tools[0]
        param_template = tool.get("param_template", {})
        if not param_template:
            return []

        templates = []
        for param_name, param_def in param_template.items():
            template = ParamTemplate(
                param_name=param_name,
                param_type=param_def.get("type", "string"),
                required=param_def.get("required", False),
                default_value=param_def.get("default"),
                allowed_range=param_def.get("range"),
                format_regex=param_def.get("format"),
                dependencies=param_def.get("dependencies", {}),
                security_sensitive=param_def.get("security_sensitive", False)
            )
            templates.append(template)

        return templates

    # ========== 核心校验逻辑（保留原版所有业务逻辑） ==========
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
                instruction_id=request.instruction_id,
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

        # 依赖关系检查（严格模式专属）
        if strictness == Strictness.STRICT:
            for template in templates:
                if template.dependencies and template.param_name in params:
                    dep_errors = self._check_dependencies(template, params, template_map)
                    errors.extend(dep_errors)

        return ValidationResult(
            instruction_id=request.instruction_id,
            passed=len(errors) == 0,
            errors=errors,
            corrections=corrections
        )

    def _check_dependencies(self, template: ParamTemplate, params: Dict[str, Any], template_map: Dict[str, ParamTemplate]) -> List[ValidationError]:
        errors = []
        current_value = params.get(template.param_name)

        for condition_value, required_params in template.dependencies.items():
            condition_met = False
            if isinstance(condition_value, list):
                condition_met = str(current_value) in [str(v) for v in condition_value]
            else:
                condition_met = str(current_value) == str(condition_value)

            if condition_met:
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

    def _check_type(self, value: Any, expected_type: str) -> bool:
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

    def _check_security(self, param_name: str, param_value: Any) -> Optional[ValidationError]:
        if not isinstance(param_value, str):
            return None
        name_lower = param_name.lower()

        if any(kw in name_lower for kw in ("path", "file", "dir")):
            if self.PATH_TRAVERSAL_PATTERN.search(param_value):
                return ValidationError(param_name=param_name, error_code="SECURITY_ERROR", reason="检测到路径穿越攻击特征")

        if any(kw in name_lower for kw in ("command", "cmd", "exec")):
            if self.COMMAND_INJECTION_PATTERN.search(param_value):
                return ValidationError(param_name=param_name, error_code="SECURITY_ERROR", reason="检测到命令注入特征")

        if "url" in name_lower:
            if not param_value.startswith("https://"):
                return ValidationError(param_name=param_name, error_code="SECURITY_ERROR", reason="仅允许 HTTPS 协议的 URL")

        if any(kw in name_lower for kw in ("sql", "query", "db")):
            if self.SQL_INJECTION_PATTERN.search(param_value):
                return ValidationError(param_name=param_name, error_code="SECURITY_ERROR", reason="检测到 SQL 注入特征")

        return None

    # ====================== 统计与日志 ======================
    def _publish_statistics(self):
        if not self.bus:
            return
        with self._lock:
            rate = self._passed_count / max(self._total_validations, 1)
            avg = self._total_duration / max(self._total_validations, 1)
            self.bus.publish_to_module(
                target_module="ag-mcc-12",
                event_type="validation_statistics",
                source_module=self.module_id,
                data={
                    "state": self.state.value,
                    "today_validations": self._total_validations,
                    "pass_rate": round(rate, 3),
                    "common_errors": self._error_distribution.copy(),
                    "avg_duration_ms": round(avg, 2)
                }
            )

    def _log_security_event(self, instruction_id: str, tool_name: str, error: ValidationError):
        if not self.bus:
            return
        self.bus.publish(
            topic="ag-mcc-12.log_event",
            source_module=self.module_id,
            data={
                "log_id": f"log-{uuid.uuid4().hex[:8]}",
                "event_type": "SECURITY_VIOLATION",
                "source_module": self.module_id,
                "details": {
                    "instruction_id": instruction_id,
                    "tool_name": tool_name,
                    "param_name": error.param_name,
                    "reason": error.reason
                },
                "timestamp": time.time()
            }
        )

    def get_state(self) -> ValidatorState:
        with self._lock:
            return self.state

    def emergency_shutdown(self):
        with self._lock:
            self.state = ValidatorState.SYSTEM_PAUSED
        print(f"[{self.module_id}] 紧急熔断")

    def shutdown(self):
        with self._lock:
            self.state = ValidatorState.WAITING_REQUEST
        print(f"[{self.module_id}] 已安全关闭")


# ====================== 演示与测试 ======================
def demo_main():
    print("=" * 70)
    print("  ag-mcc-05 工具参数校验器 V1.0 演示")
    print("=" * 70)

    from memory_bus import InternalBus
    bus = InternalBus()
    bus.register_module("ag-mcc-05")
    bus.register_module("ag-mcc-04")

    validator = ParamValidator()
    validator.bus = bus
    bus.subscribe_to_module("ag-mcc-05", validator.handle_message)

    # 模拟 ag-mcc-04 的工具查询响应
    def handle_tool_query(msg):
        bus.publish_reply(
            topic="ag-mcc-04.tool_query_result",
            source_module="ag-mcc-04",
            data={
                "tools": [{
                    "tool_name": "weather_api",
                    "param_template": {
                        "city": {"type": "string", "required": True},
                        "days": {"type": "int", "required": False, "range": {"min": 1, "max": 7}},
                        "format": {"type": "string", "required": False, "range": {"enum": ["json", "xml"]}},
                    }
                }],
                "total_matched": 1
            },
            correlation_id=msg.correlation_id,
            target_module=msg.source_module
        )
    bus.subscribe_to_module("ag-mcc-04", handle_tool_query)

    print("\n[演示] 参数完全合规的校验请求")
    bus.publish_to_module("ag-mcc-05", "validation_request", "ag-mcc-01", {
        "instruction_id": "CMD-001",
        "tool_name": "weather_api",
        "tool_type": "API",
        "parameters": {"city": "北京", "days": 3, "format": "json"},
        "strictness": "标准"
    })
    bus.process_all()
    validator.param_validator_main_loop()

    print("\n[演示] 缺少必填参数")
    bus.publish_to_module("ag-mcc-05", "validation_request", "ag-mcc-01", {
        "instruction_id": "CMD-002",
        "tool_name": "weather_api",
        "tool_type": "API",
        "parameters": {"days": 3},
        "strictness": "标准"
    })
    bus.process_all()
    validator.param_validator_main_loop()

    print("\n✅ 演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("ag-mcc-05 工具参数校验器 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        def setup():
            from memory_bus import InternalBus
            bus = InternalBus()
            bus.register_module("ag-mcc-05")
            bus.register_module("ag-mcc-04")
            v = ParamValidator()
            v.bus = bus
            bus.subscribe_to_module("ag-mcc-05", v.handle_message)
            # 模拟工具查询响应
            def handle_tool_query(msg):
                bus.publish_reply(
                    topic="ag-mcc-04.tool_query_result",
                    source_module="ag-mcc-04",
                    data={
                        "tools": [{
                            "tool_name": "weather_api",
                            "param_template": {
                                "city": {"type": "string", "required": True},
                                "days": {"type": "int", "required": False, "range": {"min": 1, "max": 7}},
                                "file_path": {"type": "string", "required": True, "security_sensitive": True},
                                "operation": {"type": "string", "required": True,
                                              "dependencies": {"delete": ["confirm_token"]}},
                                "confirm_token": {"type": "string", "required": False},
                            }
                        }],
                        "total_matched": 1
                    },
                    correlation_id=msg.correlation_id,
                    target_module=msg.source_module
                )
            bus.subscribe_to_module("ag-mcc-04", handle_tool_query)
            return v, bus

        def run_validation(v, bus, params):
            bus.publish_to_module("ag-mcc-05", "validation_request", "ag-mcc-01", params)
            bus.process_all()
            v.param_validator_main_loop()

        # TC01: 参数完全合规
        print("\n[TC01] 参数完全合规")
        try:
            v, bus = setup()
            run_validation(v, bus, {"instruction_id": "T01", "tool_name": "weather_api", "parameters": {"city": "北京", "days": 3}, "strictness": "标准"})
            assert v._passed_count == 1
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC02: 缺少必填参数
        print("\n[TC02] 缺少必填参数")
        try:
            v, bus = setup()
            run_validation(v, bus, {"instruction_id": "T02", "tool_name": "weather_api", "parameters": {"days": 3}, "strictness": "标准"})
            assert v._passed_count == 0
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC03: 取值范围超限
        print("\n[TC03] 取值范围超限")
        try:
            v, bus = setup()
            run_validation(v, bus, {"instruction_id": "T03", "tool_name": "weather_api", "parameters": {"city": "北京", "days": 10}, "strictness": "标准"})
            assert v._passed_count == 0
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC04: 安全敏感参数检测
        print("\n[TC04] 安全敏感参数检测")
        try:
            v, bus = setup()
            run_validation(v, bus, {"instruction_id": "T04", "tool_name": "weather_api", "parameters": {"file_path": "../../../etc/passwd"}, "strictness": "标准"})
            assert v._passed_count == 0
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC05: 严格模式依赖关系检查
        print("\n[TC05] 严格模式依赖关系检查")
        try:
            v, bus = setup()
            run_validation(v, bus, {"instruction_id": "T05", "tool_name": "weather_api", "parameters": {"operation": "delete"}, "strictness": "严格"})
            assert v._passed_count == 0
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC06: bool 不被 int 误接受
        print("\n[TC06] bool 不被 int 误接受")
        try:
            v = ParamValidator()
            assert v._check_type(True, "int") == False
            assert v._check_type(5, "int") == True
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        print("\n" + "=" * 60)
        print(f"测试结果: {passed} PASS, {failed} FAIL")
        print("=" * 60)
    else:
        demo_main()