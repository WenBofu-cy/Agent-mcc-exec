#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
InternalBus + CerebellumBus 双总线
Agent-mcc-exec 行动执行层模块间通信中枢

版本：V1.0
原创提出者：文波福
开源协议：CC BY-NC 4.0

修改记录：
- V1.0: 最终稳定版，包含双总线架构、同步请求、优先级、TTL、模块注册校验、异常日志收集
"""

from typing import Dict, List, Callable, Any, Optional
from collections import defaultdict
from dataclasses import dataclass, field
import time
import uuid
import threading
import re
from queue import PriorityQueue, Empty


# ====================== 优先级常量 ======================
PRIORITY_CRITICAL = "CRITICAL"   # 最高优先级（熔断指令、安全关键操作）
PRIORITY_HIGH = "HIGH"           # 高优先级
PRIORITY_NORMAL = "NORMAL"       # 普通优先级
PRIORITY_LOW = "LOW"             # 低优先级

# 优先级 → 数字映射（数字越小优先级越高）
PRIORITY_ORDER = {
    PRIORITY_CRITICAL: 0,
    PRIORITY_HIGH: 1,
    PRIORITY_NORMAL: 2,
    PRIORITY_LOW: 3,
}

# 消息 ID 前缀
MSG_ID_PREFIX = "MSG"
CORRELATION_PREFIX = "REQ"

# 模块 ID 格式校验正则（支持 ag-ecc / ag-mem / ag-mcc）
MODULE_ID_PATTERN = re.compile(r"^ag-(ecc|mem|mcc)-\d{2}$")

# 默认消息 TTL（秒），超时未处理自动丢弃
DEFAULT_MSG_TTL = 30.0


@dataclass
class Message:
    """标准总线报文（对齐模块接口规格）"""
    message_id: str
    topic: str
    source_module: str
    target_module: str = ""
    data: Any = None
    timestamp: float = field(default_factory=time.time)
    correlation_id: str = ""
    priority: str = PRIORITY_NORMAL
    expire_at: float = 0.0          # 过期时间戳（秒），0 表示永不过期

    def is_expired(self) -> bool:
        """检查消息是否已过期"""
        return self.expire_at > 0 and time.time() > self.expire_at


class InternalBus:
    """
    MCC 内部调度总线（MCC 内部 12 个模块专用）
    
    特性：
    - 支持优先级投递（CRITICAL > HIGH > NORMAL > LOW）
    - 支持同步 request() 请求-响应模式（使用 correlation_id 关联）
    - 支持消息 TTL 超时丢弃
    - 支持模块注册校验
    - 异常处理器日志收集（对接 ag-mcc-12）
    """

    def __init__(self, validate_modules: bool = False):
        self._subscriptions: Dict[str, List[Callable[[Message], None]]] = defaultdict(list)
        self._module_subscriptions: Dict[str, List[Callable[[Message], None]]] = defaultdict(list)
        self._message_queue: PriorityQueue = PriorityQueue()
        self._lock = threading.Lock()
        self._validate_modules = validate_modules
        self._registered_modules: set = set()
        self._pending_logs: List[Dict[str, Any]] = []
        self._pending_requests: Dict[str, threading.Event] = {}
        self._pending_responses: Dict[str, Message] = {}

    # ====================== 模块注册 ======================
    def register_module(self, module_id: str):
        """注册模块 ID，自动校验格式"""
        if not MODULE_ID_PATTERN.match(module_id):
            raise ValueError(f"模块 ID 格式非法: {module_id}，必须为 ag-(ecc|mem|mcc)-NN")
        with self._lock:
            self._registered_modules.add(module_id)

    def is_module_registered(self, module_id: str) -> bool:
        with self._lock:
            return module_id in self._registered_modules

    # ====================== 订阅接口 ======================
    def subscribe(self, topic: str, handler: Callable[[Message], None]):
        with self._lock:
            self._subscriptions[topic].append(handler)

    def subscribe_to_module(self, module_id: str, handler: Callable[[Message], None]):
        with self._lock:
            self._module_subscriptions[module_id].append(handler)

    # ====================== 异步发布 ======================
    def publish(
        self,
        topic: str,
        source_module: str,
        data: Any = None,
        target_module: str = "",
        priority: str = PRIORITY_NORMAL,
        correlation_id: str = "",
        ttl: float = DEFAULT_MSG_TTL
    ):
        """异步发布消息"""
        if not topic or not source_module:
            raise ValueError("topic 和 source_module 不能为空")
        if self._validate_modules:
            if not self.is_module_registered(source_module):
                raise ValueError(f"未注册的源模块: {source_module}")
            if target_module and not self.is_module_registered(target_module):
                raise ValueError(f"未注册的目标模块: {target_module}")

        msg = Message(
            message_id=f"{MSG_ID_PREFIX}-{uuid.uuid4().hex[:12]}",
            topic=topic,
            source_module=source_module,
            target_module=target_module,
            data=data,
            priority=priority,
            correlation_id=correlation_id or f"{CORRELATION_PREFIX}-{uuid.uuid4().hex[:8]}",
            expire_at=(time.time() + ttl) if ttl > 0 else 0.0,
        )
        priority_num = PRIORITY_ORDER.get(msg.priority, 2)
        self._message_queue.put((priority_num, msg.timestamp, msg))

    def publish_to_module(
        self,
        target_module: str,
        event_type: str,
        source_module: str,
        data: Any = None,
        priority: str = PRIORITY_NORMAL,
        ttl: float = DEFAULT_MSG_TTL
    ):
        """点对点异步发布"""
        topic = f"{target_module}.{event_type}"
        self.publish(topic=topic, source_module=source_module, data=data,
                     target_module=target_module, priority=priority, ttl=ttl)

    # ====================== 同步请求 ======================
    def request(
        self,
        topic: str,
        source_module: str,
        data: Any = None,
        target_module: str = "",
        timeout_ms: float = 2000.0,
        priority: str = PRIORITY_NORMAL
    ) -> Optional[Message]:
        """
        同步请求-响应
        
        发送请求后阻塞等待，直到收到携带相同 correlation_id 的响应或超时。
        响应方需调用 publish_reply() 发送响应消息。
        """
        correlation_id = f"{CORRELATION_PREFIX}-{uuid.uuid4().hex[:8]}"
        event = threading.Event()

        with self._lock:
            self._pending_requests[correlation_id] = event

        self.publish(
            topic=topic,
            source_module=source_module,
            data=data,
            target_module=target_module,
            priority=priority,
            correlation_id=correlation_id,
        )

        if event.wait(timeout=timeout_ms / 1000.0):
            with self._lock:
                response = self._pending_responses.pop(correlation_id, None)
                self._pending_requests.pop(correlation_id, None)
            return response
        else:
            with self._lock:
                self._pending_requests.pop(correlation_id, None)
                self._pending_responses.pop(correlation_id, None)
            return None

    def publish_reply(
        self,
        topic: str,
        source_module: str,
        data: Any,
        correlation_id: str,
        target_module: str = "",
        priority: str = PRIORITY_NORMAL
    ):
        """发送同步请求的响应，correlation_id 必须与原始请求一致。"""
        msg = Message(
            message_id=f"{MSG_ID_PREFIX}-{uuid.uuid4().hex[:12]}",
            topic=topic,
            source_module=source_module,
            target_module=target_module,
            data=data,
            priority=priority,
            correlation_id=correlation_id,
        )

        with self._lock:
            if correlation_id in self._pending_requests:
                self._pending_responses[correlation_id] = msg
                self._pending_requests[correlation_id].set()

    # ====================== 消息处理 ======================
    def process_one(self) -> int:
        """处理队列中的下一条消息（按优先级）"""
        try:
            priority_num, timestamp, msg = self._message_queue.get(timeout=0)
        except Empty:
            return 0

        if msg.is_expired():
            return 1

        if msg.target_module:
            handlers = self._module_subscriptions.get(msg.target_module, [])
            for handler in handlers:
                self._deliver(handler, msg)
            return 1

        handlers = self._subscriptions.get(msg.topic, [])
        for handler in handlers:
            self._deliver(handler, msg)
        return 1

    def _deliver(self, handler: Callable[[Message], None], msg: Message):
        try:
            handler(msg)
        except Exception as e:
            log_entry = {
                "log_id": f"log-{uuid.uuid4().hex[:8]}",
                "event_type": "message_handler_error",
                "source_module": "InternalBus",
                "details": {
                    "error": str(e),
                    "message_id": msg.message_id,
                    "topic": msg.topic,
                    "source_module": msg.source_module,
                    "target_module": msg.target_module,
                },
                "timestamp": time.time(),
            }
            with self._lock:
                self._pending_logs.append(log_entry)

    def process_batch(self, max_count: int = 50) -> int:
        total = 0
        for _ in range(max_count):
            if self.process_one() == 0:
                break
            total += 1
        return total

    def process_all(self) -> int:
        total = 0
        while self.process_one():
            total += 1
        return total

    # ====================== 查询与工具 ======================
    def pending_count(self) -> int:
        return self._message_queue.qsize()

    def clear_queue(self):
        with self._lock:
            self._message_queue = PriorityQueue()

    def collect_pending_logs(self) -> List[Dict[str, Any]]:
        with self._lock:
            logs = self._pending_logs.copy()
            self._pending_logs.clear()
        return logs


# ====================== CerebellumBus（对外总线） ======================
class CerebellumBus:
    """
    对外小脑总线（ECC ↔ MCC 专用）
    
    仅用于 ECC 认知大脑与 MCC 行动执行层之间的跨系统通信。
    内部通信请使用 InternalBus。
    """

    def __init__(self, validate_modules: bool = False):
        self._subscriptions: Dict[str, List[Callable[[Message], None]]] = defaultdict(list)
        self._module_subscriptions: Dict[str, List[Callable[[Message], None]]] = defaultdict(list)
        self._message_queue: PriorityQueue = PriorityQueue()
        self._lock = threading.Lock()
        self._validate_modules = validate_modules
        self._registered_modules: set = set()
        self._pending_logs: List[Dict[str, Any]] = []

    def register_module(self, module_id: str):
        if not MODULE_ID_PATTERN.match(module_id):
            raise ValueError(f"模块 ID 格式非法: {module_id}，必须为 ag-(ecc|mem|mcc)-NN")
        with self._lock:
            self._registered_modules.add(module_id)

    def subscribe(self, topic: str, handler: Callable[[Message], None]):
        with self._lock:
            self._subscriptions[topic].append(handler)

    def subscribe_to_module(self, module_id: str, handler: Callable[[Message], None]):
        with self._lock:
            self._module_subscriptions[module_id].append(handler)

    def publish(
        self,
        topic: str,
        source_module: str,
        data: Any = None,
        target_module: str = "",
        priority: str = PRIORITY_NORMAL,
        correlation_id: str = "",
        ttl: float = DEFAULT_MSG_TTL
    ):
        if not topic or not source_module:
            raise ValueError("topic 和 source_module 不能为空")
        if self._validate_modules:
            if not self.is_module_registered(source_module):
                raise ValueError(f"未注册的源模块: {source_module}")
            if target_module and not self.is_module_registered(target_module):
                raise ValueError(f"未注册的目标模块: {target_module}")

        msg = Message(
            message_id=f"{MSG_ID_PREFIX}-{uuid.uuid4().hex[:12]}",
            topic=topic,
            source_module=source_module,
            target_module=target_module,
            data=data,
            priority=priority,
            correlation_id=correlation_id or f"{CORRELATION_PREFIX}-{uuid.uuid4().hex[:8]}",
            expire_at=(time.time() + ttl) if ttl > 0 else 0.0,
        )
        priority_num = PRIORITY_ORDER.get(msg.priority, 2)
        self._message_queue.put((priority_num, msg.timestamp, msg))

    def publish_to_module(
        self,
        target_module: str,
        event_type: str,
        source_module: str,
        data: Any = None,
        priority: str = PRIORITY_NORMAL,
        ttl: float = DEFAULT_MSG_TTL
    ):
        topic = f"{target_module}.{event_type}"
        self.publish(topic=topic, source_module=source_module, data=data,
                     target_module=target_module, priority=priority, ttl=ttl)

    def is_module_registered(self, module_id: str) -> bool:
        with self._lock:
            return module_id in self._registered_modules

    def process_one(self) -> int:
        try:
            priority_num, timestamp, msg = self._message_queue.get(timeout=0)
        except Empty:
            return 0
        if msg.is_expired():
            return 1
        if msg.target_module:
            handlers = self._module_subscriptions.get(msg.target_module, [])
        else:
            handlers = self._subscriptions.get(msg.topic, [])
        for handler in handlers:
            self._deliver(handler, msg)
        return 1

    def _deliver(self, handler, msg):
        try:
            handler(msg)
        except Exception as e:
            log_entry = {
                "log_id": f"log-{uuid.uuid4().hex[:8]}",
                "event_type": "message_handler_error",
                "source_module": "CerebellumBus",
                "details": {"error": str(e), "message_id": msg.message_id, "topic": msg.topic},
                "timestamp": time.time(),
            }
            with self._lock:
                self._pending_logs.append(log_entry)

    def process_batch(self, max_count: int = 50) -> int:
        total = 0
        for _ in range(max_count):
            if self.process_one() == 0:
                break
            total += 1
        return total

    def process_all(self) -> int:
        total = 0
        while self.process_one():
            total += 1
        return total

    def pending_count(self) -> int:
        return self._message_queue.qsize()

    def clear_queue(self):
        with self._lock:
            self._message_queue = PriorityQueue()

    def collect_pending_logs(self) -> List[Dict[str, Any]]:
        with self._lock:
            logs = self._pending_logs.copy()
            self._pending_logs.clear()
        return logs


# ========== 集成演示 ==========
def demo_main():
    print("=" * 60)
    print("  InternalBus + CerebellumBus 双总线 V1.0 演示")
    print("=" * 60)

    internal = InternalBus()
    internal.register_module("ag-mcc-01")
    internal.register_module("ag-mcc-02")

    external = CerebellumBus()
    external.register_module("ag-mcc-01")
    external.register_module("ag-ecc-12")

    def sync_handler(msg: Message):
        print(f"  [同步] ag-mcc-02 收到: {msg.topic}, data={msg.data}")
        internal.publish_reply(
            topic="ag-mcc-02.response",
            source_module="ag-mcc-02",
            data={"status": "ok", "result": "tool_executed"},
            correlation_id=msg.correlation_id,
            target_module=msg.source_module,
        )

    internal.subscribe_to_module("ag-mcc-02", sync_handler)

    print("\n  发起同步请求...")
    response = internal.request(
        topic="ag-mcc-02.tool_call",
        source_module="ag-mcc-01",
        data={"tool": "weather_api", "params": {"city": "Beijing"}},
        target_module="ag-mcc-02",
        timeout_ms=2000,
    )
    if response:
        print(f"  收到响应: {response.data}")
    else:
        print("  请求超时")

    received = []
    external.subscribe("ag-mcc-01.execute_command", lambda msg: received.append(msg))
    external.publish("ag-mcc-01.execute_command", "ag-ecc-12", {"command": "tool_call", "target": "weather_api"})
    external.process_all()
    print(f"\n  外部总线处理: {len(received)} 条消息")
    print("\n✅ 双总线 V1.0 演示完成")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("=" * 60)
        print("双总线 V1.0 单元测试")
        print("=" * 60)
        passed, failed = 0, 0

        # TC-01
        print("\n[TC-01] CerebellumBus 基本发布订阅")
        try:
            bus = CerebellumBus()
            received = []
            bus.subscribe("ag-mcc-01.test", lambda msg: received.append(msg))
            bus.publish("ag-mcc-01.test", "ag-ecc-12", {"key": "value"})
            bus.process_all()
            assert len(received) == 1
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC-02
        print("\n[TC-02] InternalBus 同步请求")
        try:
            bus = InternalBus()
            bus.register_module("ag-mcc-01")
            bus.register_module("ag-mcc-02")
            def handler(msg):
                bus.publish_reply("resp", "ag-mcc-02", {"result": 42}, msg.correlation_id, msg.source_module)
            bus.subscribe_to_module("ag-mcc-02", handler)
            resp = bus.request("ag-mcc-02.query", "ag-mcc-01", {}, "ag-mcc-02", timeout_ms=2000)
            assert resp is not None and resp.data == {"result": 42}
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC-03
        print("\n[TC-03] 同步请求超时")
        try:
            bus = InternalBus()
            bus.register_module("ag-mcc-01")
            bus.register_module("ag-mcc-02")
            resp = bus.request("ag-mcc-02.query", "ag-mcc-01", {}, "ag-mcc-02", timeout_ms=100)
            assert resp is None
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC-04
        print("\n[TC-04] CRITICAL 优先级优先投递")
        try:
            bus = InternalBus()
            bus.register_module("ag-mcc-01")
            order = []
            bus.subscribe("test.priority", lambda msg: order.append(msg.data["n"]))
            bus.publish("test.priority", "ag-mcc-01", {"n": 3}, priority=PRIORITY_LOW)
            bus.publish("test.priority", "ag-mcc-01", {"n": 2}, priority=PRIORITY_NORMAL)
            bus.publish("test.priority", "ag-mcc-01", {"n": 1}, priority=PRIORITY_CRITICAL)
            bus.process_all()
            assert order == [1, 2, 3]
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC-05
        print("\n[TC-05] 模块 ID 格式校验（ag-mcc）")
        try:
            bus = InternalBus()
            bus.register_module("ag-mcc-01")
            try:
                bus.register_module("invalid_id")
                assert False
            except ValueError:
                pass
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC-06
        print("\n[TC-06] 消息 TTL 超时丢弃")
        try:
            bus = InternalBus()
            bus.register_module("ag-mcc-01")
            received = []
            bus.subscribe("test.ttl", lambda msg: received.append(msg))
            bus.publish("test.ttl", "ag-mcc-01", {"data": 1}, ttl=0.01)
            time.sleep(0.05)
            bus.process_all()
            assert len(received) == 0
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        # TC-07
        print("\n[TC-07] 双总线隔离")
        try:
            internal = InternalBus()
            external = CerebellumBus()
            internal.register_module("ag-mcc-01")
            external.register_module("ag-mcc-01")
            internal_recv, external_recv = [], []
            internal.subscribe("test.isolation", lambda msg: internal_recv.append(msg))
            external.subscribe("test.isolation", lambda msg: external_recv.append(msg))
            internal.publish("test.isolation", "ag-mcc-01", {"data": 1})
            internal.process_all()
            external.process_all()
            assert len(internal_recv) == 1 and len(external_recv) == 0
            print("   ✅ PASS"); passed += 1
        except Exception as e:
            print(f"   ❌ FAIL: {e}"); failed += 1

        print("\n" + "=" * 60)
        print(f"测试结果: {passed} PASS, {failed} FAIL")
        print("=" * 60)
    else:
        demo_main()