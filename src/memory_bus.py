#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MemoryBus 全局记忆总线 + InternalBus 内部调度总线
适用于 Agent-mlnf-mem（51 模块）与 Agent-ecc-brain（12 模块）双项目

版本：V1.0
原创提出者：文波福
开源协议：CC BY-NC 4.0
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
PRIORITY_CRITICAL = "CRITICAL"
PRIORITY_HIGH = "HIGH"
PRIORITY_NORMAL = "NORMAL"
PRIORITY_LOW = "LOW"

PRIORITY_ORDER = {
    PRIORITY_CRITICAL: 0,
    PRIORITY_HIGH: 1,
    PRIORITY_NORMAL: 2,
    PRIORITY_LOW: 3,
}

MSG_ID_PREFIX = "MSG"
CORRELATION_PREFIX = "REQ"
MODULE_ID_PATTERN = re.compile(r"^ag-(mem|ecc|mcc)-\d{2}$")
DEFAULT_MSG_TTL = 30.0


@dataclass
class Message:
    message_id: str
    topic: str
    source_module: str
    target_module: str = ""
    data: Any = None
    timestamp: float = field(default_factory=time.time)
    correlation_id: str = ""
    priority: str = PRIORITY_NORMAL
    expire_at: float = 0.0

    def is_expired(self) -> bool:
        return self.expire_at > 0 and time.time() > self.expire_at


class InternalBus:
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

    def register_module(self, module_id: str):
        if not MODULE_ID_PATTERN.match(module_id):
            raise ValueError(f"模块 ID 格式非法: {module_id}")
        with self._lock:
            self._registered_modules.add(module_id)

    def is_module_registered(self, module_id: str) -> bool:
        with self._lock:
            return module_id in self._registered_modules

    def subscribe(self, topic: str, handler: Callable[[Message], None]):
        with self._lock:
            self._subscriptions[topic].append(handler)

    def subscribe_to_module(self, module_id: str, handler: Callable[[Message], None]):
        with self._lock:
            self._module_subscriptions[module_id].append(handler)

    def publish(
        self, topic: str, source_module: str, data: Any = None,
        target_module: str = "", priority: str = PRIORITY_NORMAL,
        correlation_id: str = "", ttl: float = DEFAULT_MSG_TTL
    ):
        if self._validate_modules:
            if not self.is_module_registered(source_module):
                raise ValueError(f"未注册的源模块: {source_module}")
            if target_module and not self.is_module_registered(target_module):
                raise ValueError(f"未注册的目标模块: {target_module}")

        msg = Message(
            message_id=f"{MSG_ID_PREFIX}-{uuid.uuid4().hex[:12]}",
            topic=topic, source_module=source_module,
            target_module=target_module, data=data, priority=priority,
            correlation_id=correlation_id or f"{CORRELATION_PREFIX}-{uuid.uuid4().hex[:8]}",
            expire_at=(time.time() + ttl) if ttl > 0 else 0.0,
        )
        self._message_queue.put((PRIORITY_ORDER.get(msg.priority, 2), msg.timestamp, msg))

    def publish_to_module(
        self, target_module: str, event_type: str, source_module: str,
        data: Any = None, priority: str = PRIORITY_NORMAL,
        correlation_id: str = "", ttl: float = DEFAULT_MSG_TTL
    ):
        self.publish(
            topic=f"{target_module}.{event_type}", source_module=source_module,
            data=data, target_module=target_module, priority=priority,
            correlation_id=correlation_id, ttl=ttl
        )

    def request(
        self, topic: str, source_module: str, data: Any = None,
        target_module: str = "", timeout_ms: float = 2000.0,
        priority: str = PRIORITY_NORMAL
    ) -> Optional[Message]:
        cid = f"{CORRELATION_PREFIX}-{uuid.uuid4().hex[:8]}"
        event = threading.Event()
        with self._lock:
            self._pending_requests[cid] = event
        self.publish(topic=topic, source_module=source_module, data=data,
                     target_module=target_module, priority=priority, correlation_id=cid)
        if event.wait(timeout=timeout_ms / 1000.0):
            with self._lock:
                resp = self._pending_responses.pop(cid, None)
                self._pending_requests.pop(cid, None)
            return resp
        else:
            with self._lock:
                self._pending_requests.pop(cid, None)
                self._pending_responses.pop(cid, None)
            return None

    def publish_reply(
        self, topic: str, source_module: str, data: Any,
        correlation_id: str, target_module: str = "",
        priority: str = PRIORITY_NORMAL
    ):
        msg = Message(
            message_id=f"{MSG_ID_PREFIX}-{uuid.uuid4().hex[:12]}",
            topic=topic, source_module=source_module,
            target_module=target_module, data=data,
            priority=priority, correlation_id=correlation_id,
        )
        with self._lock:
            if correlation_id in self._pending_requests:
                self._pending_responses[correlation_id] = msg
                self._pending_requests[correlation_id].set()

    def process_one(self) -> int:
        try:
            _, _, msg = self._message_queue.get(timeout=0)
        except Empty:
            return 0
        if msg.is_expired():
            return 1
        handlers = (
            self._module_subscriptions.get(msg.target_module, [])
            if msg.target_module else self._subscriptions.get(msg.topic, [])
        )
        for h in handlers:
            self._deliver(h, msg)
        return 1

    def _deliver(self, handler, msg):
        try:
            handler(msg)
        except Exception as e:
            self._pending_logs.append({
                "log_id": f"log-{uuid.uuid4().hex[:8]}",
                "event_type": "message_handler_error",
                "source_module": "InternalBus",
                "details": {"error": str(e), "message_id": msg.message_id,
                            "topic": msg.topic, "source_module": msg.source_module,
                            "target_module": msg.target_module},
                "timestamp": time.time(),
            })

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


class MemoryBus(InternalBus):
    """对外记忆总线（ECC ↔ MLNF 专用）"""
    pass


# ====================== CerebellumBus（ECC ↔ MCC 工具调用总线） ======================
CerebellumBus = MemoryBus  # 接口完全兼容，物理隔离实例