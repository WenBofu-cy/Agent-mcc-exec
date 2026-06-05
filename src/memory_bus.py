#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MemoryBus 全局记忆总线
Agent 内部模块间通信的唯一中枢

版本：V1.0
原创提出者：文波福
开源协议：CC BY-NC 4.0

职责：
  - 作为各中枢模块间消息路由的唯一中转站
  - 每个模块通过 publish(topic, data) 发布消息，通过 subscribe(topic, callback) 订阅消息
  - 支持同步和异步两种投递模式
  - 维护模块注册表，支持按模块 ID 点对点路由
"""

from typing import Dict, List, Callable, Any, Optional
from collections import defaultdict
from dataclasses import dataclass, field
import time
import uuid
import threading


@dataclass
class Message:
    message_id: str = ""
    topic: str = ""
    source_module: str = ""
    target_module: str = ""
    data: Any = None
    timestamp: float = field(default_factory=time.time)


class MemoryBus:
    def __init__(self):
        self._subscriptions: Dict[str, List[Callable]] = defaultdict(list)
        self._module_subscriptions: Dict[str, List[Callable]] = defaultdict(list)
        self._message_queue: List[Message] = []
        self._lock = threading.Lock()
        self._message_counter: int = 0
        self._pending_logs: List[Dict[str, Any]] = []

    def subscribe(self, topic: str, handler: Callable[[Message], None]):
        with self._lock:
            self._subscriptions[topic].append(handler)

    def subscribe_to_module(self, module_id: str, handler: Callable[[Message], None]):
        with self._lock:
            self._module_subscriptions[module_id].append(handler)

    def publish(self, topic: str, source_module: str, data: Any = None, target_module: str = ""):
        self._message_counter += 1
        message = Message(
            message_id=f"MSG-{self._message_counter:06d}",
            topic=topic,
            source_module=source_module,
            target_module=target_module,
            data=data
        )
        with self._lock:
            self._message_queue.append(message)

    def publish_to_module(self, target_module: str, event_type: str, source_module: str, data: Any = None):
        topic = f"{target_module}.{event_type}"
        self.publish(topic, source_module, data, target_module)

    def process_one(self) -> int:
        with self._lock:
            if not self._message_queue:
                return 0
            message = self._message_queue.pop(0)

        handlers = self._subscriptions.get(message.topic, [])
        for handler in handlers:
            try:
                handler(message)
            except Exception as e:
                self._log_error("topic_handler_error", str(e))

        if message.target_module:
            module_handlers = self._module_subscriptions.get(message.target_module, [])
            for handler in module_handlers:
                try:
                    handler(message)
                except Exception as e:
                    self._log_error("module_handler_error", str(e))

        return 1

    def process_all(self) -> int:
        total = 0
        while self.process_one():
            total += 1
        return total

    def process_batch(self, max_count: int = 50) -> int:
        total = 0
        for _ in range(max_count):
            if not self.process_one():
                break
            total += 1
        return total

    def pending_count(self) -> int:
        with self._lock:
            return len(self._message_queue)

    def _log_error(self, error_type: str, detail: str):
        self._pending_logs.append({
            "log_id": f"log-{uuid.uuid4().hex[:8]}",
            "event_type": error_type,
            "source_module": "MemoryBus",
            "details": {"error": detail},
            "timestamp": time.time()
        })

    def collect_pending_logs(self) -> List[Dict[str, Any]]:
        logs = self._pending_logs.copy()
        self._pending_logs.clear()
        return logs