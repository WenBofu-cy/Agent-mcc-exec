# MemoryBus 总线报文规范 V1.1

**EM-Core Agent · 认知层与记忆层数据交互标准**

**版本**：V1.1 ｜ **日期**：2026-06-22
**适用中枢**：ECC（认知大脑） ↔ MLNF-Mem（记忆中枢）
**架构同源**：EM-Core HR人形机器人 / EM-Core AD自动驾驶


## 一、总线定位

MemoryBus 是 ECC 认知大脑与 MLNF-Mem 记忆中枢之间的唯一数据通道。所有记忆检索、经验写入、I值同步、会话锁管控、审计日志归档均通过本总线完成。

**核心约束：**

1. ECC-06（记忆交互单元）和 ECC-12（全局网关）为 MemoryBus 常规请求发起端。会话锁指令仅由 ECC-12 发起。MLNF-Mem 仅被动响应，不主动推送数据。崩溃恢复场景中 MLNF 可主动发起 SESSION_RECOVER、LOCK_ALIVE_QUERY、LOCK_ALIVE_LOST 等系统级请求。
2. 所有报文采用异步非阻塞模式。全部操作统一为请求-响应双报文模型，响应报文送达后 ECC 回复 MSG_ACK 确认。LOCK_ALIVE_QUERY 的 RESPONSE 免除 MSG_ACK。
3. 多会话报文基于 session_id 分片隔离处理。同一 session 内写入串行排队，跨 session 写入并行分片处理；锁相关指令全局快照隔离串行执行。
4. 会话锁指令优先级高于所有常规读写操作，即时处理，不进入排队队列。MLNF-01 预留 2-4 个专用线程处理锁指令，基础 2 个，队列深度超过 4 时临时扩展至 4 个，60s 无任务自动回收至 2 个。锁指令之间按 WAL 落盘顺序串行处理，独立 WAL 通道仅隔离其他操作类型。
5. 会话锁生命周期由 CerebellumBus 通过 LOCK/UNLOCK 指令统一管控。CerebellumBus 接收全会话 OK 回执后，ECC-12 方可通过 MemoryBus 下发 UNLOCK 指令。UNLOCK 执行前必须等待当前 session 内所有 COMMITTING 状态的事务完成或超时。跨设备 SESSION_SWITCH 携带 force_takeover:true 时，采用 CerebellumBus 定义的两阶段提交协议，ECC 同步下发强制 UNLOCK。
6. L3 风险等级任务申请记忆锁自动升级为 EXCLUSIVE 排他锁，禁止并行读取。EXCLUSIVE 锁不可自动降级，仅管理员 SESSION_FORCE_UNLOCK_ADMIN 或 24 小时硬超时可强制释放。LOCK_ALIVE_LOST 后 READ_ONLY 锁进入安全倒计时，EXCLUSIVE 锁保持持有状态，仅发送 LOCK_EXPIRE_WARNING 预警，不自动释放。
7. CerebellumBus 与 MemoryBus 共享同一密钥派生体系，两套总线的签名校验规则、防重放机制、洪水防护策略保持一致。跨总线报文须携带双重签名，MLNF 必须同时校验两个签名。MLNF 持有的 MCC 模块公钥列表由 ECC-12 在每次 KEY_ROTATION 完成后通过 KEY_SYNC 指令统一推送，首次启动时从设备安全飞地预置信任链加载。
8. 所有非同一进程内通信必须走 TLS 1.3 加密信道。


## 二、报文通用格式

### 2.1 通用报文头

```json
{
  "header": {
    "msg_id": "mem-20260621-143105-0001",
    "msg_type": "REQUEST | RESPONSE | ACK",
    "source": "ECC-06",
    "target": "MLNF-01",
    "session_id": "session_x",
    "timestamp": "2026-06-21T14:31:05.000Z",
    "ext_version": "1.1",
    "key_version": 1,
    "payload_hash": "",
    "body_hash": "",
    "chunk_group_id": "",
    "chunk_index": 0,
    "chunk_total": 0,
    "chunk_ttl": 10,
    "chunk_hash": "",
    "txn_group_id": "",
    "txn_seq": 0,
    "txn_total": 0,
    "original_source": "",
    "recovery_override": false,
    "replay": false,
    "restart_marker": false
  },
  "body": {}
}
```

### 2.2 头部字段定义

| 字段 | 类型 | 必填 | 说明 |
|------|------|:---:|------|
| msg_id | string | ✅ | 全局唯一报文ID，格式 `mem-{date}-{time}-{seq}` |
| msg_type | enum | ✅ | REQUEST / RESPONSE / ACK |
| source | string | ✅ | 发送方模块编号 |
| target | string | ✅ | 接收方模块编号 |
| session_id | string | ✅ | 会话隔离标识。跨总线 MSG_LIST_QUERY 可选填 |
| timestamp | ISO8601 | ✅ | 报文生成时间，须保留三位毫秒精度，偏差超 ±60s 直接丢弃 |
| ext_version | string | ✅ | 协议版本固定 "1.1"，主版本不同直接丢弃 |
| key_version | int | ✅ | 签名密钥版本号，用于密钥轮换过渡期双密钥共存校验 |
| payload_hash | string | 条件必填 | 非恢复类报文必填，body 完整内容的 SHA-256 哈希 |
| body_hash | string | 条件必填 | 恢复类报文必填，body 核心字段按字母序序列化后的 SHA-256 哈希 |
| chunk_group_id | string | 条件必填 | 分包报文必填，同组所有 chunk 共享同一 ID |
| chunk_index | int | 条件必填 | 分包报文必填，当前 chunk 序号 |
| chunk_total | int | 条件必填 | 分包报文必填，总 chunk 数量 |
| chunk_ttl | int | 条件必填 | 分包报文必填，重组超时秒数，默认 10s |
| chunk_hash | string | 条件必填 | 分包报文每个 chunk 独立 SHA-256 哈希 |
| txn_group_id | string | 条件必填 | 批量 WRITE 事务分组 ID |
| txn_seq | int | 条件必填 | 事务内分片序号 |
| txn_total | int | 条件必填 | 事务内分片总数，推荐 ≤10，最大 50 |
| original_source | string | 条件必填 | 跨总线 ACK 报文携带，保留发起方真实模块编号 |
| recovery_override | bool | 条件必填 | CRASH_RECOVERY_CHECK 锁指令携带，豁免限流 |
| replay | bool | 条件必填 | ECC 本地 WAL 重放锁指令时携带，MLNF 优先处理 |
| restart_marker | bool | 条件必填 | MLNF 重启后 SESSION_RECOVER 携带 |

### 2.3 标准响应报文

```json
{
  "header": {
    "msg_id": "mem-20260621-143105-0002",
    "msg_type": "RESPONSE",
    "source": "MLNF-01",
    "target": "ECC-06",
    "session_id": "session_x",
    "timestamp": "2026-06-21T14:31:05.015Z",
    "ext_version": "1.1",
    "key_version": 1,
    "payload_hash": "sha256_xxxxxx",
    "ref_msg_id": "mem-20260621-143105-0001"
  },
  "body": {
    "status": "OK | ERROR | LOCKED | NOT_FOUND | PERMISSION_DENIED | TIMEOUT | CONFLICT | DEVICE_SESSION_TRANSFERRED",
    "sign_mlnf01": "mlnf_sig_xxxxxx",
    "wal_status": "wal_committed | wal_pending",
    "data": {},
    "error": {
      "code": "MEM_LOCK_ACTIVE",
      "message": "当前会话只读锁活跃，写入操作被拦截",
      "offset_ms": 6500
    }
  }
}
```

### 2.4 MSG_ACK 确认报文

```json
{
  "header": {
    "msg_id": "mem-ack-xxxx",
    "msg_type": "ACK",
    "source": "ECC-06",
    "target": "MLNF-52",
    "session_id": "session_x",
    "timestamp": "2026-06-21T14:31:06.000Z",
    "ext_version": "1.1",
    "key_version": 1,
    "payload_hash": "",
    "original_source": "MCC-09"
  },
  "body": {
    "operation": "MSG_ACK",
    "ref_msg_id": "mem-20260621-143105-0001"
  }
}
```

### 2.5 响应状态码

| 状态码 | 说明 |
|--------|------|
| OK | 操作成功 |
| ERROR | 内部错误 |
| LOCKED | 会话只读锁活跃，写入/晋升被拦截 |
| NOT_FOUND | 查询的记忆条目不存在 |
| PERMISSION_DENIED | ECC-05 权限校验未通过 |
| TIMEOUT | 总线通信超时 |
| CONFLICT | I值更新版本冲突 |
| DEVICE_SESSION_TRANSFERRED | 会话已转移到其他设备 |


## 三、核心操作报文定义

### 3.1 记忆检索查询（ECC-06 → MLNF-52）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "ECC-06",
    "target": "MLNF-52"
  },
  "body": {
    "operation": "QUERY",
    "sign_ecc12": "e12_sig_xxxxxx",
    "query": {
      "funnel": "FUNNEL_ONE | FUNNEL_TWO",
      "funnel_id": "u_1 | f_3",
      "layer": "L1 | L2 | L3 | L4 | L5 | ALL",
      "match_type": "EXACT | SEMANTIC | RANGE",
      "conditions": {
        "task_type": "代码开发",
        "time_range": {"from": "2026-06-01", "to": "2026-06-21"},
        "i_value_min": 0.6,
        "max_results": 10,
        "include_history": false
      },
      "semantic_vector": []
    }
  }
}
```

**响应：**

```json
{
  "header": {
    "msg_type": "RESPONSE",
    "source": "MLNF-52",
    "target": "ECC-06",
    "session_id": "session_x",
    "timestamp": "2026-06-21T14:31:05.015Z"
  },
  "body": {
    "status": "OK",
    "sign_mlnf52": "mlnf_sig_xxxxxx",
    "data": {
      "results": [
        {
          "mem_id": "mem-f3-l4-20260618-0038",
          "funnel": "FUNNEL_TWO",
          "funnel_id": "f_3",
          "layer": "L4",
          "i_value": 0.85,
          "i_version": 6,
          "content": {},
          "match_score": 0.92,
          "timestamp": "2026-06-18T10:30:00Z"
        }
      ],
      "total_matched": 5,
      "has_more": false,
      "query_time_ms": 3
    }
  }
}
```

### 3.2 经验写入（ECC-12 → MLNF-01）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "ECC-12",
    "target": "MLNF-01"
  },
  "body": {
    "operation": "WRITE",
    "sign_ecc12": "e12_sig_xxxxxx",
    "funnel": "FUNNEL_TWO",
    "funnel_id": "f_3",
    "layer": "L1",
    "entry": {
      "task_type": "代码开发",
      "action_sequence": ["打开IDE", "定位第45行", "修改参数"],
      "result": "SUCCESS",
      "s_value": 0.3,
      "v_value": 0.9,
      "c_value": 0.5,
      "depends_on": [],
      "atomic_group": "",
      "timestamp": "2026-06-21T14:31:05.000Z",
      "source_session": "session_x"
    }
  }
}
```

**响应：**

```json
{
  "header": {
    "msg_type": "RESPONSE",
    "source": "MLNF-01",
    "target": "ECC-12",
    "session_id": "session_x",
    "timestamp": "2026-06-21T14:31:05.020Z"
  },
  "body": {
    "status": "OK | ERROR | LOCKED | PERMISSION_DENIED",
    "sign_mlnf01": "mlnf_sig_xxxxxx",
    "wal_status": "wal_committed | wal_pending",
    "data": {"mem_id": "mem-f3-l1-20260621-0001"},
    "error": null
  }
}
```

### 3.3 会话锁指令（ECC-12 → MLNF-01）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "ECC-12",
    "target": "MLNF-01"
  },
  "body": {
    "operation": "LOCK | UNLOCK | QUERY_LOCK_STATUS",
    "sign_ecc12": "e12_sig_xxxxxx",
    "session_id": "session_x",
    "lock_type": "READ_ONLY | EXCLUSIVE",
    "reason": "LLM_CALL_START | SESSION_ALL_TASKS_DONE | CRASH_RECOVERY_CHECK | L3_RISK_TASK",
    "expected_lock_state": {}
  }
}
```

**响应：**

```json
{
  "header": {
    "msg_type": "RESPONSE",
    "source": "MLNF-01",
    "target": "ECC-12",
    "session_id": "session_x",
    "timestamp": "2026-06-21T14:31:05.030Z"
  },
  "body": {
    "status": "OK",
    "sign_mlnf01": "mlnf_sig_xxxxxx",
    "data": {
      "session_id": "session_x",
      "lock_status": "LOCKED | UNLOCKED",
      "lock_type": "READ_ONLY | EXCLUSIVE",
      "locked_at": "2026-06-21T14:31:05.000Z",
      "lock_expire_at": "2026-06-22T14:31:05.000Z",
      "pending_writes": 3,
      "active_txn_count": 2,
      "unfinished_txn_count": 0
    }
  }
}
```

### 3.4 I值指标推送（ECC-06 → MLNF-30）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "ECC-06",
    "target": "MLNF-30"
  },
  "body": {
    "operation": "I_VALUE_UPDATE",
    "sign_ecc12": "e12_sig_xxxxxx",
    "mem_id": "mem-f3-l2-20260618-0038",
    "update_ts": "2026-06-21T14:31:05.000Z",
    "parent_version": 5,
    "metrics": {
      "s_value": 0.3,
      "v_value": 0.9,
      "c_value": 0.7
    },
    "source_module": "ECC-08",
    "trigger": "TASK_COMPLETED"
  }
}
```

**响应：**

```json
{
  "header": {
    "msg_type": "RESPONSE",
    "source": "MLNF-30",
    "target": "ECC-06",
    "session_id": "session_x",
    "timestamp": "2026-06-21T14:31:05.040Z"
  },
  "body": {
    "status": "OK | ERROR | CONFLICT",
    "sign_mlnf30": "mlnf_sig_xxxxxx",
    "data": {
      "mem_id": "mem-f3-l2-20260618-0038",
      "i_value_new": 0.72,
      "current_main_version": 6
    }
  }
}
```

### 3.5 审计日志归档（ECC-12 → MLNF-59）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "ECC-12",
    "target": "MLNF-59"
  },
  "body": {
    "operation": "AUDIT_LOG",
    "sign_ecc12": "e12_sig_xxxxxx",
    "log_type": "SECURITY_INTERCEPT | MEMORY_WRITE | LOCK_OPERATION | L3_BLOCK",
    "security_level": "CRITICAL | HIGH | MEDIUM | LOW",
    "session_id": "session_x",
    "entry": {
      "action": "MEMORY_WRITE_BLOCKED",
      "reason": "SESSION_LOCK_ACTIVE",
      "mem_id": "mem-f3-l2-20260618-0038",
      "timestamp": "2026-06-21T14:31:05.000Z"
    }
  }
}
```

**响应：**

```json
{
  "header": {
    "msg_type": "RESPONSE",
    "source": "MLNF-59",
    "target": "ECC-12",
    "session_id": "session_x",
    "timestamp": "2026-06-21T14:31:05.050Z"
  },
  "body": {
    "status": "OK",
    "wal_status": "wal_committed",
    "sign_mlnf59": "mlnf_sig_xxxxxx",
    "data": {"log_id": "audit-20260621-143105-0001"}
  }
}
```

### 3.6 会话恢复同步（MLNF → ECC-12）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "MLNF-01",
    "target": "ECC-12"
  },
  "body": {
    "operation": "SESSION_RECOVER",
    "body_hash": "sha256_xxxxxx",
    "sign_mlnf01": "mlnf_sig_xxxxxx",
    "restart_marker": false,
    "active_sessions": ["session_x", "session_y"],
    "unfinished_txns": [
      {
        "txn_group_id": "txn-session_x-001",
        "received_seqs": [0, 1],
        "total_seqs": 3,
        "lock_token_snapshot": "snap_xxxxxx",
        "device_id": "device_macbook_pro_01"
      }
    ],
    "active_locks": [
      {
        "session_id": "session_x",
        "lock_type": "READ_ONLY",
        "locked_at": "2026-06-21T14:31:05.000Z",
        "auto_released": false,
        "release_reason": ""
      }
    ],
    "last_wal_timestamp": "2026-06-21T14:30:00.000Z"
  }
}
```

### 3.7 心跳存活查询（MLNF → ECC-12）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "MLNF-01",
    "target": "ECC-12"
  },
  "body": {
    "operation": "LOCK_ALIVE_QUERY",
    "body_hash": "sha256_xxxxxx",
    "sign_mlnf01": "mlnf_sig_xxxxxx",
    "session_id": "session_x",
    "query_seq": 5
  }
}
```

**响应：**

```json
{
  "header": {
    "msg_type": "RESPONSE",
    "source": "ECC-12",
    "target": "MLNF-01",
    "session_id": "session_x",
    "timestamp": "2026-06-21T14:31:06.000Z"
  },
  "body": {
    "status": "OK",
    "sign_ecc12": "e12_sig_xxxxxx",
    "data": {
      "session_id": "session_x",
      "cerebellum_status": "CONNECTED | DEGRADED",
      "query_seq": 5
    }
  }
}
```

### 3.8 心跳断连通知（MLNF → ECC-12）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "MLNF-01",
    "target": "ECC-12"
  },
  "body": {
    "operation": "LOCK_ALIVE_LOST",
    "body_hash": "sha256_xxxxxx",
    "sign_mlnf01": "mlnf_sig_xxxxxx",
    "session_id": "session_x",
    "last_heartbeat_time": "2026-06-21T14:31:05.000Z",
    "consecutive_misses": 5,
    "cumulative_misses_120s": 9
  }
}
```

### 3.9 管理员强制解锁（ECC-12 → MLNF-01）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "ECC-12",
    "target": "MLNF-01"
  },
  "body": {
    "operation": "SESSION_FORCE_UNLOCK_ADMIN",
    "sign_ecc12": "e12_sig_xxxxxx",
    "admin_sign": "admin_rsa_sig_xxxxxx",
    "session_id": "session_x"
  }
}
```

### 3.10 依赖回滚预警（MLNF → ECC-12）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "MLNF-01",
    "target": "ECC-12"
  },
  "body": {
    "operation": "DEPENDENCY_ROLLBACK_WARNING",
    "body_hash": "sha256_xxxxxx",
    "sign_mlnf01": "mlnf_sig_xxxxxx",
    "session_id": "session_y",
    "txn_group_id": "txn-session_y-002",
    "failed_dependency": {
      "txn_group_id": "txn-session_x-001",
      "mem_ids": ["mem-f3-l1-20260621-0001"],
      "failure_reason": "TXN_ROLLBACK"
    },
    "action_timeout_ms": 5000
  }
}
```

### 3.11 跨总线精确列表查询（MCC-09 → MLNF-51，经 ECC-12 代理）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "MCC-09",
    "target": "MLNF-51",
    "session_id": "session_x",
    "msg_id": "mem-query-xxxx",
    "timestamp": "2026-06-21T15:20:10.000Z",
    "ext_version": "1.1",
    "key_version": 1,
    "body_hash": "sha256_xxxxxx"
  },
  "body": {
    "operation": "MSG_LIST_QUERY",
    "list_hash": "sha256_xxxxxx",
    "mcc_send_timestamp": "2026-06-21T15:20:10.000Z",
    "sign_mcc09": "mcc_sig_xxxxxx",
    "sign_ecc12_proxy": "e12_proxy_sig_xxxxxx"
  }
}
```

**响应：**

```json
{
  "header": {
    "msg_type": "RESPONSE",
    "source": "MLNF-51",
    "target": "MCC-09",
    "session_id": "session_x",
    "msg_id": "mem-list-xxxx",
    "timestamp": "2026-06-21T15:20:10.000Z",
    "ext_version": "1.1",
    "key_version": 1,
    "payload_hash": "sha256_xxxxxx"
  },
  "body": {
    "operation": "MSG_LIST_RESPONSE",
    "msg_ids": ["cere-xxx-0001"],
    "source_device_id": "device_macbook_pro_01",
    "list_generation_time": "2026-06-21T15:20:00.000Z",
    "list_coverage_end_time": "2026-06-21T15:19:50.000Z",
    "wal_flushed_up_to": "2026-06-21T15:19:55.000Z",
    "gap_range": {"start_time": "2026-06-21T15:19:50.000Z", "end_time": "2026-06-21T15:19:55.000Z"},
    "list_freshness": "LIVE | CACHED",
    "cache_time": "2026-06-21T15:18:00.000Z",
    "time_sync_offset_to_mcc_ms": 15,
    "network_delay_estimate_ms": 5,
    "confidence_level": "HIGH | MEDIUM | LOW",
    "sign_mlnf51": "mlnf_sig_xxxxxx"
  }
}
```

### 3.12 密钥同步（ECC-12 → MLNF-01）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "ECC-12",
    "target": "MLNF-01"
  },
  "body": {
    "operation": "KEY_SYNC",
    "sign_ecc12": "e12_sig_xxxxxx",
    "key_version": 2,
    "mcc_public_keys": {},
    "activation_time": "2026-06-21T16:00:00.000Z"
  }
}
```

### 3.13 锁到期预警（MLNF-01 → ECC-12）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "MLNF-01",
    "target": "ECC-12"
  },
  "body": {
    "operation": "LOCK_EXPIRE_WARNING",
    "body_hash": "sha256_xxxxxx",
    "sign_mlnf01": "mlnf_sig_xxxxxx",
    "session_id": "session_x",
    "lock_type": "EXCLUSIVE",
    "expire_at": "2026-06-22T14:31:05.000Z",
    "remaining_sec": 60
  }
}
```

### 3.14 会话接管通知（MLNF-01 → ECC-12）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "MLNF-01",
    "target": "ECC-12"
  },
  "body": {
    "operation": "SESSION_TAKEOVER_NOTIFY",
    "body_hash": "sha256_xxxxxx",
    "sign_mlnf01": "mlnf_sig_xxxxxx",
    "session_id": "session_x",
    "new_device_id": "device_macbook_pro_02",
    "transfer_time": "2026-06-21T15:25:00.000Z",
    "transition_id": "uuid_xxxxxx"
  }
}
```

### 3.15 设备会话转移（ECC-12 → MLNF-01）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "ECC-12",
    "target": "MLNF-01"
  },
  "body": {
    "operation": "SESSION_DEVICE_TRANSFER",
    "sign_ecc12": "e12_sig_xxxxxx",
    "session_id": "session_x",
    "old_device_id": "device_macbook_pro_01",
    "new_device_id": "device_macbook_pro_02",
    "transition_id": "uuid_xxxxxx",
    "list_acquired": true
  }
}
```

**响应：**

```json
{
  "header": {
    "msg_type": "RESPONSE",
    "source": "MLNF-01",
    "target": "ECC-12",
    "session_id": "session_x",
    "timestamp": "2026-06-21T15:25:05.000Z"
  },
  "body": {
    "status": "OK",
    "sign_mlnf01": "mlnf_sig_xxxxxx",
    "data": {
      "transition_id": "uuid_xxxxxx",
      "msg_ids": ["cere-xxx-0001"],
      "list_coverage_end_time": "2026-06-21T15:25:04.000Z",
      "gap_range": {"start_time": "2026-06-21T15:25:04.000Z", "end_time": "2026-06-21T15:25:04.500Z"}
    }
  }
}
```


## 四、错误码定义

### 4.1 故障码安全分级

| 安全等级 | 说明 | 审计留存时长 |
|----------|------|:---:|
| CRITICAL | 安全攻击/权限逃逸/签名伪造 | 永久（上限 1GB，超限归档压缩） |
| HIGH | 认证失败/令牌异常/洪水攻击 | 90 天 |
| MEDIUM | 资源超限/超时/任务失败 | 30 天 |
| LOW | 普通业务告警 | 7 天 |

### 4.2 错误码分类

| 错误码 | 安全等级 | 说明 |
|--------|:---:|------|
| MEM_LOCK_ACTIVE | MEDIUM | 会话只读锁活跃，写入/晋升被拦截 |
| MEM_QUOTA_EXCEEDED | MEDIUM | 全局存储配额已满 |
| MEM_LAYER_QUOTA_FULL | MEDIUM | 目标层级配额已满 |
| MEM_FUNNEL_NOT_FOUND | LOW | 目标子漏斗不存在 |
| MEM_ENTRY_CORRUPTED | HIGH | 记忆条目数据损坏 |
| MEM_PERMISSION_DENIED | HIGH | ECC-05 权限校验未通过 |
| MEM_BUS_TIMEOUT | MEDIUM | 总线通信超时 |
| MEM_SIGN_INVALID | CRITICAL | 报文签名校验失败 |
| MEM_VERSION_MISMATCH | HIGH | 协议主版本不匹配 |
| MEM_MSG_DUPLICATE | LOW | 重复报文 |
| MEM_PAYLOAD_OVERSIZE | MEDIUM | 请求报文 Payload 超限 |
| MEM_LOCK_EXPIRED | MEDIUM | 会话锁持有超时自动释放 |
| MEM_I_VALUE_STALE | LOW | I值更新版本冲突 |
| MEM_SESSION_FLOOD | HIGH | 单会话短时间 msg_id 请求超限 |
| MEM_TXN_TIMEOUT | MEDIUM | 事务超时未集齐全部分片 |
| MEM_LOCK_STORM | HIGH | 单会话锁指令超限 |
| MEM_WAL_QUOTA_EXCEEDED | HIGH | WAL 存储配额超限 |
| MEM_DEPENDENCY_CYCLE | HIGH | depends_on 声明存在循环依赖 |
| MEM_DEPENDENCY_FAILED | HIGH | 跨事务依赖对象已回滚或失败 |
| MEM_DEPENDENCY_CHAIN_TOO_DEEP | MEDIUM | 跨事务依赖深度超过限制 |


## 五、安全与并发约束

### 5.1 签名规则

- 签名算法：HMAC-SHA256。
- 密钥体系：MemoryBus 与 CerebellumBus 共享同一密钥派生体系。首次启动基于设备 TPM/安全飞地生成根密钥，各模块签名密钥由此派生，支持 KEY_ROTATION 在线轮换。
- 双密钥管理：MLNF 仅保留当前有效版本和最近一个直接前驱版本。key_version 不匹配且非前驱版本时返回 MEM_SIGN_INVALID。过渡期内旧版本报文增加 timestamp 新鲜度检查，偏差超过 30s 判定为重放。
- 报文签名域：非分包报文签名包含 payload_hash（非恢复类）或 body_hash（恢复类）；分包报文签名包含 chunk_hash，非 payload_hash。两者互斥。
- 待签内容：`msg_id.timestamp.session_id.source.target.ext_version.key_version.chunk_group_id.chunk_index.chunk_total.[payload_hash|body_hash|chunk_hash].txn_group_id.operation` 分别 Base64 编码，`.` 顺序拼接。
- 签名校验在 msg_id 去重之前执行。重传时必须保证 body 与原始报文完全一致。
- 跨总线报文采用双重签名：发起方模块原始签名 + ECC-12 代理签名。
- sign_ecc12 为 ECC-12 网关签名，全部 REQUEST 报文强制携带。RESPONSE 报文携带对应 MLNF 模块签名。
- ACK 报文免除签名校验与重传确认。

### 5.2 防重放、限流与重传约束

1. 滑动窗口去重：维护 msg_id 队列，上限 10000 条或 2MB 内存；LRU 淘汰，条目超 300s 自动过期。
2. 所有 REQUEST 报文双重校验：全局 timestamp ±60s + 单会话 msg_id 30s 新鲜度窗口。
3. 会话洪水防护：单 session 10s 内新增 msg_id 超 300 条限流 30s，200~300 条仅告警。连续 3 个窗口维持 200-300 条自动升级限流。限流排除锁指令和审计日志，锁指令单独限流：单 session 10s 内最多 10 条。
4. 时钟偏移处理：timestamp 偏差超 ±60s 丢弃报文。
5. 重传规则：MLNF 发送 RESPONSE 后启动 2s 计时器等待 MSG_ACK，未收到则间隔翻倍重传最多 3 次，一轮结束冷却 60s，3 次失败写入 WAL。
6. MSG_ACK 的 target 动态匹配 RESPONSE 的 source。跨总线 ACK 增加 original_source 字段。ACK 报文免除重传与二次确认。

### 5.3 并发、锁与写入约束

1. 同一 session 写入串行排队，跨 session 写入分片并行。锁相关指令全局快照串行隔离。
2. 会话锁生命周期由 CerebellumBus 统一管控。MLNF 每 10s 发送 LOCK_ALIVE_QUERY。连续 5 次无响应或最近 120s 内累计丢失超 8 次，发送 LOCK_ALIVE_LOST。READ_ONLY 锁在 LOCK_ALIVE_LOST 后启动安全倒计时 60s，归零自动释放并通过 SESSION_RECOVER 同步状态，标记 auto_released:true。EXCLUSIVE 锁不可自动释放，仅在 LOCK_ALIVE_LOST 后持续发送 LOCK_EXPIRE_WARNING 预警，等待管理员手动干预或 24 小时硬超时。
3. 锁令牌由 MLNF-01 集中管理缓存，ECC-06 发起 WRITE 时无需携带令牌。
4. 批量 WRITE 事务：事务开始时锁令牌快照绑定 txn_group_id + device_id。事务超时 = min(30s + (txn_total-1)×10s, 120s)。超时后可选部分提交或全部放弃。部分提交时 MLNF 根据 depends_on 构建 DAG 进行依赖排除。跨事务依赖深度上限 2 层。事务提交前执行环检测。事务提交进入 COMMITTING 中间态，最多允许 1 个活跃 QUERY。depends_on 非空时 COMMITTING 必须等待依赖项 QUERY 确认引用完整。依赖项 QUERY 超时后 entry 回退至 L1 临时层后台异步重试最多 3 次。UNLOCK 执行前等待当前 session 所有 COMMITTING 事务完成或超时。
5. 跨设备切换通过 SESSION_DEVICE_TRANSFER 完成，携带 transition_id。原设备收到 DEVICE_SESSION_TRANSFERRED 后 2s 内停止所有该 session 请求。MSG_LIST_QUERY 全失败时 SESSION_DEVICE_TRANSFER 强制生成 LIVE 列表附加到响应中。
6. 事务回滚前 MLNF 发送 DEPENDENCY_ROLLBACK_WARNING。ALIASED 标记生成时执行 aliased_from 链循环检测，深度上限 6 层。
7. EXCLUSIVE 锁持有期间禁止一切读写操作。锁到期前 60s 发送 LOCK_EXPIRE_WARNING。锁释放后 5s 内拒绝该 session 新 QUERY/WRITE 请求。
8. I_VALUE_UPDATE 采用乐观并发控制，版本冲突返回 CONFLICT。同 session 1s 窗口内合并批量更新。同基线多更新各自创建独立版本，parent_version 标识父节点。主分支选择版本号最大者。历史版本保留上限 10 个，安全审计保留版本及相邻版本豁免清理。contributing_sources 保留最近 10 次来源信息，审计保留版本不清除。
9. 单次 QUERY 最大返回 100 条。响应超 500KB 采用 chunk_group 分包。
10. 已回滚分片标记后 24 小时物理删除。部分提交事务的 WAL 记录保留至 txn_group_id 生命周期结束。引用计数表采用分段存储，按创建日期分桶，每段文件在创建后第 8 天整体删除。
11. entry 内容一致性比较使用规范化 JSON（键按字母序排列，数字使用固定精度 6 位小数格式化）。
12. 版本号使用 WAL 持久化 + 64 位整数单调递增。崩溃恢复后从 WAL 最后序号 +1 继续。
13. 单 REQUEST Payload 上限 2MB。
14. 总线请求全局最大重试 3 次，单次超时 10s。
15. MSG_LIST_RESPONSE 为 CACHED 时 confidence_level 必须为 LOW。CACHED 列表不合并到活跃防重放窗口，需用户确认后进入离线保守模式。

### 5.4 WAL持久化与崩溃恢复约束

1. WRITE、LOCK、UNLOCK、AUDIT_LOG、SESSION_FORCE_UNLOCK_ADMIN、I_VALUE_UPDATE 强制写入 WAL。LOCK_ALIVE_QUERY 不写 WAL。
2. QUERY 可配置 wal_write。
3. WAL 日志分级留存：CRITICAL 永久（上限 1GB），HIGH 留存 90 天，其余留存 7 天。
4. 进程启动恢复逻辑：扫描未完成事务与锁状态，主动发送 SESSION_RECOVER。回滚扫描优先于新任务调度。恢复期间每秒最多处理 10 个 session。
5. MSG_LIST_RESPONSE 响应前强制刷新 WAL 缓冲区。生成顺序：先生成 msg_id 列表，再刷新 WAL，最后计算 body_hash 并签名。
6. 版本号、query_seq、锁状态等关键计数器通过 WAL 持久化保证恢复后连续。


## 六、传输层安全规范

1. 所有非同一进程内通信必须走 TLS 1.3 加密信道。
2. 跨设备通信强制双向证书认证（mTLS）。
3. 证书由设备 TPM/安全飞地根密钥派生，首次配对时交换并缓存。
4. 证书有效期 90 天，到期前 7 天自动发起轮换。
5. 证书黑名单由 ECC 统一管理。
6. 安全凭证禁止在非加密信道传输。


## 七、监控埋点标准

1. 每条报文自动记录传输延迟、校验失败次数、重传次数、限流触发标记。
2. ECC-12 每 60s 汇聚指标推送至 MLNF 监控日志分区。
3. 指标数据留存 7 天，支持按 session_id/operation/时间范围查询。


## 八、版本规范

1. MemoryBus V1.1 与 CerebellumBus V1.1 协议版本对齐。
2. ext_version 固定 "1.1"，主版本不一致直接丢弃，次版本向前兼容。
3. 两套总线共用底层传输通道，业务报文隔离，支持联合升级。共享密钥派生体系，签名校验规则、防重放机制、洪水防护策略保持一致。


## 九、附录：报文类型索引

| 编号 | 报文名称 | 方向 | 类型 |
|:---:|----------|------|:---:|
| 3.1 | QUERY | ECC→MLNF | REQUEST/RESPONSE |
| 3.2 | WRITE | ECC→MLNF | REQUEST/RESPONSE |
| 3.3 | LOCK/UNLOCK/QUERY_LOCK_STATUS | ECC→MLNF | REQUEST/RESPONSE |
| 3.4 | I_VALUE_UPDATE | ECC→MLNF | REQUEST/RESPONSE |
| 3.5 | AUDIT_LOG | ECC→MLNF | REQUEST/RESPONSE |
| 3.6 | SESSION_RECOVER | MLNF→ECC | REQUEST |
| 3.7 | LOCK_ALIVE_QUERY | MLNF→ECC | REQUEST/RESPONSE |
| 3.8 | LOCK_ALIVE_LOST | MLNF→ECC | REQUEST |
| 3.9 | SESSION_FORCE_UNLOCK_ADMIN | ECC→MLNF | REQUEST |
| 3.10 | DEPENDENCY_ROLLBACK_WARNING | MLNF→ECC | REQUEST |
| 3.11 | MSG_LIST_QUERY/RESPONSE | 跨总线 | REQUEST/RESPONSE |
| 3.12 | KEY_SYNC | ECC→MLNF | REQUEST |
| 3.13 | LOCK_EXPIRE_WARNING | MLNF→ECC | REQUEST |
| 3.14 | SESSION_TAKEOVER_NOTIFY | MLNF→ECC | REQUEST |
| 3.15 | SESSION_DEVICE_TRANSFER | ECC→MLNF | REQUEST/RESPONSE |