# CerebellumBus 总线报文规范 V1.1

EM-Core Agent · 认知层与执行层指令交互标准
版本：V1.1 ｜ 日期：2026-06-22
适用中枢：ECC（认知大脑） ↔ MCC（执行小脑）
架构同源：EM-Core HR人形机器人 / EM-Core AD自动驾驶

## 一、总线定位

CerebellumBus 是 ECC 认知大脑与 MCC 执行小脑唯一的指令通信通道。任务下发、DAG并行调度、故障回执、熔断信号、资源降级同步、会话状态同步及跨设备会话路由全部经由本总线流转。

核心约束：

1. ECC-12 网关为 REQUEST 报文唯一发送端；RESPONSE 与 NOTIFY 报文由 MCC 各模块主动上报，不受此限。
2. 所有业务指令采用请求-回执双报文模型；熔断、降级、心跳、跨设备同步为单向 NOTIFY 报文，ECC收到所有上行报文后回复极简ACK；总线报文统一重传与幂等规则。
3. 多会话报文基于 session_id 分片隔离处理，单会话 DAG 任务有序解析；FILE/CLIPBOARD/WINDOW/NETWORK资源锁全局统一等待超时10s。
4. ECC 下发 DAG 任务 REQUEST 报文须携带有效 sign_ecc05 与 payload_hash。MCC-02 校验 sign_ecc05 和 payload_hash 通过后即时生成 sign_mcc02 存入 DAG 上下文缓存，双签名同步用于回执、熔断、告警类报文，缺失任一签名直接丢弃并返回 REJECT 回执，写入审计日志。
5. L3 永久拦截级任务在 ECC-12 网关预处理阶段直接拦截，不下发至总线；拦截事件自动生成AUDIT_LOG通过MemoryBus归档。若因异常时序 L3 报文流入总线，MCC-02 识别 L3 标记后立即丢弃、上报安全告警。L3风险任务联动MemoryBus自动申请EXCLUSIVE排他记忆锁，禁止并行读取。
6. DAG全会话全部任务正常完成且返回OK回执（wal_status=wal_committed）后，ECC-12通过MemoryBus下发UNLOCK。跨设备SESSION_SWITCH携带force_takeover:true时，采用两阶段提交协议：Phase1冻结原设备并等待确认，Phase2确认冻结成功后再执行强制解锁。正常切换与异常接管清理路径分离。
7. CerebellumBus与MemoryBus共享同一密钥派生体系，两套总线的签名校验规则、防重放机制、洪水防护策略保持一致。跨总线报文须携带请求方模块签名，接收方校验签名通过后响应。所有非同一进程内通信必须走 TLS 1.3 加密信道。

## 二、报文通用格式

### 2.1 通用报文头

```json
{
  "header": {
    "msg_id": "cere-20260621-152010-0001",
    "msg_type": "REQUEST | RESPONSE | NOTIFY",
    "source": "ECC-12",
    "target": "MCC-01",
    "session_id": "session_x",
    "timestamp": "2026-06-21T15:20:10.000Z",
    "ext_version": "1.1",
    "key_version": 1,
    "payload_hash": "",
    "body_hash": "",
    "is_feedback_summary": false,
    "trust_token": "",
    "device_challenge": "",
    "status_token": "",
    "sequence": 0,
    "chunk_group_id": "",
    "chunk_index": 0,
    "chunk_total": 0,
    "chunk_ttl": 10,
    "chunk_hash": "",
    "emergency_override": false,
    "post_force_takeover": false
  },
  "body": {}
}
```

### 2.2 头部字段定义

字段 类型 必填 说明
msg_id string 是 全局唯一报文ID，格式 cere-{date}-{time}-{seq}，REQUEST、TASK_FEEDBACK用于幂等去重，**管理员解锁报文msg_id全局唯一不可复用**
msg_type enum 是 REQUEST下发任务 / RESPONSE回执结果 / NOTIFY单向通知
source string 是 REQUEST固定ECC-12；RESPONSE/NOTIFY为对应MCC模块编号
target string 是 接收方模块编号
session_id string 是 会话隔离标识，锁、并发、回执路由核心字段，**trust_token、status_token、模块签名、查询权限全部强制绑定本字段**
timestamp ISO8601 是 严格保留三位毫秒精度.sssZ；本地时间偏差超±60s直接丢弃，响应携带offset_ms上报时钟异常。**管理员解锁、紧急签名时间窗口压缩至10s/5s**
ext_version string 是 协议版本固定"1.1"，主版本不同直接丢弃，次版本向前兼容
key_version int 是 签名密钥版本号，用于密钥轮换过渡期双密钥共存校验
payload_hash string 条件必填 非恢复类报文必填，body完整内容的SHA-256哈希。空body报文（各类ACK、LOAD_DEGRADE、HEARTBEAT_STALL）置空字符串，哈希校验分支直接跳过
body_hash string 条件必填 恢复类报文必填，body核心字段按字母序序列化后的SHA-256哈希
is_feedback_summary bool 条件必填 TASK_FEEDBACK降级传输时为true，其余报文为false或不携带。校验层依据此字段分流分包/摘要两条逻辑
trust_token string 条件必填 离线保守模式下DAG_DISPATCH必填，MCC校验scope，**签名强制绑定session_id，跨session直接拒绝**
device_challenge string 条件必填 SESSION_SWITCH必填，随机字符串，device_sign签名必须包含此值。无challenge的SESSION_SWITCH直接REJECT
status_token string 条件必填 SESSION_STATUS_QUERY响应返回的一次性状态凭证，有效期500ms，**绑定session_id+仅允许DAG_DISPATCH操作、单次使用立即失效、禁止复用**
sequence int 条件必填 进度类NOTIFY携带，session生命周期内单调递增。会话完整销毁后重置为0写入WAL。sequence=-1时进度通知豁免去重。**去重校验三元组：session_id+operation+sequence**
chunk_group_id string 条件必填 分包报文必填，同组所有chunk共享同一ID
chunk_index int 条件必填 分包报文必填，当前chunk序号（从0开始）
chunk_total int 条件必填 分包报文必填，总chunk数量
chunk_ttl int 条件必填 分包报文必填，重组超时秒数。普通RESPONSE为10s，BRANCH_DETAIL_RETRIEVE为30s
chunk_hash string 条件必填 分包报文每个chunk独立SHA-256哈希，独立参与签名校验。**单chunk最大尺寸256KB，超限直接丢弃返回CHUNK_OVERSIZE**
emergency_override bool 条件必填 全局熔断期间紧急通道DAG_DISPATCH必填。紧急任务单会话max_parallel=1，全局最多同时2条紧急DAG，**必须附带emergency_admin_sign管理员签名，签名有效期5s，无合法签名直接拦截**
post_force_takeover bool 条件必填 强制接管后被Kill任务回执携带，豁免token校验。接收窗口60s

### 2.3 标准回执报文模板

```json
{
  "header": {
    "msg_id": "cere-20260621-152010-0002",
    "msg_type": "RESPONSE",
    "source": "MCC-36",
    "target": "ECC-12",
    "session_id": "session_x",
    "timestamp": "2026-06-21T15:20:10.020Z",
    "ext_version": "1.1",
    "key_version": 1,
    "payload_hash": "sha256_xxxxxx",
    "ref_msg_id": "cere-20260621-152010-0001"
  },
  "body": {
    "status": "OK | PARTIAL_FAIL | GLOBAL_FAIL | TIMEOUT | REJECT | DEGRADE_LIMIT | CANCELLED",
    "risk_level": "L0 | L1 | L2 | L3",
    "retry_count": 0,
    "lock_type": "",
    "wal_status": "wal_committed | wal_pending | wal_force_unlock",
    "sign_ecc05": "ec_sig_xxxxxx",
    "sign_mcc02": "mcc_sig_xxxxxx",
    "data": {},
    "error": {
      "fault_code": "F1-404",
      "fault_category": "FILE",
      "severity": "MEDIUM",
      "message": "目标文件不存在",
      "offset_ms": 0
    }
  }
}
```

### 2.4 MSG_ACK确认报文

```json
{
  "header": {
    "msg_id": "cere-ack-xxxx",
    "msg_type": "NOTIFY",
    "source": "ECC-12",
    "target": "MCC-01",
    "session_id": "session_x",
    "timestamp": "2026-06-21T15:20:15.000Z",
    "ext_version": "1.1",
    "key_version": 1,
    "payload_hash": ""
  },
  "body": {
    "operation": "MSG_ACK",
    "ref_msg_id": "cere-20260621-152010-0001"
  }
}
```

### 2.5 回执状态枚举

状态码 说明
OK 全会话全部任务执行完成且无故障。仅当wal_status=wal_committed时，ECC调用MemoryBus UNLOCK
PARTIAL_FAIL 单分支子任务失败，其余分支正常完成，不触发记忆锁解锁。会话锁最大持有时间24小时，超时MCC向ECC发送LIFECYCLE_GRACE_PERIOD，进入5分钟宽限期。宽限期启动时对该session L1缓存加排他锁；跨设备读取时临时申请共享读锁（上限30s）。归档写入前等待所有共享读锁释放，排他锁全程持有至归档完成或用户操作重置计时器。锁开始时间由MCC-04在锁生效时通过MemoryBus同步至MLNF持久化。24小时超时由MCC-04本地计时为主，ECC-09为备（MCC-04心跳超时10s未更新时ECC接管计时）。两者任一判定超时即触发宽限期流程。触发方发送LIFECYCLE_GRACE_PERIOD时附带锁开始时间戳，接收方校验
GLOBAL_FAIL 会话全局熔断、不可恢复故障
TIMEOUT 任务报文超30s未入队自动丢弃
REJECT 安全校验不通过、签名缺失、格式非法、L3高危拦截、Payload超限、DAG拓扑非法
DEGRADE_LIMIT 系统负载超限，并发限流拒绝任务，**包含会话冻结细分场景SESSION_FROZEN_FOR_SWITCH**
CANCELLED 全会话因DAG_CANCEL或TASK_CANCEL级联取消而终止。取消节点不计入finished_task_count。全取消不写入长效记忆；部分取消仅成功任务晋升，取消分支数据丢弃。**所有取消操作强制WAL落盘，级联取消同步回收任务快照**

## 三、核心操作报文定义

### 3.1 DAG任务下发请求（ECC→MCC-01）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "ECC-12",
    "target": "MCC-01"
  },
  "body": {
    "operation": "DAG_DISPATCH",
    "sign_ecc05": "ec_sig_xxxxxx",
    "risk_level": "L1",
    "user_confirm_timeout": 120,
    "emergency_admin_sign": "",
    "dag": {
      "dag_id": "dag-session_x-001",
      "max_parallel": 6,
      "task_nodes": [
        {
          "task_id": "task_01",
          "deps": [],
          "op_type": "FILE_COPY",
          "params": {"src": "/a.md", "dst": "/out/"},
          "lock_type": "FILE",
          "risk_level": "L0"
        }
      ]
    }
  }
}
```

DAG下发接收ACK报文

```json
{
  "header": {
    "msg_id": "cere-ack-xxxx",
    "msg_type": "NOTIFY",
    "source": "MCC-01",
    "target": "ECC-12",
    "session_id": "session_x",
    "timestamp": "2026-06-21T15:20:15.000Z",
    "ext_version": "1.1",
    "key_version": 1,
    "payload_hash": ""
  },
  "body": {
    "operation": "DAG_ACK",
    "ref_msg_id": "cere-20260621-152010-0001"
  }
}
```

DAG下发拒收通知报文

```json
{
  "header": {
    "msg_id": "cere-rej-xxxx",
    "msg_type": "NOTIFY",
    "source": "MCC-01",
    "target": "ECC-12",
    "session_id": "session_x",
    "timestamp": "2026-06-21T15:20:16.000Z",
    "ext_version": "1.1",
    "key_version": 1,
    "payload_hash": ""
  },
  "body": {
    "operation": "DAG_REJECT_NOTIFY",
    "ref_msg_id": "cere-20260621-152010-0001",
    "fault_code": "R2-01",
    "message": "单会话并行数量超限",
    "sign_ecc05": "ec_sig_xxxxxx",
    "sign_mcc02": "mcc_sig_xxxxxx"
  }
}
```

### 3.2 执行回执（MCC-36→ECC-12）

```json
{
  "header": {
    "msg_type": "RESPONSE",
    "source": "MCC-36",
    "target": "ECC-12",
    "is_feedback_summary": false
  },
  "body": {
    "operation": "TASK_FEEDBACK",
    "dag_id": "dag-session_x-001",
    "risk_level": "L1",
    "retry_count": 0,
    "wal_status": "wal_committed",
    "sign_ecc05": "ec_sig_xxxxxx",
    "sign_mcc02": "mcc_sig_xxxxxx",
    "finished_task_count": 2,
    "cancelled_task_count": 0,
    "failed_task_count": 0,
    "all_task_finished": true,
    "branch_details_hash": "sha256_xxxxxx",
    "is_interim": false,
    "branch_details": []
  }
}
```

TASK_FEEDBACK降级传输规则：若body超过500KB，先发送仅含状态摘要的轻量回执（is_feedback_summary<10KB），详细branch_details写入WAL并通过MemoryBus异步同步。MCC缓存完整明细最长7天。MemoryBus推送失败每10s重试最多5次；全部失败后写入本地持久化文件并上报ECC。ECC可主动发起BRANCH_DETAIL_RETRIEVE拉取请求，从MCC本地文件读取明细补推至MLNF。MLNF收到明细后校验branch_details_hash，不一致时标记记忆为“待验证”（7天有效期，到期自动降回L1并清除hash）。同一session多次哈希不一致触发ECC告警“MCC摘要传输可能存在数据损坏”。branch_details_hash纳入上行TASK_FEEDBACK报文签名。**中间回执is_interim=true仅保留30s，超时自动清理**。

### 3.3 熔断通知（MCC-33→ECC-12）

```json
{
  "header": {
    "msg_type": "NOTIFY",
    "source": "MCC-33",
    "target": "ECC-12"
  },
  "body": {
    "operation": "FUSE_TRIGGER",
    "session_id": "session_x",
    "risk_level": "L2",
    "sign_ecc05": "ec_sig_xxxxxx",
    "sign_mcc02": "mcc_sig_xxxxxx",
    "fuse_scope": "BRANCH | SESSION",
    "trigger_reason": "UNRECOVERABLE_HARDWARE_ERROR",
    "affected_task_ids": ["task_02"],
    "auto_reset_after_sec": 300
  }
}
```

### 3.4 资源降级同步通知

MCC主动上报（负载超限）：

```json
{
  "header": {"msg_type": "NOTIFY", "source": "MCC-37", "target": "ECC-12", "payload_hash": ""},
  "body": {
    "operation": "LOAD_DEGRADE",
    "cpu_usage": 86,
    "mem_usage": 93,
    "battery": 16,
    "allow_max_session": 4,
    "allow_single_parallel": 3
  }
}
```

ECC主动下发（用户手动省电，优先级覆盖硬件自动降级）：

```json
{
  "header": {"msg_type": "NOTIFY", "source": "ECC-12", "target": "MCC-37", "payload_hash": ""},
  "body": {
    "operation": "LOAD_DEGRADE",
    "trigger_source": "USER",
    "allow_max_session": 2,
    "allow_single_parallel": 1
  }
}
```

### 3.5 心跳卡死告警（MCC-37→ECC-12）

```json
{
  "header": {"msg_type": "NOTIFY", "source": "MCC-37", "target": "ECC-12", "payload_hash": ""},
  "body": {
    "operation": "HEARTBEAT_STALL",
    "session_id": "session_x",
    "stall_task_id": "task_02",
    "stall_duration_ms": 10500
  }
}
```

### 3.6 会话断点恢复同步（MCC-04→ECC-12）

```json
{
  "header": {"msg_type": "NOTIFY", "source": "MCC-04", "target": "ECC-12", "body_hash": "sha256_xxxxxx"},
  "body": {
    "operation": "SESSION_RECOVER",
    "session_id": "session_x",
    "unfinished_dag_ids": ["dag-session_x-001"],
    "last_snapshot_time": "2026-06-21T15:18:00.000Z"
  }
}
```

### 3.7 跨设备会话同步通知（ECC-12→MCC-09）

```json
{
  "header": {
    "msg_type": "NOTIFY",
    "source": "ECC-12",
    "target": "MCC-09",
    "body_hash": "sha256_xxxxxx",
    "device_challenge": "random_xxxxxx"
  },
  "body": {
    "operation": "SESSION_SWITCH",
    "session_id": "session_x",
    "target_device_id": "device_macbook_pro_02",
    "transfer_dag_ids": ["dag-session_x-001"],
    "sync_timestamp": "2026-06-21T15:25:00.000Z",
    "device_sign": "dev_sig_xxxxxx",
    "force_takeover": false,
    "active_trust_tokens": [],
    "pending_trust_tokens": [],
    "system_status": {
      "level": "NORMAL | DEGRADED | MINIMUM",
      "reason": "CPU | MEMORY | BATTERY | USER",
      "allow_max_session": 8,
      "allow_single_parallel": 6
    }
  }
}
```

### 3.8 密钥轮换通知（ECC-12→MCC-02）

```json
{
  "header": {"msg_type": "NOTIFY", "source": "ECC-12", "target": "MCC-02", "payload_hash": "sha256_xxxxxx"},
  "body": {
    "operation": "KEY_ROTATION",
    "new_key_version": 2,
    "activation_time": "2026-06-21T16:00:00.000Z",
    "grace_period_sec": 60
  }
}
```

### 3.9 会话生命周期通知（MCC-04→ECC-12）

```json
{
  "header": {"msg_type": "NOTIFY", "source": "MCC-04", "target": "ECC-12", "body_hash": "sha256_xxxxxx"},
  "body": {
    "operation": "LIFECYCLE_GRACE_PERIOD | LIFECYCLE_ARCHIVED",
    "session_id": "session_x",
    "trigger_reason": "PARTIAL_FAIL_TIMEOUT",
    "lock_start_time": "2026-06-21T00:00:00.000Z"
  }
}
```

### 3.10 任务取消指令（ECC-12→MCC-01）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "ECC-12",
    "target": "MCC-01"
  },
  "body": {
    "operation": "DAG_CANCEL | TASK_CANCEL",
    "dag_id": "dag-session_x-001",
    "task_id": "task_02",
    "sign_ecc05": "ec_sig_xxxxxx",
    "cascade": true
  }
}
```

取消操作回执：

```json
{
  "header": {
    "msg_type": "RESPONSE",
    "source": "MCC-01",
    "target": "ECC-12"
  },
  "body": {
    "operation": "CANCEL_FEEDBACK",
    "dag_id": "dag-session_x-001",
    "task_id": "task_02",
    "cancel_status": "CANCELLED | PARTIAL_CANCELLED | REJECT_ALREADY_DONE | REJECT_NOT_FOUND",
    "cascaded_task_ids": ["task_03"],
    "sign_mcc02": "mcc_sig_xxxxxx"
  }
}
```

### 3.11 密钥重签请求（MCC→ECC-12）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "MCC-36",
    "target": "ECC-12"
  },
  "body": {
    "operation": "KEY_RESYNC_REQUEST",
    "ref_msg_id": "cere-20260621-152010-0002",
    "sign_mcc02": "mcc_sig_xxxxxx"
  }
}
```

密钥重签响应（ECC-12→MCC）：

```json
{
  "header": {
    "msg_type": "RESPONSE",
    "source": "ECC-12",
    "target": "MCC-36"
  },
  "body": {
    "operation": "KEY_RESYNC_RESPONSE | KEY_RESYNC_EXPIRED",
    "ref_msg_id": "cere-20260621-152010-0002",
    "sign_ecc05": "ec_sig_xxxxxx"
  }
}
```

### 3.12 冻结状态通知（MCC-04→ECC-12）

```json
{
  "header": {"msg_type": "NOTIFY", "source": "MCC-04", "target": "ECC-12", "body_hash": "sha256_xxxxxx"},
  "body": {
    "operation": "FREEZE_ACK | UNFREEZE_ACK | FROZEN_EXPIRE_QUERY",
    "session_id": "session_x",
    "freeze_expire_time": "2026-06-21T15:25:40.000Z",
    "lock_snapshot": {"FILE": 2, "NETWORK": 0}
  }
}
```

### 3.13 强制解冻指令（ECC-12→MCC-04）

```json
{
  "header": {"msg_type": "NOTIFY", "source": "ECC-12", "target": "MCC-04", "body_hash": "sha256_xxxxxx"},
  "body": {
    "operation": "UNFREEZE | FORCE_UNFREEZE",
    "session_id": "session_x",
    "force_destroy": true
  }
}
```

### 3.14 回滚进度通知（MCC-04→ECC-12）

```json
{
  "header": {
    "msg_type": "NOTIFY",
    "source": "MCC-04",
    "target": "ECC-12",
    "body_hash": "sha256_xxxxxx",
    "sequence": 3
  },
  "body": {
    "operation": "ROLLBACK_PROGRESS",
    "session_id": "session_x",
    "completed_count": 50,
    "total_count": 100
  }
}
```

### 3.15 信任令牌签发（ECC-12→MCC）

```json
{
  "header": {
    "msg_type": "NOTIFY",
    "source": "ECC-12",
    "target": "MCC-01"
  },
  "body": {
    "operation": "TRUST_TOKEN_ISSUE",
    "session_id": "session_x",
    "trust_token": "token_xxxxxx",
    "scope": "REQUEST_EXEC",
    "max_uses": 10,
    "expire_time": "2026-06-21T15:30:00.000Z",
    "sign_ecc05": "ec_sig_xxxxxx"
  }
}
```

### 3.16 信任令牌确认/撤销（MCC→ECC-12）

```json
{
  "header": {
    "msg_type": "NOTIFY",
    "source": "MCC-01",
    "target": "ECC-12"
  },
  "body": {
    "operation": "TOKEN_CACHED_ACK | TOKEN_REVOKED_ACK",
    "session_id": "session_x",
    "trust_token": "token_xxxxxx",
    "session_status": "ACCEPTING | ROLLBACK_IN_PROGRESS | GRACE_PERIOD"
  }
}
```

### 3.17 会话状态查询（ECC-12→MCC-04）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "ECC-12",
    "target": "MCC-04"
  },
  "body": {
    "operation": "SESSION_STATUS_QUERY",
    "session_id": "session_x",
    "sign_ecc05": "ec_sig_xxxxxx"
  }
}
```

会话状态查询响应（MCC-04→ECC-12）：

```json
{
  "header": {
    "msg_type": "RESPONSE",
    "source": "MCC-04",
    "target": "ECC-12",
    "status_token": "stok_xxxxxx"
  },
  "body": {
    "operation": "SESSION_STATUS_RESPONSE",
    "session_id": "session_x",
    "session_status": "ACCEPTING | ROLLBACK_IN_PROGRESS | GRACE_PERIOD | LOCKED",
    "active_locks": [
      {"lock_type": "FILE", "holder_session": "session_y", "wait_queue_length": 2}
    ],
    "rollback_remaining": 0,
    "sign_mcc04": "mcc_sig_xxxxxx"
  }
}
```

### 3.18 信任令牌撤销指令（ECC-12→MCC）

```json
{
  "header": {
    "msg_type": "NOTIFY",
    "source": "ECC-12",
    "target": "MCC-01"
  },
  "body": {
    "operation": "TOKEN_REVOKE",
    "session_id": "session_x",
    "trust_token": "token_xxxxxx",
    "sign_ecc05": "ec_sig_xxxxxx"
  }
}
```

### 3.19 回滚锁冲突通知（MCC-31→MCC-05）

```json
{
  "header": {
    "msg_type": "NOTIFY",
    "source": "MCC-31",
    "target": "MCC-05"
  },
  "body": {
    "operation": "ROLLBACK_LOCK_CONFLICT",
    "session_id": "session_x",
    "rollback_task_id": "task_r1",
    "holding_task_id": "task_t1",
    "lock_type": "FILE",
    "holding_task_status": "STALLED",
    "wait_duration_ms": 10500
  }
}
```

### 3.20 MemoryBus跨总线查询报文

精确列表查询（MCC→MLNF）：

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "MCC-09",
    "target": "MLNF-51",
    "session_id": "session_x",
    "msg_id": "cere-query-xxxx",
    "timestamp": "2026-06-21T15:20:10.000Z",
    "ext_version": "1.1",
    "key_version": 1,
    "body_hash": "sha256_xxxxxx"
  },
  "body": {
    "operation": "MSG_LIST_QUERY",
    "list_hash": "sha256_xxxxxx",
    "sign_mcc09": "mcc_sig_xxxxxx",
    "cursor": "",
    "has_more": false
  }
}
```

精确列表响应（MLNF→MCC）：

```json
{
  "header": {
    "msg_type": "RESPONSE",
    "source": "MLNF-51",
    "target": "MCC-09",
    "session_id": "session_x",
    "msg_id": "cere-list-xxxx",
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
    "list_freshness": "LIVE | CACHED",
    "cache_time": "2026-06-21T15:18:00.000Z",
    "sign_mlnf": "mlnf_sig_xxxxxx",
    "cursor": "",
    "has_more": false
  }
}
```

### 3.21 分支明细补拉请求（ECC→MCC）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "ECC-12",
    "target": "MCC-36"
  },
  "body": {
    "operation": "BRANCH_DETAIL_RETRIEVE",
    "dag_id": "dag-session_x-001",
    "ref_msg_id": "cere-20260621-152010-0002",
    "sign_ecc05": "ec_sig_xxxxxx"
  }
}
```

### 3.22 快照过期预警通知（MCC-31→ECC-12）

```json
{
  "header": {"msg_type": "NOTIFY", "source": "MCC-31", "target": "ECC-12", "body_hash": "sha256_xxxxxx"},
  "body": {
    "operation": "SNAPSHOT_EXPIRE_WARNING",
    "session_id": "session_x",
    "affected_task_ids": ["task_01", "task_02"],
    "expire_time": "2026-06-21T15:35:00.000Z"
  }
}
```

### 3.23 会话清理完成通知（MCC→ECC-12）

```json
{
  "header": {"msg_type": "NOTIFY", "source": "MCC-04", "target": "ECC-12", "body_hash": "sha256_xxxxxx"},
  "body": {
    "operation": "SESSION_CLEANUP_DONE",
    "session_id": "session_x",
    "cleanup_reason": "FORCE_TAKEOVER | NORMAL_SWITCH | TIMEOUT"
  }
}
```

### 3.24 接管中止通知（ECC-12→MCC-09）

```json
{
  "header": {"msg_type": "NOTIFY", "source": "ECC-12", "target": "MCC-09", "body_hash": "sha256_xxxxxx"},
  "body": {
    "operation": "TAKEOVER_ABORT",
    "session_id": "session_x",
    "reason": "ORIGINAL_DEVICE_HEARTBEAT_RESTORED"
  }
}
```

### 3.25 管理员强制解锁指令（ECC-12→MCC-04）

```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "ECC-12",
    "target": "MCC-04"
  },
  "body": {
    "operation": "SESSION_FORCE_UNLOCK_ADMIN",
    "session_id": "session_x",
    "admin_sign": "admin_rsa_sig_xxxxxx",
    "sign_ecc05": "ec_sig_xxxxxx"
  }
}
```

### 3.26 跨会话锁冲突告警通知（新增）
```json
{
  "header": {
    "msg_type": "NOTIFY",
    "source": "MCC-31",
    "target": "ECC-12",
    "session_id": "session_x",
    "timestamp": "2026-06-21T15:20:10.000Z",
    "ext_version": "1.1",
    "key_version": 1,
    "body_hash": "sha256_xxxxxx"
  },
  "body": {
    "operation": "CROSS_SESSION_LOCK_CONFLICT",
    "local_session_id": "session_x",
    "remote_session_id": "session_y",
    "lock_type": "FILE",
    "conflict_task_id": "task_01"
  }
}
```

### 3.27 管理员手动强制归档（新增）
```json
{
  "header": {
    "msg_type": "REQUEST",
    "source": "ECC-12",
    "target": "MCC-04"
  },
  "body": {
    "operation": "LIFECYCLE_FORCE_ARCHIVE",
    "session_id": "session_x",
    "admin_sign": "admin_rsa_sig_xxxxxx",
    "sign_ecc05": "ec_sig_xxxxxx"
  }
}
```

## 四、全局故障错误码体系

### 4.1 故障码安全分级

安全等级 说明 审计留存时长
CRITICAL 安全攻击/权限逃逸/签名伪造 永久（独立永久审计库，不跟随WAL清理）
HIGH 认证失败/令牌异常/洪水攻击 90天
MEDIUM 资源超限/超时/任务失败 30天
LOW 普通业务告警 7天

### 4.2 故障码分类

类别 前缀 安全等级 说明
F 文件 F1-F7 MEDIUM 路径校验、磁盘空间检查、权限、锁、格式、超时、完整性
A 应用 A1-A6 MEDIUM 未安装、无响应、控件定位失败、版本不兼容、弹窗阻塞、崩溃
N 网络 N1-N6 MEDIUM 域名解析、连接超时、客户端错误、服务端错误、SSL、带宽不足
C 命令脚本 C1-C5 HIGH 语法错误、高危系统调用、执行超时、注入风险、权限不足
B 剪贴板 B1-B3 LOW 被占用、内容过大、格式不支持
R 并发资源 R1-R5 MEDIUM 全局并发满、单会话并行满、锁等待超时、端口耗尽、全局熔断
H 硬件外设 H1-H3 LOW 未连接、电池不足、存储介质弹出
V 协议校验 V1-01 HIGH 报文字段未知/类型不匹配，解析直接REJECT
PAYLOAD_OVERSIZE — MEDIUM REQUEST报文超过2MB，丢弃返回REJECT
CHUNK_OVERSIZE — MEDIUM 单分片超过256KB，直接丢弃
SIGN_INVALID — CRITICAL 签名校验失败，单会话1分钟5次无效签名触发120s拉黑。密钥轮换过渡期内旧版本密钥签名校验失败不计入拉黑计数
SIGN_EXPIRED — HIGH key_version对应密钥已过期，不计入拉黑计数，提示对端使用KEY_RESYNC_REQUEST重签
SESSION_FLOOD — HIGH 单会话10s内200~300条仅告警，>300条限流30s。连续3个10s窗口维持200-300条自动升级限流
UPGRADE_REQUIRED — MEDIUM 旧格式报文在兼容截止日后被拒绝
TOKEN_SCOPE_INVALID — HIGH trust_token/status_token会话不匹配、操作不匹配
TOKEN_EXPIRED — MEDIUM trust_token已过期或次数耗尽
SIGN_ADMIN_INVALID — CRITICAL 管理员签名非法
SIGN_ADMIN_REPLAY — CRITICAL 管理员解锁报文重放攻击
CROSS_SESSION_QUERY_FORBIDDEN — HIGH 跨会话非法查询
EMERGENCY_OVERRIDE_UNAUTH — CRITICAL 无合法紧急管理员签名

### 4.3 细分故障码触发条件

F 文件类
F1：文件不存在 → 提示核对路径
F2：文件权限不足 → 请求授权
F3：磁盘空间不足 → 清理临时文件
F4：文件锁占用超时10s → R3故障码
F5：文件格式不兼容 → 格式转换提示
F6：文件读写超时 → 重试或跳过
F7：文件校验损坏 → 从备份恢复

A 应用类
A1：应用未安装 → 安装提示
A2：应用无响应 → 重启应用
A3：UI控件定位失败 → 降级执行
A4：应用版本不兼容 → 更新提示
A5：弹窗阻塞 → 自动关闭弹窗
A6：应用崩溃 → 恢复上下文重启

N 网络类
N1：DNS解析失败 → 切换DNS
N2：连接超时 → 切换备用接口
N3：HTTP4xx → 校验请求参数
N4：HTTP5xx → 指数退避重试
N5：SSL证书异常 → 安全风险告警
N6：带宽不足 → 降低并发

C 命令脚本类
C1：脚本语法错误 → 沙箱拦截
C2：高危系统调用 → 永久拦截
C3：脚本执行超时 → 强制终止
C4：注入风险 → 语义拦截
C5：脚本权限不足 → 沙箱降权

B 剪贴板类
B1：剪贴板占用 → 等待互斥锁
B2：剪贴板数据过大 → 分批传输
B3：剪贴板格式不支持 → 自动转换

R 并发资源类
R1：全局会话达上限 → 排队等待
R1-01：SESSION_FROZEN_FOR_SWITCH 会话接管冻结限流
R2：单会话并行达上限 → 降低并行度
R2-02：DAG拓扑非法（循环/孤儿依赖）→ 不可重试，终止会话
R3：资源锁等待10s超时 → 生成锁占用故障
R4：端口耗尽 → 等待复用连接
R5-GLOBAL_FUSE：全局熔断 → 拒绝新DAG任务

H 硬件外设类
H1：打印机离线缺纸 → 用户检查硬件
H2：外置存储移除 → 暂停关联任务
H3：音视频权限缺失 → 请求授权

## 五、总线约束规则

### 5.1 安全强制约束

1. ECC下发DAG REQUEST携带有效sign_ecc05与payload_hash，MCC-02校验通过后生成sign_mcc02存入上下文，双签名回填所有上行报文。
2. 缺失任一签名直接REJECT，写入审计日志。密钥轮换过渡期旧密钥签名失败不计入拉黑计数。SIGN_EXPIRED不计入拉黑计数。
3. L3任务ECC网关前置拦截，拦截事件生成AUDIT_LOG推送MemoryBus归档。报文异常流入总线则直接丢弃并告警。
4. 所有回执、熔断NOTIFY必须携带完整双签名。
5. SESSION_SWITCH必须携带device_sign和device_challenge配对签名。device_sign基于设备TPM/安全飞地根密钥派生，签名计算必须包含device_challenge。device_challenge同时进入总线HMAC签名，双重绑定，缺一不可。
6. OK回执发送前MCC必须强制WAL落盘，wal_status=wal_committed。ECC仅对此状态OK回执调用MemoryBus UNLOCK。
7. KEY_RESYNC_REQUEST必须携带sign_mcc02且与ref_msg_id原始报文session_id一致。ref_msg_id对应报文的源模块或目标模块与请求方模块必须一致，跨模块重签直接拒绝。恢复场景（operation_context=SESSION_RECOVERY且请求方为MCC-04或MCC-36）允许豁免跨会话限制。KEY_RESYNC_RESPONSE即确认原报文已被接受，MCC收到后不重传原报文。
8. 离线保守模式下首次用户确认后ECC先发送TRUST_TOKEN_ISSUE（含msg_id去重），收到TOKEN_CACHED_ACK后才可下发携带该token的DAG_DISPATCH。TOKEN_CACHED_ACK超时2s重发TRUST_TOKEN_ISSUE最多3次，重传使用相同msg_id。MCC维护独立token状态表（token→{status: ACTIVE|REVOKED}）。**TRUST_TOKEN_ISSUE签名强制绑定session_id，跨session使用直接拒绝**。token校验与状态更新采用读锁先行、串行互斥约束：撤销指令到达时立即拦截所有持有该token的在途/排队任务；**已进入执行阶段的任务允许正常跑完，不再拦截**。token有效期300s或10次使用以先到为准。签发前ECC检查session状态，不可执行时不签发。跨设备传输token必须走TLS加密。
9. SESSION_STATUS_QUERY返回status_token（有效期500ms），DAG_DISPATCH携带此token。MCC校验status_token有效且未过期。**status_token强制绑定session_id、仅允许用于DAG_DISPATCH、单次校验通过立即失效、禁止复用**。session状态变更时MCC先使status_token失效再变更状态。
10. force_takeover后，被Kill任务回执携带post_force_takeover:true及takeover_msg_id（force_takeover报文的msg_id）。MCC-02校验时验证takeover_msg_id对应接管操作真实存在且发生在60s内。回执豁免token校验，wal_status强制设为wal_force_unlock。回执接收窗口60s。
11. 全局熔断期间保留1个紧急session通道。仅L3安全级别操作可携带emergency_override:true。紧急任务单会话max_parallel=1，**EM-Core全局集群最多同时存在2条紧急DAG**。所有emergency_override=true任务必须附带emergency_admin_sign管理员独立RSA签名，签名有效期5s，无合法签名直接REJECT，故障码EMERGENCY_OVERRIDE_UNAUTH。
12. 管理员可通过SESSION_FORCE_UNLOCK_ADMIN报文强制释放会话全部资源锁。携带独立管理员RSA签名，无视24小时锁限制，写入最高等级安全审计日志。**管理员签名原文必须绑定msg_id+session_id+timestamp+operation，时间窗口10s，msg_id全局唯一禁止重放**。仅全局ECC-ADMIN网关持有管理员私钥，所有MCC模块不存储管理员私钥。

**签名生成规则补充**
· 签名算法：HMAC-SHA256。
· 密钥体系：首次启动基于设备TPM/安全飞地生成根密钥，ECC-05与MCC-02签名密钥由此派生，支持KEY_ROTATION在线轮换。
· 双密钥管理：MCC仅保留当前有效版本和最近一个直接前驱版本。key_version不等于当前版本且不等于前驱版本时，直接返回SIGN_EXPIRED，禁止验签链式回溯。
· 过渡期规则：key_version对应旧版本时，MCC先用旧密钥验签，失败再用当前版本密钥验签。旧版本报文增加timestamp新鲜度检查：报文timestamp距当前超过30s判定为重放，拒绝并写入安全审计。过渡期持续至activation_time+grace_period_sec，之后旧密钥立即失效。
· 报文分为两类：非恢复类携带payload_hash，完整签名覆盖header核心字段+payload_hash+trust_token+device_challenge；恢复类（SESSION_RECOVER、SESSION_SWITCH、FREEZE_ACK等）禁止携带payload_hash，携带body_hash，签名覆盖header核心字段+operation+session_id+body_hash+device_challenge。
· body_hash覆盖字段按operation类型定义，字段按Unicode码点字母序序列化（数字键视为字符串字母序，数组保持原序，null值字段加__null后缀参与序列化）：SESSION_RECOVER纳入unfinished_dag_ids+last_snapshot_time；FREEZE_ACK纳入lock_snapshot+freeze_expire_time；SESSION_SWITCH纳入transfer_dag_ids+target_device_id+force_takeover+active_trust_tokens+pending_trust_tokens+system_status。嵌套JSON对象递归应用字母序。
· 待签内容（所有头部安全控制字段完整纳入）：msg_id.timestamp.session_id.source.target.ext_version.key_version.sequence.chunk_group_id.chunk_index.chunk_total.payload_hash/body_hash.chunk_hash.trust_token.device_challenge.dag_id.operation.takeover_msg_id 分别Base64编码，顺序拼接。
· chunk_group内所有分片必须携带完全一致key_version。每个chunk独立计算chunk_hash，每个分片完整参与签名校验。重组时先校验所有分片哈希再合并校验总payload_hash。**分片重组超时/校验失败，立即清空当前chunk_group所有本地缓存，防止脏数据内存驻留**。

**报文校验顺序与防重放（全量修复）**
1. 校验顺序：格式与版本校验 → 按operation类型分支校验payload_hash或body_hash（空body报文跳过哈希校验）→ msg_id滑动窗口去重 → 时间戳偏移校验±60s → 签名校验（含trust_token scope）→ token有效性校验。
2. 防重放：NOTIFY使用布隆过滤器去重，**去重Key为session_id+operation+sequence三元组**。布隆过滤器容量100万条、30分钟自动清理；**占用达到95%容量时主动淘汰30%最早过期条目**，防止内存溢出。REQUEST、RESPONSE使用msg_id精确去重，滑动窗口上限10000条/300s过期。所有REQUEST报文双重校验：全局timestamp±60s + 单会话msg_id 30s新鲜度窗口，超出直接REJECT。跨设备切换时新设备通过MSG_LIST_QUERY向MLNF拉取原设备精确列表（超时5s），校验list_hash后合并窗口。**MSG_LIST_QUERY签名必须绑定目标查询session_id，签名与报文session_id不匹配直接拒绝，禁止跨会话窃取数据**。MSG_LIST_RESPONSE数据仅允许当前查询session使用，禁止跨session复用。
3. MSG_LIST_QUERY单次返回msg_id上限2000条，超限通过cursor/has_more分页拉取。合并窗口时总条目不可突破10000硬限制。CACHED列表仅合并300s内未过期msg_id，过期条目直接丢弃不加入窗口。
4. 会话洪水防护：单session 10s内msg_id超300条限流30s。连续3个10s窗口维持200-300条自动升级限流。限流与硬件降级取最严者独立生效。

**跨设备接管中止强制清理规则**
TAKEOVER_ABORT触发后，ECC必须批量下发TOKEN_REVOKE，撤销本次切换产生的所有active_trust_tokens、pending_trust_tokens，所有MCC节点立即标记对应token永久失效并写入安全审计。

**断电崩溃WAL原子兜底规则**
回滚两阶段WAL必须原子写入。无法原子写入的存储引擎先写临时预日志，双阶段全部完成再正式提交。系统重启扫描到「仅回滚开始、无清理完成」的半完成记录，自动执行完整资源释放、锁清理、快照回收，重置回滚进度为0，闭环恢复。

**版本兼容兜底行为**
收到 UPGRADE_REQUIRED 回执后，ECC 本地标记对端协议版本过低，停止下发新版格式报文，弹出版本升级提示，不再发起任何跨总线同步、任务下发请求。