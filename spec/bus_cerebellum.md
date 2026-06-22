```markdown
# CerebellumBus 总线报文规范 V1.1

**EM-Core Agent · 认知层与执行层指令交互标准**

> 版本：V1.1 ｜ 日期：2026-06-22
> 适用中枢：ECC（认知大脑） ↔ MCC（执行小脑）
> 架构同源：EM-Core HR人形机器人 / EM-Core AD自动驾驶


## 一、总线定位

CerebellumBus 是 ECC 认知大脑与 MCC 执行小脑唯一的指令通信通道。任务下发、DAG并行调度、故障回执、熔断信号、资源降级同步、会话状态同步及跨设备会话路由全部经由本总线流转。

**核心约束：**

1. ECC-12 网关为 REQUEST 报文唯一发送端；RESPONSE 与 NOTIFY 报文由 MCC 各模块主动上报。
2. 所有业务指令采用请求-回执双报文模型；熔断、降级、心跳、跨设备同步为单向 NOTIFY 报文。
3. 多会话报文基于 session_id 分片隔离处理，单会话 DAG 任务有序解析。
4. ECC 下发 DAG 任务 REQUEST 报文须携带有效 sign_ecc05。MCC-02 校验 sign_ecc05 通过后即时生成 sign_mcc02 存入 DAG 上下文缓存，双签名同步用于回执、熔断、告警类报文，缺失任一签名直接丢弃并返回 REJECT 回执，写入审计日志。
5. L3 永久拦截级任务在 ECC-12 网关预处理阶段直接拦截，不下发至总线。若因异常时序 L3 报文已进入 CerebellumBus，MCC-02 校验 sign_ecc05 时识别到 L3 标记，立即丢弃且严禁入队，仅上报安全告警。


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
    "ext_version": "1.1"
  },
  "body": {}
}
```

### 2.2 头部字段定义

| 字段 | 类型 | 必填 | 说明 |
|------|------|:---:|------|
| msg_id | string | ✅ | 全局唯一报文ID，格式 `cere-{date}-{time}-{seq}`，用于幂等去重 |
| msg_type | enum | ✅ | REQUEST（下发任务）/ RESPONSE（回执结果）/ NOTIFY（单向通知） |
| source | string | ✅ | 发送方模块编号。REQUEST 固定为 ECC-12；RESPONSE 为 MCC-36；NOTIFY 为 MCC-33/MCC-37/MCC-04 等 |
| target | string | ✅ | 接收方模块编号 |
| session_id | string | ✅ | 会话隔离标识，锁、并发、回执路由核心字段 |
| timestamp | ISO8601 | ✅ | 报文生成时间，须保留三位毫秒精度（.sssZ），禁止省略 |
| ext_version | string | ✅ | 协议版本，固定 "1.1"。主版本不同直接丢弃，次版本向前兼容 |

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
    "ref_msg_id": "cere-20260621-152010-0001"
  },
  "body": {
    "status": "OK | PARTIAL_FAIL | GLOBAL_FAIL | TIMEOUT | REJECT | DEGRADE_LIMIT",
    "risk_level": "L0 | L1 | L2 | L3",
    "retry_count": 0,
    "lock_type": "",
    "wal_write": true,
    "sign_ecc05": "ec_sig_xxxxxx",
    "sign_mcc02": "mcc_sig_xxxxxx",
    "data": {},
    "fault": {
      "fault_code": "F1-404",
      "fault_category": "FILE",
      "severity": "MEDIUM",
      "message": "目标文件不存在"
    }
  }
}
```

### 2.4 回执状态枚举

| 状态码 | 说明 |
|--------|------|
| OK | 全会话全部并行/串行任务执行完成且无故障 |
| PARTIAL_FAIL | 单分支子任务失败，其余分支正常完成 |
| GLOBAL_FAIL | 会话全局熔断、不可恢复故障 |
| TIMEOUT | 任务报文超 30s 未入队自动丢弃 |
| REJECT | 安全校验不通过、签名缺失、负载超限、格式非法、L3 高危拦截 |
| DEGRADE_LIMIT | 系统负载超限，并发限流拒绝任务 |


## 三、核心操作报文定义

### 3.1 DAG 任务下发请求（ECC→MCC-01）

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
        },
        {
          "task_id": "task_02",
          "deps": ["task_01"],
          "op_type": "CODE_RUN",
          "params": {"script": "main.py"},
          "lock_type": "NONE",
          "risk_level": "L1"
        }
      ]
    }
  }
}
```

### 3.2 DAG 下发接收确认（MCC-01→ECC-12）

```json
{
  "header": {
    "msg_id": "cere-ack-xxxx",
    "msg_type": "NOTIFY",
    "source": "MCC-01",
    "target": "ECC-12",
    "session_id": "session_x",
    "timestamp": "2026-06-21T15:20:15.000Z",
    "ext_version": "1.1"
  },
  "body": {
    "operation": "DAG_ACK",
    "ref_msg_id": "cere-20260621-152010-0001"
  }
}
```

### 3.3 DAG 下发拒收通知（MCC-01→ECC-12）

```json
{
  "header": {
    "msg_id": "cere-rej-xxxx",
    "msg_type": "NOTIFY",
    "source": "MCC-01",
    "target": "ECC-12",
    "session_id": "session_x",
    "timestamp": "2026-06-21T15:20:16.000Z",
    "ext_version": "1.1"
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

### 3.4 单分支/全会话执行回执（MCC-36→ECC-12）

```json
{
  "header": {
    "msg_type": "RESPONSE",
    "source": "MCC-36",
    "target": "ECC-12"
  },
  "body": {
    "operation": "TASK_FEEDBACK",
    "dag_id": "dag-session_x-001",
    "risk_level": "L1",
    "retry_count": 0,
    "wal_write": true,
    "sign_ecc05": "ec_sig_xxxxxx",
    "sign_mcc02": "mcc_sig_xxxxxx",
    "finished_task_count": 2,
    "failed_task_count": 0,
    "all_task_finished": true,
    "branch_details": [
      {
        "task_id": "task_01",
        "status": "SUCCESS",
        "exec_ms": 1200,
        "lock_type": "FILE"
      }
    ]
  }
}
```

### 3.5 全局/局部熔断通知（MCC-33→ECC-12）

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

### 3.6 资源降级同步通知

**MCC 主动上报（负载超限）：**

```json
{
  "header": {"msg_type": "NOTIFY", "source": "MCC-37", "target": "ECC-12"},
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

**ECC 主动下发（用户手动开启省电模式）：**

```json
{
  "header": {"msg_type": "NOTIFY", "source": "ECC-12", "target": "MCC-37"},
  "body": {
    "operation": "LOAD_DEGRADE",
    "trigger_source": "USER",
    "allow_max_session": 2,
    "allow_single_parallel": 1
  }
}
```

### 3.7 心跳卡死告警（MCC-37→ECC-12）

```json
{
  "header": {"msg_type": "NOTIFY", "source": "MCC-37", "target": "ECC-12"},
  "body": {
    "operation": "HEARTBEAT_STALL",
    "session_id": "session_x",
    "stall_task_id": "task_02",
    "stall_duration_ms": 10500
  }
}
```

### 3.8 会话断点恢复同步（MCC-04→ECC-12）

```json
{
  "header": {"msg_type": "NOTIFY", "source": "MCC-04", "target": "ECC-12"},
  "body": {
    "operation": "SESSION_RECOVER",
    "session_id": "session_x",
    "unfinished_dag_ids": ["dag-session_x-001"],
    "last_snapshot_time": "2026-06-21T15:18:00.000Z"
  }
}
```

### 3.9 跨设备会话同步通知（ECC-12→MCC-09）

```json
{
  "header": {"msg_type": "NOTIFY", "source": "ECC-12", "target": "MCC-09"},
  "body": {
    "operation": "SESSION_SWITCH",
    "session_id": "session_x",
    "target_device_id": "device_macbook_pro_02",
    "transfer_dag_ids": ["dag-session_x-001"],
    "sync_timestamp": "2026-06-21T15:25:00.000Z",
    "device_sign": "dev_sig_xxxxxx",
    "force_takeover": false
  }
}
```


## 四、全局故障错误码体系

| 类别 | 前缀 | 说明 |
|------|:---:|------|
| F 文件 | F1-F7 | 路径校验、磁盘空间检查、权限、锁、格式、超时、完整性 |
| A 应用 | A1-A6 | 未安装、无响应、控件定位失败、版本不兼容、弹窗阻塞、崩溃 |
| N 网络 | N1-N6 | 域名解析、连接超时、客户端错误、服务端错误、SSL、带宽不足 |
| C 命令脚本 | C1-C5 | 语法错误、高危系统调用、执行超时、注入风险、权限不足 |
| B 剪贴板 | B1-B3 | 被占用、内容过大、格式不支持 |
| R 并发资源 | R1-R5 | 全局并发满、单会话并行满、锁等待超时、端口耗尽、全局熔断 |
| H 硬件外设 | H1-H3 | 未连接、电池不足、存储介质弹出 |


## 五、总线约束规则

### 5.1 安全强制约束

1. ECC 下发 DAG 任务 REQUEST 报文携带有效 sign_ecc05，MCC-02 校验通过即时生成 sign_mcc02 存入 DAG 上下文。双签名同步回填所有回执、熔断告警报文，校验不通过返回 REJECT。
2. 缺失任一签名直接返回 REJECT 状态回执，写入审计日志。
3. L3 永久拦截级任务在 ECC-12 网关预处理阶段直接拦截，不下发至总线。若报文异常流入总线，MCC-02 识别 L3 标记后丢弃并上报安全告警。
4. 所有回执、熔断类报文必须同步携带双签名用于日志归档校验。
5. 所有 SESSION_SWITCH 跨设备同步 NOTIFY 报文必须携带 device_sign 设备配对签名。目标设备存在未解锁 session 只读锁时直接丢弃报文并生成拒收通知。
6. 若拒收原因为锁未释放，ECC-12 判定原设备离线或卡死时，可下发携带 force_takeover: true 的二次接管报文。目标设备收到后必须强制释放本地只读锁、销毁本地 DAG 上下文，并立即向本地正在运行的所有相关 DAG 任务下发 HARD_KILL 信号。被 Kill 的任务严禁继续执行后续节点、严禁写入任何 WAL 日志，并立即向总线发送 GLOBAL_FAIL 回执。

#### 签名生成规则

- 签名算法：HMAC-SHA256。
- 签名密钥：ECC-05 与 MCC-02 各自持有预共享对称密钥。
- 待签内容区分两类报文：携带 dag_id 的 DAG_DISPATCH 将 header.msg_id、header.timestamp、header.session_id、body.operation、body.dag.dag_id 分别 Base64 编码，以 `.` 固定顺序拼接；其余无 dag_id 报文将 header.msg_id、header.timestamp、header.session_id、body.operation 分别 Base64 编码，以 `.` 拼接。
- 严禁将 body.data 及其内部字段纳入签名计算范围。
- 签名有效期绑定 msg_id 与 session_id，时钟偏差仅日志告警，不判定签名失效。
- sign_ecc05 由 ECC-05 生成嵌入 REQUEST；sign_mcc02 由 MCC-02 校验 ECC 签名后计算缓存，统一回填所有上行报文。

#### 报文防重放与校验顺序

1. 接收方校验顺序：格式与版本校验 → msg_id 滑动窗口去重校验 → 时间戳防重放校验 → 签名密码学校验。任何一步失败立即返回 REJECT 并丢弃。
2. 接收方维护 msg_id 滑动窗口去重队列：硬性上限 10000 条或 2MB，LRU 淘汰最旧记录；条目存放超 300s 自动过期删除。
3. 接收方校验 header.timestamp，若与本地时间偏差超过 ±60s，直接返回 REJECT 并丢弃报文。

### 5.2 并发时序约束

1. 全局最大并发会话固定 8，单会话最大并行任务默认 6，降级时取用户手动降级与硬件自动降级两者最小值。
2. 同 session 多条 REQUEST 串行排队处理，跨 session 报文分片并行解析。
3. 熔断、降级、锁相关 NOTIFY 报文优先级高于普通 DAG 任务。
4. ECC 下发 DAG_DISPATCH REQUEST 后等待 MCC-01 返回 DAG_ACK；2s 未收到自动重传，最多 3 次；收到 DAG_REJECT_NOTIFY 直接终止当前 DAG 流程。
5. MCC-01 接收 DAG_DISPATCH 后，MCC-05 必须对 task_nodes 进行拓扑校验：有向无环图检测、依赖引用完整性检测。任一失败返回 REJECT fault_code:R2-02 DAG_INVALID。
6. 存在 SESSION_GLOBAL 熔断标记时，该会话新接收 DAG_REQUEST 直接丢弃，返回 GLOBAL_FAIL 回执。
7. 仅当前全会话内全部串行、并行子任务执行完毕且无全局致命故障，MCC 才上报 OK 完整回执。存在 PARTIAL_FAIL 分支仅返回 PARTIAL_FAIL 回执，不会触发 MemoryBus 解锁。
8. 任务执行失败自动累加 retry_count，达到 3 次上限停止重试并上报故障。
9. ECC 收到 MCC 任意 RESPONSE 报文后回复携带 ref_msg_id 与 timestamp 极简 ACK；MCC 发出 RESPONSE 启动 2s 重传计时器，未收到 ACK 最多重传 3 次；3 次无应答转为 NOTIFY 推送并写入本地 WAL。

### 5.3 资源与限流约束

1. 所有 REQUEST 报文 Payload 上限 2MB，超限直接丢弃并返回 REJECT。单条 DAG 报文最多携带 12 个子任务。RESPONSE 单条 body 不得超过 500KB。
2. 总线单批次批量回执上限 50 条任务结果。
3. 任务报文生存周期 30s，超时未处理自动丢弃并返回 TIMEOUT 回执。
4. 高危弹窗 120s 无用户确认，MCC 自动拒绝当前 DAG 任务。
5. FILE/CLIPBOARD/WINDOW/NETWORK 四类资源锁最大等待超时 10s，超时生成 R3 故障码。
6. 单 task 的 risk_level 优先级高于外层 DAG 总 risk_level，安全校验时取层级最高值。
7. WAL 写入与截断策略：单条 TASK_FEEDBACK 回执若超过 500KB，允许将 data.trace 等非关键日志字段置为 `[TRUNCATED_DUE_TO_SIZE_LIMIT]` 占位符，保留原字段键名维持双签名校验完整性。截断仅允许在总线报文组装阶段执行，MCC 内存原始执行结果与 WAL 持久化记录保持完整。

### 5.4 日志与幂等约束

1. WAL 持久化规则：REQUEST、TASK_FEEDBACK 执行报文 wal_write 标记可配置；FUSE_TRIGGER、SESSION_RECOVER、SESSION_SWITCH 三类 NOTIFY 强制写入 WAL；LOAD_DEGRADE、HEARTBEAT_STALL、DAG_ACK、DAG_REJECT_NOTIFY 无需持久化。WAL 本地记录留存 7 天，到期自动清理。
2. 依靠 msg_id 实现执行类报文幂等校验，重复接收相同 msg_id 直接丢弃。
3. NOTIFY 类报文按 session_id+operation 做状态去重，未变更重复消息自动合并丢弃。
4. 接收方解析报文发现未知必填字段或字段类型不符，返回 REJECT CODE:V1-01。

### 5.5 单向 NOTIFY 报文重传与 ACK 规则

1. 熔断、降级、心跳、会话恢复等 NOTIFY，ECC 接收后回复极简 ACK（携带 ref_msg_id、timestamp）。
2. MCC 未收到 ACK 则 2s 间隔重传，后续重传间隔翻倍（2s→4s→8s），最多重传 3 次；全部失败写入本地持久化日志。
3. ACK 风暴防御：MCC 收到 ECC 极简 ACK，若对应 msg_id 任务已清理，直接静默丢弃 ACK。


## 六、全局资源锁枚举

| 枚举值 | 说明 |
|--------|------|
| FILE | 文件读写互斥锁 |
| CLIPBOARD | 剪贴板操作互斥锁 |
| WINDOW | 窗口焦点与句柄操作互斥锁 |
| NETWORK | 网络请求与带宽占用互斥锁 |
| NONE | 无资源锁（只读或沙箱内操作） |


## 七、版本规范

1. 本规范 CerebellumBus V1.1 与 MemoryBus V1.1 协议版本对齐，整套 EM-Core 总线体系版本号统一。
2. 报文头部 ext_version 固定为 "1.1"，主版本不一致直接丢弃，次版本向前兼容。
3. CerebellumBus 与 MemoryBus 共用底层传输通道，业务报文隔离，支持联合升级。
```