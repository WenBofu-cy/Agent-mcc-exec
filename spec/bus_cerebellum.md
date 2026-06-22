# CerebellumBus 总线报文规范 V1.1
**EM-Core Agent · 认知层与执行层指令交互标准**
**版本**：V1.1 ｜ **日期**：2026-06-22
**适用中枢**：ECC（认知大脑） ↔ MCC（执行小脑）
**架构同源**：EM-Core HR人形机器人 / EM-Core AD自动驾驶

## 一、总线定位
CerebellumBus 是 ECC 认知大脑与 MCC 执行小脑唯一的指令通信通道。任务下发、DAG并行调度、故障回执、熔断信号、资源降级同步、会话状态同步及跨设备会话路由全部经由本总线流转。
**核心约束：**
1. ECC-12 网关为 REQUEST 报文唯一发送端；RESPONSE 与 NOTIFY 报文由 MCC 各模块主动上报，不受此限。
2. 所有业务指令采用请求-回执双报文模型；熔断、降级、心跳、跨设备同步为单向 NOTIFY 报文，ECC收到所有上行报文后回复极简ACK；总线报文统一重传与幂等规则。
3. 多会话报文基于 session_id 分片隔离处理，单会话 DAG 任务有序解析；FILE/CLIPBOARD/WINDOW/NETWORK资源锁全局统一等待超时10s。
4. ECC 下发 DAG 任务 REQUEST 报文须携带有效 sign_ecc05。MCC-02 校验 sign_ecc05 通过后即时生成 sign_mcc02 存入 DAG 上下文缓存，双签名同步用于回执、熔断、告警类报文，缺失任一签名直接丢弃并返回 REJECT 回执，写入审计日志。
5. L3 永久拦截级任务在 ECC-12 网关预处理阶段直接拦截，不下发至总线；拦截事件自动生成AUDIT_LOG通过MemoryBus归档。若因异常时序 L3 报文流入总线，MCC-02 识别 L3 标记后立即丢弃、上报安全告警。L3风险任务联动MemoryBus自动申请EXCLUSIVE排他记忆锁，禁止并行读取。
6. DAG全会话全部任务正常完成并返回OK回执后，ECC-12通过MemoryBus下发UNLOCK；跨设备SESSION_SWITCH携带force_takeover:true时，ECC同步向MemoryBus下发强制解锁指令，无视原设备在线状态。

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
| ------ |------ |------ |------ |
| msg_id | string | 是 | 全局唯一报文ID，格式 `cere-{date}-{time}-{seq}`，REQUEST、TASK_FEEDBACK用于幂等去重 |
| msg_type | enum | 是 | REQUEST下发任务 / RESPONSE回执结果 / NOTIFY单向通知 |
| source | string | 是 | REQUEST固定ECC-12；RESPONSE/NOTIFY为对应MCC模块编号 |
| target | string | 是 | 报文接收方模块编号 |
| session_id | string | 是 | 会话隔离标识，锁、并发、回执路由核心字段 |
| timestamp | ISO8601 | 是 | 严格保留三位毫秒精度.sssZ；本地时间偏差超±60s直接丢弃，响应携带offset_ms上报时钟异常 |
| ext_version | string | 是 | 协议版本固定"1.1"，主版本不同直接丢弃，次版本向前兼容 |

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
    "ext_version": "1.1"
  },
  "body": {
    "operation": "MSG_ACK",
    "ref_msg_id": "cere-20260621-152010-0001"
  }
}
```
### 2.5 回执状态枚举
- **OK**：全会话全部并行/串行任务执行完成且无故障。
- **PARTIAL_FAIL**：单分支子任务失败，其余分支正常完成，不触发记忆锁解锁。
- **GLOBAL_FAIL**：会话全局熔断、不可恢复故障。
- **TIMEOUT**：任务报文超30s未入队自动丢弃。
- **REJECT**：安全校验不通过、签名缺失、格式非法、L3高危拦截、Payload超限、DAG拓扑非法。
- **DEGRADE_LIMIT**：系统负载超限，并发限流拒绝任务。

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
#### DAG下发接收ACK报文
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
#### DAG下发拒收通知报文
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
### 3.2 单分支/全会话执行回执（MCC-36→ECC-12）
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
### 3.3 全局/局部熔断通知（MCC-33→ECC-12）
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
ECC主动下发（用户手动省电，优先级覆盖硬件自动降级）：
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
### 3.5 心跳卡死告警（MCC-37→ECC-12）
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
### 3.6 会话断点恢复同步（MCC-04→ECC-12）
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
### 3.7 跨设备会话同步通知（ECC-12→MCC-09）
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
- **F（文件类 F1~F7）**：路径校验、磁盘空间检查、提示用户更换路径。
- **A（应用类 A1~A6）**：检测软件安装状态、控件重定位重试。
- **N（网络类 N1~N6）**：自动重连、API指数退避最多3次。
- **C（命令脚本 C1~C5）**：高危脚本拦截、沙箱降权。
- **B（剪贴板 B1~B3）**：互斥锁等待、自动分批传输。
- **R（并发资源 R1~R5）**：降低并行度、排队等待；R5-GLOBAL_FUSE全局熔断，新任务直接DEGRADE_LIMIT拒绝。
- **H（硬件外设 H1~H3）**：外设离线提示、触发省电降级。
- **V1-01**：报文字段未知/类型不匹配，解析直接REJECT。
- **PAYLOAD_OVERSIZE**：REQUEST报文超过2MB，丢弃返回REJECT。
- **SIGN_INVALID**：签名校验失败，写入安全审计；单会话1分钟5次无效签名触发120s拉黑。
- **SESSION_FLOOD**：单会话10s msg_id超200条，限流30s丢弃全部入站报文。

### 细分故障码触发条件
- F1：文件不存在 → 提示核对路径
- F2：文件权限不足 → 请求授权
- F3：磁盘空间不足 → 清理临时文件
- F4：文件锁占用超时10s → R3故障码
- F5：文件格式不兼容 → 格式转换提示
- F6：文件读写超时 → 重试或跳过
- F7：文件校验损坏 → 从备份恢复
- A1：应用未安装 → 安装提示
- A2：应用无响应 → 重启应用
- A3：UI控件定位失败 → 降级执行
- A4：应用版本不兼容 → 更新提示
- A5：弹窗阻塞 → 自动关闭弹窗
- A6：应用崩溃 → 恢复上下文重启
- N1：DNS解析失败 → 切换DNS
- N2：连接超时 → 切换备用接口
- N3：HTTP4xx → 校验请求参数
- N4：HTTP5xx → 指数退避重试
- N5：SSL证书异常 → 安全风险告警
- N6：带宽不足 → 降低并发
- C1：脚本语法错误 → 沙箱拦截
- C2：高危系统调用 → 永久拦截
- C3：脚本执行超时 → 强制终止
- C4：注入风险 → 语义拦截
- C5：脚本权限不足 → 沙箱降权
- B1：剪贴板占用 → 等待互斥锁
- B2：剪贴板数据过大 → 分批传输
- B3：剪贴板格式不支持 → 自动转换
- R1：全局会话达上限 → 排队等待
- R2：单会话并行达上限 → 降低并行度
- R2-02：DAG拓扑非法（循环/孤儿依赖）→ 不可重试，终止会话
- R3：资源锁等待10s超时 → 生成锁占用故障
- R4：端口耗尽 → 等待复用连接
- R5-GLOBAL_FUSE：全局熔断 → 拒绝新DAG任务
- H1：打印机离线缺纸 → 用户检查硬件
- H2：外置存储移除 → 暂停关联任务
- H3：音视频权限缺失 → 请求授权

## 五、总线约束规则
### 5.1 安全强制约束
1. ECC下发DAG REQUEST携带有效sign_ecc05，MCC-02校验通过生成sign_mcc02存入上下文，双签名回填所有上行报文；校验失败返回REJECT。
2. 缺失任一签名直接REJECT，写入审计日志；单会话1分钟累计5次无效签名，临时拉黑源模块120s。
3. L3任务ECC网关前置拦截，拦截事件生成AUDIT_LOG推送MemoryBus归档；报文异常流入总线则直接丢弃并告警。
4. 所有回执、熔断NOTIFY必须携带完整双签名用于日志校验。
5. SESSION_SWITCH必须携带device_sign配对签名；force_takeover:true下发时，同步调用MemoryBus强制UNLOCK，MCC批量kill任务后推送FUSE_TRIGGER(BRANCH)携带全部终止task_id，ECC收到熔断通知判定原会话销毁完成。

#### 签名生成规则
- 签名算法：HMAC-SHA256。
- 预共享密钥：ECC-05与MCC-02独立密钥对。
- 待签内容区分两类报文：
  1. DAG_DISPATCH：msg_id、timestamp、session_id、operation、dag_id分别Base64编码，`.`顺序拼接；
  2. 其余报文：msg_id、timestamp、session_id、operation分别Base64编码拼接。
- 禁止将body.data内部字段纳入签名，载荷截断不破坏签名校验。
- sign_ecc05由ECC-05生成嵌入REQUEST；sign_mcc02校验后计算缓存，回填全部上行报文。

#### 报文校验顺序与防重放
1. 固定校验流程：格式&版本校验 → msg_id滑动窗口去重 → 时间戳偏移校验 ±60s → 签名校验；任意步骤失败直接丢弃返回REJECT。
2. msg_id滑动窗口双淘汰：上限10000条/2MB内存，LRU淘汰；条目超过300s自动过期删除，禁止无限缓存。
3. 会话洪水防护：单session 10s新增msg_id超过200条，触发SESSION_FLOOD限流，30s丢弃该会话全部入站报文。

### 5.2 并发时序约束
1. 全局最大并发会话8，单会话默认并行6；手动用户降级优先级高于硬件自动负载，上限取两者最小值。
2. 同session REQUEST串行排队，跨session分片并行；熔断、降级NOTIFY优先级高于普通DAG。
3. ECC下发DAG_DISPATCH等待DAG_ACK，2s未收到重传，最多3次；3次失败记录总线告警；收到DAG_REJECT_NOTIFY直接终止会话，DAG拓扑错误不可重试。
4. 存在SESSION全局熔断标记时，新DAG_REQUEST直接丢弃返回GLOBAL_FAIL。
5. 全会话全部任务无致命故障才返回OK回执，PARTIAL_FAIL不触发记忆锁解锁；ECC收到OK后调用MemoryBus UNLOCK。
6. 任务失败retry_count自增，上限3次停止重试上报故障。
7. MCC发送RESPONSE/上行NOTIFY后2s等待MSG_ACK，未收到则间隔翻倍重传(2s→4s→8s)，最多3轮；一轮重传结束冷却60s才可再次重传；3次失败写入WAL等待会话恢复同步。
8. ACK风暴防御：收到对应任务已销毁的过期MSG_ACK直接静默丢弃，不触发告警与重传。

### 5.3 资源与限流约束
1. 所有REQUEST Payload上限2MB，超限PAYLOAD_OVERSIZE拒绝；单DAG最多12个task节点。RESPONSE单条body上限500KB，超限仅允许截断data.trace等非关键日志占位，原始内存/WAL数据完整不可截断。
2. 批量回执单次最多50条任务结果。
3. DAG报文生存周期30s，超时TIMEOUT丢弃。
4. 用户弹窗120s无确认自动拒绝当前DAG。
5. FILE/CLIPBOARD/WINDOW/NETWORK锁统一最大等待10s，超时R3故障；多锁使用`FILE, NETWORK`逗号空格分隔格式。
6. 单task risk_level优先级高于外层DAG总等级，安全拦截取最高等级。

### 5.4 日志与幂等约束
1. WAL持久化统一留存7天，到期自动清理；WRITE、TASK_FEEDBACK可配置wal_write；FUSE_TRIGGER、SESSION_RECOVER、SESSION_SWITCH强制落盘；LOAD_DEGRADE、HEARTBEAT_STALL、各类ACK无需持久化。
2. REQUEST、TASK_FEEDBACK依靠msg_id幂等，重复报文直接复用缓存结果，不重复执行。
3. NOTIFY按session_id+operation状态去重，无状态变更消息合并丢弃防风暴。
4. 解析出现未知必填字段/类型不符返回V1-01，禁止填充默认值兼容。

## 六、全局资源锁枚举（lock_type）
| 枚举值 | 说明 |
| ------ |------ |
| FILE | 文件读写互斥锁 |
| CLIPBOARD | 剪贴板操作互斥锁 |
| WINDOW | 窗口焦点句柄互斥锁 |
| NETWORK | 网络带宽请求互斥锁 |
| NONE | 无资源锁（只读/沙箱隔离操作） |

## 七、版本规范
1. CerebellumBus V1.1与MemoryBus V1.1版本完全对齐，整套EM-Core总线版本统一。
2. ext_version固定"1.1"，主版本不匹配直接丢弃，次版本向前兼容。
3. 两套总线复用底层传输通道，业务报文隔离，支持联合升级。