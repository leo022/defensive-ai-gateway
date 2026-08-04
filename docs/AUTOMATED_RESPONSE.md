# 审批后自动化处置

## 1. 适用范围

当前迭代只支持一类动作：将告警证据中的来源 IP 通过 WAF 或边界防火墙临时封禁。
主机隔离、账号禁用、RASP 策略切换和永久封禁仍只生成建议，不会编译成执行任务。

处置链路不直接执行 LLM 输出。系统先从规范化事件中取得 `src_ip`，再把明确包含
“封禁/阻断来源 IP”语义的建议编译成结构化动作。审批人看到的对象、业务范围和时效
就是后续执行使用的内容；自由文本不会作为设备命令下发。

```text
告警证据 -> 研判建议 -> Validator -> 结构化动作 -> 审批达标
                                                |
                                                v
                            持久化处置任务 -> 连接器 -> 核验 -> 到期回滚
```

## 2. 安全控制

- 全局处置开关默认关闭。首次配置必须由配置管理员显式启用。
- 生产默认保持双人审批；处置任务只在最终一票使审批达到法定人数后创建。
- 配置、审批、处置执行使用不同角色。审批 Token 不能配置连接器或手工调度任务。
- 来源 IP 取自已持久化的规范化证据，不从建议文本中提取。
- 回环、链路本地、组播、未指定和保留地址不能成为封禁对象。
- 受保护网段在执行前再次检查。命中保护网段时会创建可见的失败任务和审计记录，
  不会静默跳过。
- 远程连接器必须使用 HTTPS；连接时执行 DNS 固定、禁用重定向并拒绝受限地址。
- 凭据只通过环境变量注入。数据库和浏览器只保存环境变量名。
- 每个任务冻结连接器版本、端点、模式、超时和凭据变量名。后续修改连接器不会改变
  已批准任务的下发或回滚目标。
- 下发、核验和回滚分别使用稳定且互不相同的幂等键。网络重试不会重复创建规则，
  回滚也不会被设备误判为下发请求的重复调用。
- 规则生效必须经过设备侧核验。TTL 从核验成功时开始计算，而不是从排队或审批时开始。
- Case 关闭或被确认误报后，尚未执行的任务会取消；已经生效的规则会进入补偿回滚。
- 全局开关关闭时停止新的下发，但不会阻止已经生效规则的到期或人工回滚。

## 3. 权限

| 角色 | 能力 |
| --- | --- |
| `config` | 新建或修改连接器、执行非变更性健康检查、修改处置策略 |
| `approver` | 对审批单投票，不能配置设备或手工调度 |
| `responder` | 查看处置任务、显式调度、人工回滚，不能修改连接器 |
| `read` | 查看连接器公开状态和任务，不可变更 |
| `api-admin` | break-glass 管理身份，具备全部角色；日常操作不应使用 |

生产环境增加独立的 `DEFENSIVE_AI_RESPONDER_TOKEN`。标准通用 Webhook 凭据变量为
`DEFENSIVE_AI_RESPONSE_CONNECTOR_TOKEN`，也可以使用其他符合大写环境变量命名规则的
变量名，但部署平台必须把该变量注入 Gateway 进程。

## 4. 执行模式

| 模式 | 最终审批后的行为 | 适用阶段 |
| --- | --- | --- |
| `shadow` | 生成完整任务和审计，不调用设备接口 | 联调、规则校验、上线观察 |
| `manual` | 进入待调度，由 `responder` 再确认后调用接口 | 初期生产、重大活动保障 |
| `auto` | 连接器健康且策略开启时立即排队执行 | 指标稳定且完成变更评审后 |

建议按 `shadow -> manual -> auto` 顺序推进。模式调整只影响之后审批的任务；既有任务
继续使用冻结的连接器快照。

若审批完成时尚未配置连接器，任务进入 `waiting_configuration`。连接器配置完成后，
必须由 `responder` 显式调度；该操作会先冻结当前唯一启用的连接器版本，然后执行。
系统不会把新配置自动套用到旧审批任务。

## 5. 连接器协议

连接器类型为 `generic_webhook`。Gateway 向配置的端点发送 `POST` JSON：

```json
{
  "operation": "apply",
  "idempotency_key": "operation-specific-sha256",
  "task_idempotency_key": "stable-task-sha256",
  "remote_rule_id": "",
  "action": {
    "action_type": "network.block_ip",
    "object": "43.154.138.159/32",
    "source_ip": "43.154.138.159",
    "scope": {
      "product": "rasp",
      "host": "106.53.107.29:8080",
      "path": "/bastestground/expression/ognl/postBody"
    },
    "duration_seconds": 1800,
    "reason": "临时封禁恶意来源 IP",
    "event_id": "event_example",
    "evidence_hash": "sha256",
    "version": 1
  }
}
```

HTTP 头同时携带 `X-Idempotency-Key`。配置了 `secret_env` 时还会携带
`Authorization: Bearer <environment value>`。

连接器需要实现四种操作：

| `operation` | 约束 | 成功响应 |
| --- | --- | --- |
| `health_check` | 不得修改设备状态 | `{"ok": true, "status": "healthy"}` |
| `apply` | 创建或复用临时规则 | `{"ok": true, "rule_id": "..."}` |
| `verify` | 查询规则是否真实生效 | `{"ok": true, "status": "active"}` |
| `rollback` | 按 `remote_rule_id` 删除规则 | `{"ok": true, "status": "removed"}` |

设备厂商 API 不符合该协议时，应在企业集成层实现一个薄适配服务。适配服务负责认证、
厂商字段映射、幂等规则和状态查询，不应让 Gateway 保存设备管理员密码。

## 6. 状态与恢复

主要状态如下：

- `waiting_configuration`：审批已完成，尚无连接器快照；
- `waiting_dispatch`：手工模式或后配置连接器，等待处置执行人调度；
- `paused`：全局开关关闭或连接器未通过健康检查；
- `queued` / `running` / `retry_wait`：等待执行、正在执行、瞬时错误退避；
- `verified`：远端规则已核验生效，等待到期或人工回滚；
- `shadowed`：影子模式已完成，不存在远端规则；
- `failed`：不可恢复错误或重试耗尽；若保留 `remote_rule_id`，可执行补偿回滚；
- `rollback_queued` / `rollback_running` / `rollback_retry`：回滚生命周期；
- `rolled_back`：远端规则已删除；
- `rollback_failed`：回滚重试耗尽，可由处置执行人再次发起。

HTTP `400/401/403/404/405/409/422` 视为配置或请求错误，不进行无限重试；`429`、
`5xx`、超时和网络错误采用有限指数退避。任务、每次尝试、响应摘要、远端规则 ID 和
审计事件均持久化到 SQLite，进程重启后可恢复。

## 7. 控制台配置顺序

1. 使用配置管理员身份进入“自动化处置 -> Playbook”，确认 Owner、适用产品、风险等级和 SLA 后发布版本。
2. 进入“连接器”，填写 HTTPS 动作端点、执行模式、TTL 上限、超时和凭据环境变量名。
3. 启用连接器并执行健康检查。非 `shadow` 模式必须显示健康后才能执行。
4. 进入“处置策略”，配置保护网段、默认 TTL 和全局最大 TTL。
5. 先启用全局开关，再通过授权测试告警完成审批。
6. 在“执行任务”认领任务，核对优先级、SLA、工单与资产上下文、对象、范围和连接器模式。
7. 在“Playbook -> 影子评估”记录人工决策，再验证到期回滚、Case 误报回滚和设备不可达恢复。
8. 只有达到预先约定的质量和风险门槛后，才考虑切换到 `manual` 或 `auto`。

## 8. P0 运营控制面

自动化处置工作台为每个任务维护以下运营字段：

- `priority`：低、中、高、紧急四级优先级；新任务默认继承其已发布 Playbook 的风险等级；
- `assignee` 与 `acknowledged_at_ms`：负责人和确认接手时间；
- `sla_due_at_ms` 与 `sla_completed_at_ms`：截止时间和不可变完成时间；后续补写备注不会改写历史 SLA；
- `handover_note`：跨班次交接信息；
- `ticket_ref`：外部工单编号；
- `asset_ref`、`asset_criticality`、`business_owner`：CMDB/资产业务上下文。

当前版本提供这些字段的人工维护与 API 回填契约，但不声称已经连接特定企业工单或 CMDB。
后续适配器应写入相同字段，并保留外部系统自身的认证、授权和变更记录。

任务列表支持按状态、优先级、负责人和 SLA 状态筛选。运营指标包括未认领、SLA 违约、
即将超时、确认接手、影子评价状态，以及已核验任务的 P50/P95 受控耗时。未认领和 SLA
积压只统计尚未完成受控目标的活动任务。

响应人员通过以下接口维护任务运营信息：

```text
POST /api/automation/tasks/{task_id}/operations
```

调用身份由服务端认证结果确定，客户端不能自行指定操作人。任务运营更新、Playbook 版本与
发布、影子评价及其审计记录在同一事务提交；审计写入失败时，业务状态一并回滚。

## 9. 版本化 Playbook 与影子评估

每个新任务必须绑定一个当时已发布、动作类型和产品范围匹配的 Playbook 版本。绑定后的
`playbook_id` 与 `playbook_version` 不会因后续编辑或发布而改变。产品专属 Playbook 优先于
通配 `*` Playbook。

Playbook 当前管理以下契约：

- 名称、说明、运营 Owner 和适用产品；
- 动作类型、风险等级和 SLA；
- 入口条件、验证、审批、执行、核验和回滚步骤的结构化定义；
- `draft`、`active`、`retired` 状态以及创建、发布身份和时间。

编辑操作始终生成新版本。只有显式发布后，新版本才可以绑定后续任务；发布新版本不会
修改历史任务。

```text
GET  /api/automation/playbooks
POST /api/automation/playbooks
POST /api/automation/playbooks/{playbook_id}/{version}/publish
```

影子模式任务完成后，系统自动生成唯一的 `response_shadow_evaluations` 记录。分析人员或
响应人员可以记录采纳、拒绝或需要调整，以及不少于 5 个字符的决策依据。评价只用于度量
和模式升级评审，不会反向触发生产动作。

```text
GET  /api/automation/shadow-evaluations
POST /api/automation/shadow-evaluations/{evaluation_id}/decision
```

影子评价只能决定一次，避免后续覆盖原始运营判断。模式从 `shadow` 提升到 `manual` 或
`auto` 前，应按 Playbook 版本审查采纳率、拒绝原因、SLA、执行核验与回滚结果。

## 10. 当前边界

本迭代只允许一个连接器处于启用状态，避免在缺少路由策略时把同一封禁下发到错误设备。
SQLite 和单执行线程适合当前 Demo 与小规模验证，不是高吞吐 SOAR 的最终形态。进入生产
扩展阶段后，应将任务租约和 Case 状态迁移到 PostgreSQL，将执行流放入具备分区和 DLQ 的
消息系统，并按租户、区域和安全设备建立连接器路由及并发限额。
