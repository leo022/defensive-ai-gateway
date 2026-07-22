# 多层记忆管理（Multi-layer Memory）

本模块实现《银行业防御AI代理网关架构设计方案》第 8 章"四层记忆 + 一层证据"（case_short_term / product_long_term / asset_profile / org_knowledge + evidence）设计，并落地第 6 章 Memory Manager 与第 11 章记忆投毒控制。生命周期治理见 `defensive_ai_gateway/memory.py`，跨模型关联见 `memory_matcher.py`，持久化见 `database.py`。

端到端架构图与 memory 在 alert processing 中的位置见 `docs/DEMO_ARCHITECTURE.md`。

## 1. 记忆层级

| 层级 | 常量 | 命名空间 | 检索键 | 治理规则 |
| --- | --- | --- | --- | --- |
| 短期 Case 记忆 | `case_short_term` | `case/{case_id}` | `case_id` / `trace_id` | Case 关闭后压缩归档；重要结论需人工确认后才晋升 |
| 产品长期记忆 | `product_long_term` | `product/{product}` | `product` / `rule_id` / `asset_type` | 按季度复核；过期自动降权 |
| 资产画像记忆 | `asset_profile` | `asset/{asset_id}` | `asset_id` / `app_id` / `owner` | 来自 CMDB/流量基线/工单/反馈；敏感字段最小化 |
| 组织知识记忆 | `org_knowledge` | `org/{scope}` | `policy` / `playbook` / `department` | 安全治理团队维护，变更走评审 |
| 证据库（只读） | `evidence` | — | `immutable evidence_ref` | 不可被 agent 修改；模型只读取脱敏摘要或引用 |

证据库为逻辑只读层：`MemoryManager.load_evidence(case_id)` 直接从 `normalized_events.evidence_json`（经 normalizer 脱敏、不可变）读取引用与摘要，agent 不能写入。

## 2. 写入与检索

- 每次 Agent 分析后，`record_case_summary()` 写入一条短期 Case 记忆（24h TTL），并对产品长期记忆提出一条 `pending_approval` 候选——**不自动晋升**。
- `load_context(product, case_id, asset_id)` 返回结构化多层上下文：`{case_short_term, product_long_term, asset_profile, org_knowledge, evidence_refs}`，由 orchestrator 注入 Agent prompt。
- `asset_id` 由事件实体（host/app/src_ip）派生，用于检索资产画像。
- Dashboard 中“确认为业务误报”会调用 `/api/alerts/{alert_id}/confirm-false-positive`，从关联告警中抽取相似特征，写入一条可治理的长期误报记忆，并记录逐告警 disposition。多告警 Case 只有全部关联告警均被确认误报后才关闭。

### 2.1 后续告警关联

`MemoryMatcher` 在调用 Local/Ollama/Gateway 之前统一执行，流程如下：

1. 从同产品 `product/{product}` 中召回最多 `candidate_limit` 条候选；只允许 `active`、`medium/high` 信任、人工批准、未过期且通过敏感性检查的产品长期记忆。
2. 对规则 ID、事件类型、应用、资产、URI 模板、进程、客户端、网络和账号计算加权结构化包含度。
3. 使用离线稳定哈希向量计算文本余弦相似度；该接口可替换为企业 Embedding 服务，默认实现不需要网络或第三方依赖。
4. 检查 `retrieval_key` 精确命中，并对规则/事件类型冲突施加负向惩罚。
5. 按配置权重合成总分，只把达到 `review_threshold` 的 Top-K 记忆注入模型上下文。
6. 模型返回后执行确定性合并：高分可支持 `suspicious → benign`；当前告警中可核验的攻击证据拥有否决权，模型仅自报 `malicious` 不能替代证据门禁。
7. 所有被评分候选写入 `memory_matches`，保留分项分数、排名、命中特征、决策和最终影响。

默认总分公式：

```text
overall = 0.68 * structured + 0.22 * semantic_vector + 0.10 * retrieval_key
```

默认 `review_threshold=0.58`、`apply_threshold=0.78`。配置位于 `memory_matching`，在切换 LLM 后端时保持一致。

## 3. 晋升五门禁（Promotion Rule）

短期/候选记忆晋升为产品长期记忆必须同时满足五条（`MemoryManager.promotion_check`）：

1. `evidence_traceable` —— 存在 `source_case_id` 且该 Case 有不可改证据引用；
2. `analyst_approved` —— 指明 `approved_by`（分析师确认）；
3. `scope_clear` —— 适用范围 `scope` 非空；
4. `expiry_set` —— 设置 `expires_at_ms`（过期时间明确）；
5. `no_sensitive_leak` —— 内容经 `PolicyEngine.redact` 不发生变化（无敏感字段泄露）。

任一不满足则 `promote()` 返回 `ok=False` 及原因列表，并写 `rejected` 事件；全部满足则状态置 `active`、信任级 `medium`，写 `promoted` 事件。

## 4. 治理操作（§6 Memory Manager / §11 记忆投毒）

- `expire_due(now)` —— 扫描到期记忆，置 `expired` 并降权（自动归档/降权）。
- `quarantine(memory_id, actor, reason)` —— 低可信/疑似投毒记忆隔离，置 `quarantined`、信任级 `low`。
- `detect_conflicts(product)` —— 检测同产品下重复/冲突长期记忆，对重复项隔离并记 `conflict_detected`。
- `review_overdue(layer)` —— 标记超过季度复核窗口的长期记忆待复核。
- `archive_case(case_id)` —— Case 关闭时压缩归档其短期记忆。
- 所有操作均写 `memory_events` 审计（proposed/promoted/rejected/expired/quarantined/conflict_detected）。

### Case 与长期记忆的生命周期联动

- 长期候选通过五门晋升为 `active` 后，若来源 Case 仍为 `open`，系统将其推进为 `under_review`，并写入 Case 审计；晋升本身不会自动关闭 Case 或确认攻击。
- Case 进入终态 `closed` 或 `false_positive` 时，其尚未晋升的产品长期候选会转为 `expired`，并记录 `source_case_terminal_before_promotion`。已晋升的 `active` 长期记忆不受此操作影响，仍按自身有效期和治理流程管理。

## 5. 数据模型

`memory_entries` 表（在原 schema 基础上扩展，含向前兼容迁移）：`memory_id, layer, namespace, retrieval_key, content, source_case_id, scope, trust_level, status, sensitivity_ok, approved_by, expires_at_ms, created_at_ms, updated_at_ms`。

`status` 取值：`active` / `pending_approval` / `expired` / `quarantined` / `revoked`。

`memory_events` 表：`event_id, memory_id, layer, event_type, actor, detail_json, created_at_ms`。

`memory_matches` 表：持久化 `event_id / alert_id / case_id / analysis_run_id / memory_id`，以及 matcher 版本、排名、结构化/语义/检索/综合分、决策、最终影响、匹配特征和分项得分。当前整体 Schema 为 v8，可从旧库自动向前迁移。

## 6. HTTP API（Dashboard 记忆治理模块）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/memory?q=&layer=&status=&namespace=&retrieval_key=&limit=&include_expired=` | 关键词与结构化条件检索（默认只返回 live：active/pending） |
| GET | `/api/memory/summary` | 返回总量、状态/层级/信任级分布、30 天内到期数与逾期复核数 |
| GET | `/api/memory/events?memory_id=&event_type=&limit=` | 治理审计事件 |
| GET | `/api/memory/matches?memory_id=&event_id=&case_id=&decision=&limit=` | 查询告警与长期记忆的评分关联记录 |
| GET | `/api/memory/{memory_id}` | 单条记忆详情、五门禁结果及该条记忆的审计事件 |
| POST | `/api/memory/{memory_id}/promote` | `{approved_by, scope, expires_at_ms, retrieval_key?}` → `{ok, reasons, memory_id}` |
| POST | `/api/memory/{memory_id}/reject` | `{actor, reason}` |
| POST | `/api/memory/{memory_id}/quarantine` | `{actor, reason}` |
| POST | `/api/memory/{memory_id}/restore` | `{actor, reason, expires_at_ms?}` → 门禁通过则恢复生效，否则回到待审批 |
| POST | `/api/memory/sweep` | `{products?}` → 到期扫描 + 冲突检测；未指定产品时扫描全部产品 |
| POST | `/api/alerts/{alert_id}/confirm-false-positive` | Dashboard 人工确认误报，抽取特征并写入长期记忆 |

Dashboard 的“记忆治理”工作台提供治理概览、关键词及层级/状态/命名空间组合筛选、结构化详情、五门禁可视化、晋升/撤销/隔离/恢复操作、全产品治理扫描、关联告警得分拆解，以及单条和全局审计时间线。操作人由 Bearer Token 对应的服务端身份写入，客户端提交的 actor 会被覆盖；撤销、隔离和恢复仍必须填写治理理由。

## 7. 范围与演进

- 当前语义分使用进程内哈希向量，适合离线部署和确定性回放；大规模生产环境可替换为企业 Embedding + pgvector/专用向量库，`MemoryMatcher`、阈值合并和 `memory_matches` 审计契约无需改变。
- 组织知识默认值为内置只读种子；生产环境由安全治理团队通过评审维护，不应由 agent 自动改写。
- 当前 Dashboard 已覆盖单条记忆的完整生命周期治理；批量审批、语义聚类冲突合并和外部知识库同步属于后续增强。
