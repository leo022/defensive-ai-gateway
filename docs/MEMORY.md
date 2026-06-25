# 多层记忆管理（Multi-layer Memory）

本模块实现《银行业防御AI代理网关架构设计方案》第 8 章“三层记忆 + 一层证据”设计，并落地第 6 章 Memory Manager 与第 11 章记忆投毒控制。代码见 `defensive_ai_gateway/memory.py` 与 `database.py`。

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
- Dashboard 中“确认为业务误报”会调用 `/api/alerts/{alert_id}/confirm-false-positive`，从关联告警中抽取相似特征，写入一条可治理的长期误报记忆，并记录审计。

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

## 5. 数据模型

`memory_entries` 表（在原 schema 基础上扩展，含向前兼容迁移）：`memory_id, layer, namespace, retrieval_key, content, source_case_id, scope, trust_level, status, sensitivity_ok, approved_by, expires_at_ms, created_at_ms, updated_at_ms`。

`status` 取值：`active` / `pending_approval` / `expired` / `quarantined` / `revoked`。

`memory_events` 表：`event_id, memory_id, layer, event_type, actor, detail_json, created_at_ms`。

## 6. HTTP API（Dashboard 记忆治理模块）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/memory?layer=&status=&namespace=&retrieval_key=&limit=&include_expired=` | 列出记忆（默认只返回 live：active/pending） |
| GET | `/api/memory/events?memory_id=&event_type=&limit=` | 治理审计事件 |
| GET | `/api/memory/{memory_id}` | 单条记忆详情 |
| POST | `/api/memory/{memory_id}/promote` | `{approved_by, scope, expires_at_ms, retrieval_key?}` → `{ok, reasons, memory_id}` |
| POST | `/api/memory/{memory_id}/reject` | `{actor, reason}` |
| POST | `/api/memory/{memory_id}/quarantine` | `{actor, reason}` |
| POST | `/api/memory/sweep` | `{products?}` → 到期扫描 + 冲突检测 |
| POST | `/api/alerts/{alert_id}/confirm-false-positive` | Dashboard 人工确认误报，抽取特征并写入长期记忆 |

## 7. 范围与演进

- 当前检索为 SQLite 基于命名空间/检索键的精确匹配；向量检索（语义相似）与图谱实体关系属技术方案阶段 C（生产增强），此处预留层级与检索键，便于平滑替换。
- 组织知识默认值为内置只读种子；生产环境由安全治理团队通过评审维护，不应由 agent 自动改写。
- 当前 Dashboard 已能触发误报确认写入；完整治理界面（批量审批、冲突处理、过期复核列表）仍属于后续增强。
