# 技术方案：外网开发到企业内网部署

## 1. 总体策略

第一阶段构建一个低依赖、可审计、可离线迁移的 MVP。外网开发环境用于快速迭代代码、测试样例、Dashboard 与适配器接口；企业内网部署时先以同一代码包运行，再逐步替换企业级组件。

本仓库的当前 demo 架构、处理时序、Dashboard、Harness、数据库和安全控制详见 `docs/DEMO_ARCHITECTURE.md`。

## 2. 分阶段架构

### 阶段 A：离线友好 MVP

- 运行时：Python 3.11+，仅标准库。
- API：内置 HTTP server，接收产品告警。
- 数据库：SQLite。
- Dashboard：静态 HTML/CSS/JS，支持 Case 展开、日志适配 Profile 配置与 dry-run、LLM 配置、浅色/深色模式与误报确认写入记忆。
- LLM：默认本地规则分析器，保留企业 LLM Gateway HTTP 适配器。
- Demo LLM：外网开发可使用本地 Ollama `gemma3:4b` 或同等 4B 级别模型验证提示词、结构化输出和 agent 编排。
- 安全动作：只读分析，处置动作只生成审批建议。

### 阶段 B：企业 PoC

- 将 SQLite 切换为 PostgreSQL。
- 将直接 HTTP 接入扩展为 Kafka/SIEM webhook/API。
- 将本地规则分析器切换为企业 LLM Gateway。
- 引入统一身份、mTLS、反向代理、集中日志和机密管理。

### 阶段 C：生产增强

- 引入 OPA/ABAC 策略服务。
- 引入向量库和图谱，用于记忆和实体关系。
- 接入 SOAR/工单系统，但保持高影响动作人工审批。
- 建立 Harness 回放集，作为 prompt、skill、模型和工具权限变更门禁。

## 3. 核心模块

- `app.py`：HTTP API 与 Dashboard。
- `orchestrator.py`：事件进入后的 agent 编排。
- `normalizer.py`：产品字段归一化。
- `log_adapter.py`：真实日志格式适配层，通过可配置 Mapping Profile 转换为内部稳定 `RawAlert`，并提供 dry-run 门禁。
- `agents/`：HIPS、RASP、NDR、WAF、SIEM 专属 Agent。
- `policy.py`：脱敏、只读策略、动作审批判定。
- `memory.py`：多层记忆管理（短期 Case / 产品长期 / 资产画像 / 组织知识 + 不可改证据库），含晋升五门禁与去毒/过期/冲突治理，详见 `docs/MEMORY.md`。
- `llm.py`：本地分析器与企业 LLM Gateway 适配器。
- `database.py`：SQLite schema 与仓储。
- `static/`：零构建 Dashboard，读取 `/api/health`、`/api/cases`、`/api/config/llm`、`/api/mapping-profiles` 与误报确认 API。
- `scripts/run_harness.py`：离线回放入口，与 HTTP 服务共用 orchestrator / normalizer / memory / LLM 运行路径，详见 `docs/HARNESS.md`。

## 4. 内网替换点

| MVP 组件 | 内网生产替换 |
|---|---|
| SQLite | PostgreSQL / 企业关系库 |
| 内置 HTTP | API Gateway + mTLS / Kafka Consumer |
| Mapping Profile | 企业日志标准 / 数据接入平台字段映射 |
| LocalHeuristicLLM | 企业 LLM Gateway / 私有模型服务 |
| 静态 Dashboard | 企业前端框架或 SOC Portal 嵌入 |
| 简单策略判断 | OPA / IAM / ABAC / SOAR 审批 |
| JSON 样例回放 | Harness 样本库 + CI 门禁 |

## 5. 安全控制

- 默认只读分析，不直接执行生产阻断。
- 所有原始事件入库，进入 prompt 前做字段脱敏。
- 每个 Agent 使用独立提示词与记忆命名空间。
- 所有 Agent Run、LLM Call、策略拦截和建议动作必须留痕。
- 高影响动作必须标记为 `approve_required`。

## 5.1 六大风险与对应控制

本网关本质是为「受监管环境下的 agentic AI」设计：上述安全控制针对 AI Agent 在
银行 SOC 落地时的六类核心风险。每类风险都已有落地实现，而非仅停留在文档。

| # | 风险 | 说明 | 对应控制（实现位置） |
| --- | --- | --- | --- |
| 1 | 幻觉与误判 | 本地小模型高置信但错误研判（误报判成攻击，或「真实攻击」结论配全「信息」维度） | 证据锚定对齐 `agents/base.py: _reconcile_model_result`（带 `evidence_assessment` 的样本以结构化真值为准）；维度一致性校验 + 证据合成；确定性兜底 `llm.py: LocalHeuristicLLM`；Prompt 契约禁止编造事实 |
| 2 | 敏感数据泄露 | 客户凭证、卡号、会话进入 prompt 或响应外泄 | `policy.py: redact` 进 prompt 前脱敏 password/token/cookie/authorization/customer_id/id_card/phone/email/session；`truncate_prompt_payload` 长度截断；原始告警只存本地 SQLite，prompt 仅拿脱敏摘要；`evidence_refs` 只读引用 |
| 3 | 越权与过度自主 | AI 直接执行封禁、隔离、停账号等高影响生产动作 | 默认 `mode: read_only`；`policy.py: action_mode` 把 block/isolate/change_policy/disable_account 一律转 `approve_required`；响应动作 advisory，主机隔离走双签审批链 |
| 4 | 提示注入与记忆投毒 | 攻击者构造告警操纵模型，或错误误报判断被写成长期记忆，把真实攻击降级 | 脱敏前置降低注入面；`memory.py` 晋升闸门 `evidence_traceable/analyst_approved/scope_clear/expiry_set/no_sensitive_leak`（缺 scope/expiry 阻断晋升）；投毒可 quarantine/revoke，含冲突检测与到期 sweep；恶意分类不自动降级 |
| 5 | 合规与可审计 | 无法解释 AI 判断、出事无法追溯 | 全链路留痕 `audit_log`/`agent_runs`/`memory_events`；结构化解释（classification/confidence/verdict/分维度证据/缺失证据）；确定性 `case_id` 便于关联复盘；Harness 离线回放同一路径 |
| 6 | 模型依赖与供应链 | 绑定单一模型/厂商，内网离线无法联网调模型，依赖增加供应链成本 | LLM 可插拔 `llm.py: build_llm`（local/ollama/gateway），运行时可切；模型缺失降级确定性分析器；标准库优先 + SQLite 开箱即用 + 静态 Dashboard 无构建步骤；`scripts/package_offline.sh` 离线包迁移；`OLLAMA_ANALYSIS_SCHEMA` 约束输出 |

归纳：

- **风险 1 / 5** 靠「证据锚定 + 结构化对齐 + 全链路留痕」解决可解释与准确。
- **风险 2 / 4** 靠「脱敏前置 + 记忆晋升闸门」解决数据泄露与投毒。
- **风险 3** 靠「只读默认 + 审批闸」解决越权。
- **风险 6** 靠「可插拔模型 + 标准库 + 离线包」解决依赖与迁移。

## 6. 当前 Demo 数据流

1. HIPS/RASP/NDR/WAF/SIEM 或样例脚本提交标准 `RawAlert`，或提交真实日志并指定 `mapping_profile`。
2. `LogAdapter` 按 Mapping Profile 抽取字段、映射严重级别/产品类型、校验必填字段；失败则拒绝进入 LLM。
3. `PolicyEngine` 对进入 prompt 的字段做脱敏与长度限制。
4. `EventNormalizer` 抽取实体、证据和敏感标签。
5. `Orchestrator` 生成 deterministic `case_id`，关联 raw alert 与 normalized event。
6. `MemoryManager` 加载 Case 短期、产品长期、资产画像、组织知识和 evidence refs。
7. 产品 Agent 调用 `LocalHeuristicLLM`、Ollama 或企业 LLM Gateway，并输出结构化 `AgentResult`。
8. SQLite 写入 `cases`、`agent_runs`、`audit_log`、`mapping_profiles` 和多层记忆候选。
9. Dashboard 通过本地 API 展示统计、Case、适配状态、证据、Agent 运行记录和 LLM 配置。
