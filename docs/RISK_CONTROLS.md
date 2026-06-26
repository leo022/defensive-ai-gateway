# 六大风险与对应控制（Demo 对照表）

Defensive AI Gateway 针对「受监管环境下的 agentic AI」在银行 SOC 落地的六类核心风险，
每类都有落地实现，而非仅停留在文档。

| # | 风险 | 说明 | 对应控制 | 实现位置 |
| --- | --- | --- | --- | --- |
| 1 | 幻觉与误判 | 本地小模型高置信但错误研判：把误报判成真实攻击，或「真实攻击」结论配全「信息」维度 | 证据锚定对齐（带 `evidence_assessment` 的样本以结构化真值为准，模型只能补充原因）；维度一致性校验 + 证据合成；确定性兜底分析器；Prompt 契约禁止编造事实 | `agents/base.py` `_reconcile_model_result`<br>`llm.py` `LocalHeuristicLLM` |
| 2 | 敏感数据泄露 | 客户凭证、卡号、会话等进入 prompt 或模型响应外泄 | 进 prompt 前字段脱敏；长度截断；原始告警只存本地 DB，prompt 仅拿脱敏摘要；`evidence_refs` 只读引用，不外泄原始敏感字段 | `policy.py` `redact` / `truncate_prompt_payload` |
| 3 | 越权与过度自主 | AI 直接执行封禁、隔离、停账号等高影响生产动作 | 默认只读模式；block/isolate/change_policy/disable_account 一律转 `approve_required`；响应动作仅 advisory，主机隔离走双签审批链 | `policy.py` `action_mode` |
| 4 | 提示注入与记忆投毒 | 攻击者构造告警操纵模型；错误误报判断被写成长期记忆，把真实攻击降级 | 脱敏前置降低注入面；长期记忆晋升闸门（缺 scope/expiry 直接阻断）；投毒可隔离/撤销，含冲突检测与到期清理；恶意分类不自动降级 | `memory.py` 晋升闸门 |
| 5 | 合规与可审计 | 无法解释 AI 判断、出事无法追溯 | 全链路留痕；结构化解释；确定性 case_id 便于关联复盘；离线回放同一路径 | `audit_log` / `agent_runs` / `memory_events`<br>`scripts/run_harness.py` |
| 6 | 模型依赖与供应链 | 绑定单一模型/厂商，内网离线无法联网调模型，依赖增加供应链成本 | LLM 可插拔（local/ollama/gateway）运行时可切；模型缺失降级确定性分析器；标准库优先 + SQLite 开箱即用 + 静态 Dashboard 无构建步骤；离线包迁移 | `llm.py` `build_llm`<br>`scripts/package_offline.sh` |

## 归纳

- **风险 1 / 5**：证据锚定 + 结构化对齐 + 全链路留痕 → 可解释与准确
- **风险 2 / 4**：脱敏前置 + 记忆晋升闸门 → 数据泄露与投毒
- **风险 3**：只读默认 + 审批闸 → 越权
- **风险 6**：可插拔模型 + 标准库 + 离线包 → 依赖与迁移

## Demo 演示映射

| 风险 | Demo 中可直接展示 |
| --- | --- |
| 1 | Dashboard Case 详情：研判结论 + 分维度证据（risk/blocked 而非全 info）；切换 ollama 后误报样本仍判 benign |
| 2 | 脱敏后证据列表不含 token/cookie；原始告警仅在本地 DB |
| 3 | 处置动作卡片显示 `approve_required` 而非「已执行」 |
| 4 | 记忆页：pending → 需晋升；恶意告警即使命中相似误报仍保留判断 |
| 5 | Agent Runs / Audit 记录完整可展开；Harness 回放确定性结果 |
| 6 | 配置页 ollama 模型下拉切换；模型断连时降级 local 仍出结论 |
