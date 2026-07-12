# 第二阶段 Defense AI Agent 设计

## 1. 阶段边界

本阶段在现有只读分析 Demo 上补齐 `Skill Registry -> Product Agent -> Validator -> Response Advisor -> Approval` 纵向闭环。网关可以生成、验证和审批处置建议，但不执行封禁、隔离、策略变更或 SOAR 动作。`approved` 只表示既有处置流程获得授权，数据库以约束强制 `execution_status=not_executed`。

真实 CMDB、IAM、SOAR、工单系统和 PostgreSQL 适配属于后续企业集成，不在本阶段用模拟网络调用冒充完成。

## 2. 运行链路

1. Orchestrator 根据产品选择唯一、版本化的分析 Skill。
2. Product Agent 基于归一化证据、已治理记忆和产品提示词生成结构化结论。
3. Validator 确定性检查输出契约、证据存在性、提示注入、敏感输出、动作权限和 Skill 边界。
4. `blocked` 和 `review` 均不进入审批队列；只有 `passed` 可交给 Response Advisor。
5. 高风险真实攻击达到阈值时，Response Advisor 生成带理由和回滚条件的 `approve_required` 请求。
6. Agent Run、Validation、Approval、Memory Summary 和 Audit 在同一事务中提交。
7. 分析师可批准、拒绝或取消 pending 请求。决定为单向状态迁移，不能二次改判。

## 3. Skill 契约

`defensive_ai_gateway/skills.py` 注册 WAF、RASP、HIPS、NDR、SIEM 五个产品 Skill，以及 Validator 和 Response Advisor Skill。清单包含：

- `name/version/owner/product/capability`
- `risk_level`
- `allowed_inputs/allowed_tools/blocked_tools`
- `output_schema/memory_namespace`

注册时 fail closed：每个 Skill 必须显式禁止 `execute_production_action`，同一工具不能同时出现在 allowlist 和 blocklist，产品分析必须恰好解析到一个 Skill。

## 4. Validator 门禁

状态含义：

- `passed`：所有确定性检查通过，可生成审批建议。
- `review`：发现提示注入或非阻断证据缺口，只保留分析结果供人工复核。
- `blocked`：输出契约、敏感数据、高风险证据或动作权限违规，禁止生成审批。

Validator 不调用 LLM，避免由同一个概率模型自证正确。验证结果完整保存在 `validation_runs`，并写入 AgentResult explanation 供 Harness 和 Dashboard 使用。

## 5. 审批状态机

```text
pending -> approved
        -> rejected
        -> cancelled
```

仅 `pending` 可以决定，且 `actor` 与 `reason` 必填。没有 `execute` API，`action_approvals.execution_status` 由数据库 CHECK 固定为 `not_executed`。后续接入 SOAR 时应新增独立、签名校验的执行回写表，而不是放宽该约束。

## 6. API

- `GET /api/skills`：读取当前 Skill 清单。
- `GET /api/approvals?case_id=&status=&limit=`：查询审批队列。
- `POST /api/approvals/{approval_id}/decision`：提交 `decision/actor/reason`。
- `GET /api/cases/{case_id}`：额外返回 `validation_runs` 和 `approvals`。

上述 Skill、审批读取和所有写接口遵循现有 Bearer Token/loopback 鉴权策略。

## 7. 验收

```bash
python3 -m unittest discover -s tests -p 'test_phase2.py' -v
python3 scripts/run_harness.py --samples samples --fail-on-validation-review
```

专项测试覆盖 Skill 最小权限、提示注入、动作越权、验证与审批原子持久化、重复告警幂等、审批单向迁移及永不标记执行。
