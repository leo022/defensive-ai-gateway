# Harness 回放说明

`scripts/run_harness.py` 用于在不启动 HTTP 服务的情况下，把 `samples/*.json` 全量回放一遍，验证归一化、agent 路由、LLM 适配、记忆写入和结构化输出是否仍可工作。

Harness 与 HTTP Dashboard 服务共用 `Orchestrator`、`EventNormalizer`、`MemoryManager`、`PolicyEngine` 和 LLM client。架构关系见 `docs/DEMO_ARCHITECTURE.md` 的 Harness Architecture。

## 本地运行

```bash
python3 scripts/run_harness.py --samples samples
```

可选地设置最低置信度门槛：

```bash
python3 scripts/run_harness.py --samples samples --fail-on-low-confidence 0.5
```

第二阶段可同时启用 Validator 发布门禁；任何 `review` 或 `blocked` 都会让回放以非零状态退出：

```bash
python3 scripts/run_harness.py --samples samples --fail-on-validation-review
```

使用配置中的 LLM provider，例如默认的本地规则分析器，或手动切换后的本地 Ollama：

```bash
python3 scripts/run_harness.py --samples samples --config config/dev.yaml --use-config-llm
```

当前开发配置默认使用 `local-rule-analyst`，无需启动 Ollama。如果把 provider 切换为 `ollama`，可使用 `http://127.0.0.1:11434/api/generate` 这类本地端点；当模型名为 `gemma3:4b` 但本机只有 `gemma3:latest` 时，适配器会自动降级并在结果中标记 fallback。

## 真实日志适配回放

如果样本不是内部标准 `RawAlert` 格式，而是内网真实告警日志格式，可先用 Mapping Profile 转换后再进入同一分析链路：

```bash
python3 scripts/run_harness.py --samples real_logs/rasp --mapping-profile demo-rasp-json
python3 scripts/run_harness.py --samples real_logs/rasp --mapping-profile-file config/rasp-prod-profile.json
```

`--mapping-profile` 使用内置 demo profile；`--mapping-profile-file` 使用自定义 JSON profile。映射失败时 harness 会直接退出，不会让字段缺失或产品类型错误的日志进入 LLM 分析。

## 随机样例

Harness 可附加随机生成的攻击或误报告警，用于观察同一产品下不同特征的 case 聚合、agent 路由和本地分析器表现：

```bash
python3 scripts/run_harness.py --samples samples --random-count 10 --random-scenario random --seed 42
python3 scripts/run_harness.py --samples samples --random-count 5 --random-product waf --random-scenario attack
python3 scripts/run_harness.py --samples samples --random-count 5 --random-product waf --random-scenario false_positive
python3 scripts/run_harness.py --samples samples --random-count 5 --random-product waf --random-scenario false_positive --seed-demo-memory
```

`--seed` 用于复现同一批随机样例。`--random-scenario` 支持 `random` / `attack` / `false_positive`。

## 记忆辅助误报分辨

默认本地分析器会读取注入 prompt 的 `product_long_term` 记忆。只有 `status=active` 且信任级别不是 `low` 的产品长期记忆会参与误报降噪；`pending_approval` 候选不会影响判断。

当长期记忆内容包含 `false_positive` / `approved` / `误报` / `已批准` 等语义，并与当前告警的规则、应用、路径、来源或 user-agent 等特征匹配时，本地分析器会把类似重复告警初判为 `benign`，同时给出只读复核建议。该逻辑用于降低噪声，不替代分析师对新特征偏离的确认。

`--seed-demo-memory` 会在临时 harness 数据库中预置两条已批准 WAF 误报记忆，便于演示同类重复告警如何被降噪。真实环境中应通过记忆治理 API 和人工审批晋升长期记忆。

## 输出结构

Harness 输出 JSON，顶层字段包括：

- `samples`：总回放数量。
- `static_samples`：来自 `samples/*.json` 的数量。
- `random_samples`：随机生成数量。
- `validation`：Validator 的 `passed/review/blocked` 汇总。
- `results`：每条样例除分析字段外还包含 `skill`、`validation` 与 `approval_request_ids`。
- `mapping_profile`：当使用 profile 回放静态样本时记录 profile id。

这些字段与 Dashboard 展开的 Case 信息来自同一 `AgentResult` 与 SQLite schema，因此可作为 prompt、normalizer、policy、memory 变更的回归对照。

## 内网用途

- 每次修改 prompt、agent、normalizer、policy 或 LLM adapter 后运行。
- 新增真实脱敏样本后加入 `samples/` 或未来的私有 harness 样本库。
- 在生产接入前，把历史误报、漏报、真实事故和提示注入样本分成不同目录，并在 CI 或发布流程中分别回放。
- 与 `python3 -m pytest` 一起作为离线包迁移前的最小验收门禁。
