# Defensive AI Gateway

[English](README_EN.md) | 中文

银行业防御 AI 代理网关 MVP。该工程用于先在外网开发与验证，再以离线包形式迁移到企业内网部署。

## 技术路线

- Python 标准库优先：第一版不依赖 pip/npm，降低内网迁移和供应链审查成本。
- SQLite 事实库：PoC 阶段开箱即用，生产可替换为 PostgreSQL。
- HTTP API + 静态 Dashboard：接收 HIPS/RASP/NDR/WAF/SIEM 告警，实时查看 Case。
- Agent/Skill/Harness 分层：产品专属提示词、记忆命名空间、策略检查和离线回放分开演进。
- LLM 可插拔：开发配置默认连接本地 Ollama `gemma3:4b`；如本机只有 `gemma3:latest`，会自动降级。测试 harness 默认仍可使用 deterministic 本地分析器。
- 随机样例 + 记忆降噪：样例脚本可随机生成 attack / false_positive 告警；已批准产品长期记忆可辅助同系统重复告警的误报分辨。

## 快速启动

```bash
python3 -m defensive_ai_gateway --config config/dev.yaml
```

服务默认监听 `127.0.0.1:8080`：

- Dashboard: `http://127.0.0.1:8080/`
- 健康检查: `GET /api/health`
- 提交告警: `POST /api/alerts`
- 查看 Case: `GET /api/cases`

## 提交样例告警

```bash
python3 scripts/send_sample.py --file samples/waf_alert.json
python3 scripts/send_sample.py --file samples/siem_case.json
```

也可以随机生成不同特征的攻击或误报告警：

```bash
python3 scripts/send_sample.py --random --count 5 --product waf --scenario random
python3 scripts/send_sample.py --random --count 3 --product waf --scenario false_positive --seed 42
```

## 真实日志格式适配

Dashboard 的“适配”页面可配置 Mapping Profile，把内网真实告警日志映射为内部稳定 `RawAlert`，并通过 dry-run 预览 `RawAlert` 与 `NormalizedEvent`。正式接入时可通过 `POST /api/alerts?profile=<profile_id>` 或请求体中的 `profile_id` 提交真实日志；映射失败的日志不会进入 LLM 分析。

Harness 也支持用 profile 回放脱敏真实日志：

```bash
python3 scripts/run_harness.py --samples real_logs/rasp --mapping-profile demo-rasp-json
python3 scripts/run_harness.py --samples real_logs/rasp --mapping-profile-file config/rasp-prod-profile.json
```

## 离线回放与打包

```bash
python3 scripts/run_harness.py --samples samples --fail-on-low-confidence 0.5
python3 scripts/run_harness.py --samples samples --random-count 10 --random-scenario random --seed 42
python3 scripts/run_harness.py --samples samples --random-count 5 --random-product waf --random-scenario false_positive --seed-demo-memory
python3 scripts/run_harness.py --samples samples --config config/dev.yaml --use-config-llm
bash scripts/package_offline.sh ../outputs
```

`--use-config-llm` 会按 `config/dev.yaml` 调用本地 Ollama。确认本机 Ollama 已启动，并已具备 `gemma3:4b` 或 `gemma3:latest`。

## k3s 与 Syslog 接入

生产接入推荐在 k3s 中用独立 collector 接收 syslog，再转发到网关 HTTP 入口：

```text
Security Product -> Syslog UDP/TCP 1514 -> Vector -> POST /api/alerts
```

参考清单：

- `deploy/k3s/gateway.yaml`：网关 Deployment、Service、Ingress、PVC 和生产配置。
- `deploy/k3s/syslog-collector-vector.yaml`：Vector syslog collector，监听 TCP/UDP `1514` 并转成标准告警 JSON。
- `docs/SYSLOG_INGESTION.md`：安全设备配置、Mapping Profile 接入和运维注意事项。

## 工程结构

```text
defensive_ai_gateway/
  app.py              HTTP API 和 Dashboard 服务
  config.py           YAML 子集配置解析与环境变量覆盖
  database.py         SQLite schema 与仓储
  models.py           事件、Case、Agent 输出模型
  normalizer.py       多产品事件归一化
  orchestrator.py     Agent 路由与执行闭环
  llm.py              默认本地 LLM 适配器与企业网关接口
  policy.py           沙箱策略、脱敏、工具权限控制
  memory.py           多层记忆管理（短期Case/产品长期/资产画像/组织知识 + 证据库）
  agents/             HIPS/RASP/NDR/WAF/SIEM 专属 Agent
  static/             Dashboard 前端
config/
  dev.yaml            外网开发配置
  prod.example.yaml   内网生产配置模板
deploy/
  docker/             容器部署参考
  k3s/                k3s 部署与 syslog collector 清单
  systemd/            Linux systemd 部署参考
docs/
  TECHNICAL_PLAN.md   技术方案与迁移路径
  OFFLINE_MIGRATION.md 离线迁移步骤
  HARNESS.md          回放评测说明
  MEMORY.md           多层记忆管理与治理
  SYSLOG_INGESTION.md syslog collector 接入说明
```

## 安全默认值

- 默认只读分析，不执行封禁、隔离、策略变更。
- prompt 前字段脱敏，原始证据仅保留在数据库。
- 每次 Agent Run、LLM 调用、策略拦截和输出都写审计记录。
- 高影响动作只生成 `approve_required` 建议。
