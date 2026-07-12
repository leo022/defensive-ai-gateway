# Defensive AI Gateway

[English](README_EN.md) | 中文

银行业防御 AI 代理网关 MVP。该工程用于先在外网开发与验证，再以离线包形式迁移到企业内网部署。

## 技术路线

- Python 标准库优先：第一版不依赖 pip/npm，降低内网迁移和供应链审查成本。
- SQLite 事实库：PoC 阶段开箱即用，生产可替换为 PostgreSQL。
- HTTP API + 静态 Dashboard：接收 HIPS/RASP/NDR/WAF/SIEM 告警，实时查看 Case。
- 异步告警队列：HTTP 入口只做鉴权、映射和入队，后台 worker 分析，避免高 QPS 告警阻塞入口。
- Agent/Skill/Harness 分层：产品专属提示词、记忆命名空间、策略检查和离线回放分开演进。
- LLM 可插拔：开发配置默认使用 deterministic 本地规则分析器 `local-rule-analyst`；需要真实模型验证时，可在 Dashboard 切换到本地 Ollama 或内网 LLM Gateway。
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

不带 `profile` 直接提交厂商原生日志时，网关会按内容指纹识别来源（例如 cloudrasp 的 `data_type=attack_event` 识别为 `rasp`）；若该产品已注册自动 profile（`AUTO_PROFILE`，默认 `rasp → auto-rasp-json`），则自动套用做深度字段映射，否则落到对应 Subagent（浅字段）。既无显式 `product` 字段、又无法识别的日志会被拒绝（400），不再静默降级为 `siem`。

Harness 也支持用 profile 回放脱敏真实日志：

```bash
python3 scripts/run_harness.py --samples real_logs/rasp --mapping-profile demo-rasp-json
python3 scripts/run_harness.py --samples real_logs/rasp --mapping-profile-file config/rasp-prod-profile.json
```

## 离线回放与打包

```bash
python3 scripts/run_harness.py --samples samples --fail-on-low-confidence 0.5
python3 scripts/run_harness.py --samples samples --fail-on-validation-review
python3 scripts/run_harness.py --samples samples --random-count 10 --random-scenario random --seed 42
python3 scripts/run_harness.py --samples samples --random-count 5 --random-product waf --random-scenario false_positive --seed-demo-memory
python3 scripts/run_harness.py --samples samples --config config/dev.yaml --use-config-llm
bash scripts/package_offline.sh ../outputs
```

`--use-config-llm` 会按 `config/dev.yaml` 使用默认的 `local-rule-analyst`。如需回放真实模型效果，可先在配置或 Dashboard 中切换到本地 Ollama / 内网 LLM Gateway。

离线包解压后可以先运行安装检查脚本，生成生产配置和数据目录：

```bash
bash install.sh
python3 -m defensive_ai_gateway --config config/prod.yaml
```

如需安装为 systemd 服务：

```bash
sudo bash install.sh --systemd --enable --start
```

## k3s 与 Syslog 接入

镜像内置离线运行配置：本地规则分析器、`0.0.0.0:8080`、SQLite `/data/gateway.db`。Docker 可直接运行，无需挂载配置文件：

```bash
docker build -t defensive-ai-gateway:latest -f deploy/docker/Dockerfile .
docker run --rm -p 8080:8080 -v defensive-ai-data:/data defensive-ai-gateway:latest
```

然后访问 `http://127.0.0.1:8080`。默认空 Token 仅适合受信任、隔离的内网；设置 `DEFENSIVE_AI_API_TOKEN` 后，受保护 API 会立即要求 Bearer Token。

生产接入推荐在 k3s 中用独立 collector 接收 syslog，再转发到网关 HTTP 入口：

```text
Security Product -> Syslog UDP/TCP 15140-15144 -> Collector -> POST /api/alerts
```

参考清单：

- `deploy/k3s/gateway.yaml`：零配置网关 Deployment、Service 和 PVC，通过节点 `8080` 直接访问。
- `deploy/k3s/syslog-collector-vector.yaml`：Vector syslog collector 参考清单，接收 syslog 并转成标准告警 JSON。
- `docs/SYSLOG_INGESTION.md`：安全设备配置、Mapping Profile 接入和运维注意事项。

如果目标服务器不安装 Python，可用 k3s 部署物料：

```bash
bash deploy/k3s/build-offline-images.sh --include-vector
bash scripts/package_k3s_deploy.sh
```

生成的 `dist/defensive-ai-gateway-k3s-deploy.tar.gz` 包含镜像、校验文件、k3s 清单、导入脚本和源码包。目标服务器解压后执行 `bash install.sh`，无需 `.env` 或应用配置即可启动；完成后访问 `http://<内网服务器IP>:8080`。

本地可以模拟五类设备分别通过不同 TCP 端口发送 syslog，并验证路由不会把安全系统识别错：

```bash
python3 -m defensive_ai_gateway --config config/dev.yaml
python3 scripts/simulate_syslog_ports.py --config config/dev.yaml
```

## 工程结构

```text
defensive_ai_gateway/
  app.py              HTTP API 和 Dashboard 服务
  config.py           YAML 子集配置解析与环境变量覆盖
  database.py         SQLite schema 与仓储
  models.py           事件、Case、Agent 输出模型
  normalizer.py       多产品事件归一化
  orchestrator.py     Agent 路由与执行闭环
  skills.py           版本化 Skill 清单与权限边界
  validation.py       确定性证据/策略 Validator
  response.py         只生成审批请求的 Response Advisor
  llm.py              默认本地 LLM 适配器与企业网关接口
  policy.py           沙箱策略、脱敏、工具权限控制
  memory.py           多层记忆管理（短期Case/产品长期/资产画像/组织知识 + 证据库）
  agents/             HIPS/RASP/NDR/WAF/SIEM 专属 Agent
  static/             Dashboard 前端
config/
  dev.yaml            外网开发配置
  container.yaml      Docker/k3s 零配置离线默认值
  prod.example.yaml   内网生产配置模板
deploy/
  docker/             容器部署参考
  k3s/                k3s 部署与 syslog collector 清单
  systemd/            Linux systemd 部署参考
docs/
  TECHNICAL_PLAN.md   技术方案与迁移路径
  OFFLINE_MIGRATION.md 离线迁移步骤
  HARNESS.md          回放评测说明
  PHASE2_DEFENSE_AGENT.md 第二阶段 Agent、验证与审批设计
  MEMORY.md           多层记忆管理与治理
  SYSLOG_INGESTION.md syslog collector 接入说明
```

## 安全默认值

- 默认只读分析，不执行封禁、隔离、策略变更。
- prompt 前字段脱敏，原始证据仅保留在数据库。
- 每次 Agent Run、LLM 调用、策略拦截和输出都写审计记录。
- 高影响动作只生成 `approve_required` 建议。
- 只有 Validator `passed` 的建议可以进入审批队列；批准不等于执行，网关不提供生产动作执行接口。
