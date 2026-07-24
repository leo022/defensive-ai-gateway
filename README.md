# Defensive AI Gateway

[English](README_EN.md) | 中文

银行业防御 AI 代理网关 MVP。该工程用于先在外网开发与验证，再以离线包形式迁移到企业内网部署。

## 技术路线

- Python 标准库优先：第一版不依赖 pip/npm，降低内网迁移和供应链审查成本。
- SQLite 事实库：PoC 阶段开箱即用，生产可替换为 PostgreSQL。
- HTTP API + 静态 Dashboard：接收 HIPS/RASP/NDR/WAF/SIEM 告警，实时查看 Case。
- 持久告警队列：HTTP 入口在返回 `202` 前写入 SQLite inbox；后台 worker 有限重试，终态失败进入可查询 DLQ。远程 LLM 不可达的告警进入独立 `deferred` 状态，只由定时恢复或分析师手工释放，进程重启可恢复。
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
- 查询接入队列/DLQ: `GET /api/alerts/inbox?status=deferred` 或 `GET /api/alerts/inbox?status=dead_letter`

Dashboard 的“模型服务 -> 内网 Gateway”可接入 kkcoder 的 OpenAI 兼容 API：

```bash
export DEFENSIVE_AI_LLM_PROVIDER=gateway
export DEFENSIVE_AI_LLM_ENDPOINT="https://kkcoder.com/v1/responses"
export DEFENSIVE_AI_LLM_API_KEY="<secret>"
export DEFENSIVE_AI_LLM_MODEL="gpt-5.5"
export DEFENSIVE_AI_LLM_ALLOWED_HOSTS="kkcoder.com"
```

Gateway 支持 `/v1/responses`、`/v1/chat/completions`、Anthropic Messages 和现有企业
JSON 协议。Anthropic Messages 仅用于实际兼容该协议的服务：设置
`ANTHROPIC_BASE_URL` 与 `ANTHROPIC_AUTH_TOKEN` 后，会规范化为 `/v1/messages`。
访问凭据只用于配置的同源端点；不要把 token 写入 YAML、README 或其他仓库文件。

Gateway 只调用 HTTP 请求-响应 API，不支持 `wss://`、`/v1/realtime`、`/ws` 等
WebSocket 入口。出现 HTTP 426 `WebSocket upgrade required` 时，应改用服务商提供的
`/v1/responses` 或 `/v1/chat/completions` HTTP 地址，而不是重试同一地址。

## 提交样例告警

```bash
python3 scripts/send_sample.py --file samples/waf_alert.json
python3 scripts/send_sample.py --file samples/siem_case.json
python3 scripts/send_demo_alerts.py
```

`alert_id` 是告警实例的幂等键。以上 `--file` 命令会原样重放固定样本；再次发送同一文件是重试，不会创建第二条原始告警或重新执行长期记忆匹配。要模拟同类型的新告警，请保留规则语义、生成新的实例 ID 和时间戳：

```bash
python3 scripts/send_sample.py --file samples/waf_alert.json --mutate
```

若同一 `alert_id` 携带不同的时间戳、字段或证据，接口会返回 `409 alert_id_conflict`，要求上游为新的告警实例分配唯一 ID，避免静默丢弃或篡改既有审计证据。
不同 ID 的同类告警在默认一小时相关窗口内会聚合为同一个 Case；这表示关联，不表示覆盖。应在该 Case 的“关联原始告警”中看到递增的告警数量和每条原始记录。

`send_demo_alerts.py` 默认提交 16 条覆盖五类产品的 Demo 告警，其中额外包含一条
WAF XSS 提示注入样本，预期触发 Validator `review` 且不生成审批项；脚本会等待所有目标告警
进入 `completed` 或 `dead_letter` 后再退出；只需提交、不等待时使用
`--wait-seconds 0`。`clean_alerts_and_memory.py` 会同步清理 durable inbox，并在仍有
`pending/retry/deferred/processing` 任务时拒绝执行，避免处理中的事实记录被删除。

对于该类 Case，分析师可在“处置台 → 研判与处置”的验证门禁中核对原始日志和证据后，选择
“复核通过并转入审批”。该操作必须填写复核依据，原始验证仍保持 `review`，自动记忆写入仍被
抑制；只有发现项仅为 `prompt_injection_detected` 且其他确定性检查通过时，才会创建可由审批人
继续处理的非执行型审批项。

如需单独演示该门禁负向路径，可使用：

```bash
python3 scripts/send_demo_alerts.py --batch validation-review
```

注意：Validator 门禁检查的是分析输出的证据可追溯性、提示注入、敏感输出和动作权限，
不是 WAF 威胁规则本身。因此 WAF 可以命中 XSS 并被分类为真实攻击，同时门禁显示
`passed`；这表示分析输出合规且可以进入审批流程，不表示告警是误报或没有风险。

也可以随机生成不同特征的攻击或误报告警：

```bash
# --file 永远按原 JSON 发送固定样本；重复提交是幂等重放
python3 scripts/send_sample.py --file samples/ndr_alert.json

# --mutate 保留同类规则语义，但生成新的告警实例 ID、时间戳和可变字段
python3 scripts/send_sample.py --file samples/ndr_alert.json --mutate --count 2

# --random 随机选择产品、场景和该产品支持的攻击特征
python3 scripts/send_sample.py --random --count 5 --product waf --scenario random
python3 scripts/send_sample.py --random --count 3 --product waf --scenario false_positive --seed 42

# 固定产品特征，但场景仍可随机；例如 NDR 可生成 SQL 注入或暴力破解
python3 scripts/send_sample.py --random --count 3 --product ndr --feature brute_force --scenario attack
python3 scripts/send_sample.py --random --count 3 --product ndr --feature sql_injection --scenario attack

# 查看各产品支持的 feature ID；也接受 sqli、bruteforce、c2 等别名
python3 scripts/send_sample.py --list-features
```

`--file` 与 `--random` 是两种互斥的发送模式。`--feature` 只控制攻击特征，`--scenario` 控制真实攻击、人工复核或误报；未指定 `--feature` 时随机选择产品特征。离线 Harness 也支持相同能力：

```bash
python3 scripts/run_harness.py --samples samples --random-count 10 --random-product ndr --random-feature brute_force
```

## 真实日志格式适配

Dashboard 的“适配”页面可配置 Mapping Profile，把内网真实告警日志映射为内部稳定 `RawAlert`，并通过 dry-run 预览 `RawAlert` 与 `NormalizedEvent`。正式接入时可通过 `POST /api/alerts?profile=<profile_id>` 或请求体中的 `profile_id` 提交真实日志；映射失败的日志不会进入 LLM 分析。

不带 `profile` 直接提交厂商原生日志时，网关会按内容指纹识别来源（例如 cloudrasp 的 `data_type=attack_event` 识别为 `rasp`）；WAF、HIPS、NDR、RASP 和 SIEM 默认均注册 `auto-<product>-json` 自动 Profile，识别后会自动做深度字段映射。既无显式 `product` 字段、又无法识别且不含标准告警字段的日志会被拒绝（400）。为兼容既有标准 `RawAlert` 调用，带有 `event_type`、`severity`、`alert_id`、`source` 或 `timestamp` 但缺少 `product` 的请求仍会按 SIEM 处理；生产接入应始终提供明确的 `product` 或 Mapping Profile。

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
export DEFENSIVE_AI_API_TOKEN='<32+ chars>'
export DEFENSIVE_AI_INGEST_TOKEN='<different 32+ chars>'
export DEFENSIVE_AI_OPERATOR_TOKEN='<different 32+ chars>'
export DEFENSIVE_AI_APPROVER_TOKEN='<different 32+ chars>'
bash install.sh
python3 -m defensive_ai_gateway --config config/prod.yaml
```

如需安装为 systemd 服务：

```bash
sudo --preserve-env=DEFENSIVE_AI_API_TOKEN,DEFENSIVE_AI_INGEST_TOKEN,DEFENSIVE_AI_OPERATOR_TOKEN,DEFENSIVE_AI_APPROVER_TOKEN \
  bash install.sh --systemd --enable --start
```

生产安装拒绝空、已知占位或重复角色 Token，默认双签且关闭 loopback 免认证。
systemd 服务只监听 `127.0.0.1:8080`，应由同机 TLS/mTLS 反向代理提供远程入口，
避免 Bearer Token 经过节点明文 HTTP。
`bash install.sh --demo-mode` 仅生成回环、单签配置，不影响 `config/dev.yaml` 的现有
Demo 启动方式。

## k3s 与 Syslog 接入

镜像内置离线运行配置：本地规则分析器、`0.0.0.0:8080`、SQLite `/data/gateway.db`。Docker 可直接运行，无需挂载配置文件：

```bash
docker build -t defensive-ai-gateway:latest -f deploy/docker/Dockerfile .
docker run --rm -p 127.0.0.1:8080:8080 \
  -e DEFENSIVE_AI_AUTH_REQUIRE_REMOTE_TOKEN=0 \
  -e DEFENSIVE_AI_DEMO_MODE=1 \
  -v defensive-ai-data:/data defensive-ai-gateway:latest
```

然后访问 `http://127.0.0.1:8080`。上面的两个环境变量只适用于隔离 Demo；
生产不要扩展这条 `docker run`，应使用下方 production Compose，把 loopback bypass、
Demo 标志和单签全部切换为生产值。

Docker 生产参考使用 `deploy/docker/compose.production.yaml`：应用仅绑定宿主回环，
必须由同机 TLS/mTLS 反向代理对外提供服务；预检脚本会验证不可变镜像 digest、
四个不同的强 Token 以及 local/Ollama/Gateway 模型参数：

```bash
set -a
. /secure/path/defensive-ai.env
set +a
bash deploy/docker/validate-production-env.sh
docker compose -f deploy/docker/compose.production.yaml up -d
```

生产接入推荐在 k3s 中用独立 collector 接收 syslog，再转发到网关 HTTP 入口：

```text
Security Product -> Syslog 15140-15144 (RASP 15143 uses TCP; UDP is migration-only) -> Collector -> POST /api/alerts
```

参考清单：

- `deploy/k3s/gateway.yaml`：默认对远程请求鉴权失败关闭的 Gateway Deployment、Service 和 PVC。
- `deploy/k3s/syslog-collector-vector.yaml`：Vector syslog collector 参考清单，使用独立 ingest Token 接收 syslog，并按五产品内置 Mapping Profile 转发。
- `docs/SYSLOG_INGESTION.md`：安全设备配置、Mapping Profile 接入和运维注意事项。

如果目标服务器不安装 Python，可用 k3s 部署物料：

```bash
export PYTHON_BASE_IMAGE='python:3.11-slim@sha256:<approved-digest>'
export VECTOR_IMAGE='timberio/vector@sha256:<approved-digest>'
bash scripts/package_k3s_deploy.sh --include-vector
```

脚本会基于当前源码重建镜像，并在成功后替换
`dist/defensive-ai-gateway-k3s-deploy.tar.gz` 及其校验文件。部署包只包含内网运行
所需的镜像、校验文件、k3s 清单和导入脚本，不包含源码与构建工具。目标服务器
解压后通过权限为 `600` 的 `.env` 设置四个独立角色 Token、TLS Secret、生产域名、来源 CIDR 和模型参数。生产默认只创建 ClusterIP + TLS Ingress，拒绝 `latest`、脏工作区、空/弱凭据、全网段来源和缺失 TLS；升级前自动备份 SQLite，失败恢复旧镜像与数据库。仅隔离、临时展示可显式使用 `bash install.sh --demo-mode` 增加明文 hostPort。详细说明见 `deploy/k3s/README.md`。

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
  memory_matcher.py   跨模型统一的长期记忆混合评分、阈值决策与安全合并
  agents/             HIPS/RASP/NDR/WAF/SIEM 专属 Agent
  static/             Dashboard 前端
config/
  dev.yaml            外网开发配置
  container.yaml      Docker/k3s 离线、远程鉴权失败关闭默认值
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
- 生产模板要求两个不同的服务端认证主体投票；本地 Demo 保持单签。
- Demo 样本真值只在回环请求带 `X-Defensive-AI-Demo-Sample: 1` 时生效，普通告警不能用请求体自证结论。
