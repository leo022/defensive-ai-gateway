# Defensive AI Gateway

简体中文 | [English](README_EN.md)

Defensive AI Gateway 是面向安全运营中心（SOC）的告警研判与响应网关。系统统一接入
HIPS、RASP、NDR、WAF 和 SIEM 告警，提供格式归一化、持久化排队、AI 辅助研判、
确定性验证、人工审批、受控响应与全程审计能力。

本仓库提供可运行的参考实现，适用于方案验证、集成测试和受控环境部署。生产使用前，
应结合组织要求完成身份与密钥管理、网络隔离、容量规划、灾备恢复及安全合规评审。

## 核心能力

| 能力 | 说明 |
| --- | --- |
| 多源告警接入 | 通过 HTTP API 或 Syslog Collector 接入 HIPS、RASP、NDR、WAF、SIEM 数据 |
| 稳定数据契约 | 使用 Mapping Profile 将厂商原始日志转换为 `RawAlert` 和 `NormalizedEvent` |
| 可靠异步处理 | 告警在返回 `202` 前写入 SQLite 持久队列，支持有限重试、延迟恢复和可查询 DLQ |
| 分层智能分析 | 按安全产品路由 Agent、Skill 和记忆命名空间，可使用本地规则分析器、Ollama 或兼容的企业 LLM Gateway |
| 验证与治理 | Validator 检查证据可追溯性、提示注入、敏感输出和动作权限 |
| 人机协同处置 | 通过 Case 工作台完成调查、复核、审批、受控执行、核验和回滚 |
| 离线评测与交付 | 提供可复现样例、随机场景、Harness 回放、离线打包以及 Docker/k3s 部署参考 |

## 处理流程

```text
HIPS / RASP / NDR / WAF / SIEM
                |
        HTTP API / Syslog Collector
                |
          Mapping Profile
                |
     RawAlert -> Durable Inbox
                |
      Product Agent / LLM Analysis
                |
             Validator
                |
       Case / Memory / Audit Log
                |
      Review -> Approval -> Response
```

## 运行要求

- Python 3.11（推荐）
- SQLite（由 Python 标准库提供）
- 无必需的 pip 或 npm 运行时依赖
- 可选：Docker、k3s、Ollama 或兼容的企业 LLM Gateway

## 快速开始

```bash
python3 -m defensive_ai_gateway --config config/dev.yaml
```

服务默认监听 `127.0.0.1:8080`：

| 用途 | 地址或接口 |
| --- | --- |
| Dashboard | `http://127.0.0.1:8080/` |
| 存活检查 | `GET /api/live` |
| 就绪检查 | `GET /api/ready` |
| 运行状态 | `GET /api/health` |
| 提交告警 | `POST /api/alerts` |
| 查询 Case | `GET /api/cases` |
| 查询延迟队列 | `GET /api/alerts/inbox?status=deferred&limit=100&offset=0` |
| 查询死信队列 | `GET /api/alerts/inbox?status=dead_letter&limit=100&offset=0` |

开发配置默认使用确定性的本地规则分析器 `local-rule-analyst`，无需外部模型服务即可运行。

## 模型服务配置

Dashboard 的“模型服务 → 内网 Gateway”支持兼容 OpenAI HTTP 协议的企业模型服务。
也可以通过环境变量完成等价配置：

```bash
export DEFENSIVE_AI_LLM_PROVIDER=gateway
export DEFENSIVE_AI_LLM_ENDPOINT="https://llm-gateway.example.com/v1/responses"
export DEFENSIVE_AI_LLM_API_KEY="<api-key>"
export DEFENSIVE_AI_LLM_MODEL="<model-id>"
export DEFENSIVE_AI_LLM_ALLOWED_HOSTS="llm-gateway.example.com"
```

Gateway 支持 `/v1/responses`、`/v1/chat/completions`、Anthropic Messages 和现有企业
JSON 协议。Anthropic Messages 仅用于实际兼容该协议的服务：设置
`ANTHROPIC_BASE_URL` 与 `ANTHROPIC_AUTH_TOKEN` 后，会规范化为 `/v1/messages`。
访问凭据仅用于已配置的同源端点。密钥应通过环境变量或专用密钥管理系统注入，不得写入
YAML、README、日志或其他仓库文件。

Gateway 只调用 HTTP 请求-响应 API，不支持 `wss://`、`/v1/realtime`、`/ws` 等
WebSocket 入口。出现 HTTP 426 `WebSocket upgrade required` 时，应改用服务商提供的
`/v1/responses` 或 `/v1/chat/completions` HTTP 地址，而不是重试同一地址。

## 样例告警与验证

```bash
python3 scripts/send_sample.py --file samples/waf_alert.json
python3 scripts/send_sample.py --file samples/siem_case.json
python3 scripts/send_demo_alerts.py
```

`alert_id` 是告警实例的幂等键。样例发送工具默认在传输前生成当前时间和唯一实例 ID，
原始日志内嵌的事件 ID 与时间也会同步刷新。仅在验证历史重放或幂等行为时，使用
`--preserve-fixture-identity` 保留固定样本身份：

```bash
python3 scripts/send_sample.py --file samples/waf_alert.json --preserve-fixture-identity
```

若同一 `alert_id` 携带不同的时间戳、字段或证据，接口会返回
`409 alert_id_conflict`。上游必须为新的告警实例分配唯一 ID，避免静默丢弃或篡改
既有审计证据。不同 ID 的同类告警在默认一小时相关窗口内可聚合为同一个 Case；
这表示事件关联，不表示数据覆盖。

`send_demo_alerts.py` 默认提交 16 条覆盖五类产品的演示告警，其中包含一条
WAF XSS 提示注入样本，预期触发 Validator `review` 且不生成审批项；脚本会等待所有目标告警
进入 `completed` 或 `dead_letter` 后再退出；只需提交、不等待时使用
`--wait-seconds 0`。`clean_alerts_and_memory.py` 会同步清理持久化队列，并在仍有
`pending/retry/deferred/processing` 任务时拒绝执行，避免处理中的事实记录被删除。

生产环境的持久队列同时受 `processing.queue_max_size`（未完成条数）、
`processing.queue_max_bytes`（未完成原始告警 JSON 字节数）和
`processing.min_free_bytes`（数据库文件系统保留空间）约束。环境变量分别为
`DEFENSIVE_AI_QUEUE_MAX_SIZE`、`DEFENSIVE_AI_QUEUE_MAX_BYTES` 和
`DEFENSIVE_AI_MIN_FREE_BYTES`。容量水位只暂停新告警接入，不会让唯一 Gateway
退出 readiness；具体使用量、最老积压时间与磁盘水位见 `GET /api/health`。

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
# --file 默认保留规则和证据语义，但生成当前时间与唯一实例 ID
python3 scripts/send_sample.py --file samples/ndr_alert.json

# --mutate 额外随机化 IP、会话和速率等可变字段
python3 scripts/send_sample.py --file samples/ndr_alert.json --mutate --count 2

# 仅在验证历史/幂等重放时保留固定 ID 与时间
python3 scripts/send_sample.py --file samples/ndr_alert.json --preserve-fixture-identity

# --random 随机选择产品、场景和该产品支持的攻击特征
python3 scripts/send_sample.py --random --count 5 --product waf --scenario random
python3 scripts/send_sample.py --random --count 3 --product waf --scenario false_positive --seed 42

# 固定产品特征，但场景仍可随机；例如 NDR 可生成 SQL 注入或暴力破解
python3 scripts/send_sample.py --random --count 3 --product ndr --feature brute_force --scenario attack
python3 scripts/send_sample.py --random --count 3 --product ndr --feature sql_injection --scenario attack

# 查看各产品支持的 feature ID；也接受 sqli、bruteforce、c2 等别名
python3 scripts/send_sample.py --list-features
```

`--file` 与 `--random` 是两种互斥的发送模式。`--feature` 控制攻击特征，
`--scenario` 控制真实攻击、人工复核或误报；未指定 `--feature` 时随机选择产品特征。
`--preserve-generated-identity` 作为兼容参数保留，新命令应使用
`--preserve-fixture-identity`。离线 Harness 也支持相同能力：

```bash
python3 scripts/run_harness.py --samples samples --random-count 10 --random-product ndr --random-feature brute_force
```

## 真实日志格式适配

Dashboard 的“适配”页面可配置 Mapping Profile，将厂商告警日志映射为稳定的
`RawAlert`，并通过 dry-run 预览 `RawAlert` 与 `NormalizedEvent`。正式接入时可通过
`POST /api/alerts?profile=<profile_id>` 或请求体中的 `profile_id` 提交原始日志；
映射失败的数据不会进入 LLM 分析。

不带 `profile` 直接提交厂商原始日志时，网关会按内容指纹识别来源。例如，
`data_type=attack_event` 可识别为 `rasp`。WAF、HIPS、NDR、RASP 和 SIEM 默认注册
`auto-<product>-json` Profile，识别后执行深度字段映射。既无显式 `product` 字段、
又无法识别且不含标准告警字段的数据会被拒绝并返回 `400`。

为兼容既有标准 `RawAlert` 调用，包含 `event_type`、`severity`、`alert_id`、`source`
或 `timestamp` 但缺少 `product` 的请求仍按 SIEM 处理。生产接入应始终提供明确的
`product` 或 Mapping Profile。

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

`--use-config-llm` 会按 `config/dev.yaml` 使用默认的 `local-rule-analyst`。如需回放真实
模型效果，可先在配置或 Dashboard 中切换到 Ollama 或企业 LLM Gateway。

离线包解压后可以先运行安装检查脚本，生成生产配置和数据目录：

```bash
export DEFENSIVE_AI_API_TOKEN='<32+ chars>'
export DEFENSIVE_AI_INGEST_TOKEN='<different 32+ chars>'
export DEFENSIVE_AI_OPERATOR_TOKEN='<different 32+ chars>'
export DEFENSIVE_AI_APPROVER_TOKEN='<different 32+ chars>'
export DEFENSIVE_AI_RESPONDER_TOKEN='<different 32+ chars>'
bash install.sh
python3 -m defensive_ai_gateway --config config/prod.yaml
```

如需安装为 systemd 服务：

```bash
sudo --preserve-env=DEFENSIVE_AI_API_TOKEN,DEFENSIVE_AI_INGEST_TOKEN,DEFENSIVE_AI_OPERATOR_TOKEN,DEFENSIVE_AI_APPROVER_TOKEN,DEFENSIVE_AI_RESPONDER_TOKEN \
  bash install.sh --systemd --enable --start
```

生产安装拒绝空、已知占位或重复角色 Token，默认双签且关闭回环免认证。
systemd 服务只监听 `127.0.0.1:8080`，应由同机 TLS/mTLS 反向代理提供远程入口，
避免 Bearer Token 经过节点明文 HTTP。
`bash install.sh --demo-mode` 仅生成回环、单签配置，不影响 `config/dev.yaml` 的现有
演示启动方式。

## 容器化部署与 Syslog 接入

### Docker 演示环境

镜像内置离线运行配置：本地规则分析器、`0.0.0.0:8080` 和 SQLite
`/data/gateway.db`。Docker 可直接运行，无需挂载配置文件：

```bash
docker build -t defensive-ai-gateway:latest -f deploy/docker/Dockerfile .
docker run --rm -p 127.0.0.1:8080:8080 \
  -e DEFENSIVE_AI_AUTH_REQUIRE_REMOTE_TOKEN=0 \
  -e DEFENSIVE_AI_DEMO_MODE=1 \
  -v defensive-ai-data:/data defensive-ai-gateway:latest
```

然后访问 `http://127.0.0.1:8080`。上述两个环境变量仅适用于隔离的演示环境。
生产部署应使用下方 Compose 参考，将回环免认证、演示标志和单签配置切换为生产值。

### Docker 生产参考

Docker 生产参考使用 `deploy/docker/compose.production.yaml`：应用仅绑定宿主回环，
必须由同机 TLS/mTLS 反向代理对外提供服务；预检脚本会验证不可变镜像 digest、
五个不同的强 Token 以及 local/Ollama/Gateway 模型参数：

```bash
set -a
. /secure/path/defensive-ai.env
set +a
bash deploy/docker/validate-production-env.sh
docker compose -f deploy/docker/compose.production.yaml up -d
```

### k3s 与 Syslog

生产接入推荐在 k3s 中用独立 collector 接收 syslog，再转发到网关 HTTP 入口：

```text
Security Product -> Syslog 15140-15144 (RASP 15143 uses TCP; UDP is migration-only) -> Collector -> POST /api/alerts
```

参考清单：

- `deploy/k3s/gateway.yaml`：默认对远程请求鉴权失败关闭的 Gateway Deployment、Service 和 PVC。
- `deploy/k3s/syslog-collector-vector.yaml`：Vector Syslog Collector 参考清单，使用独立
  ingest Token 接收 Syslog，并按五产品内置 Mapping Profile 转发。
- `docs/SYSLOG_INGESTION.md`：安全设备配置、Mapping Profile 接入和运维注意事项。

如果目标服务器不安装 Python，可用 k3s 部署物料：

```bash
export PYTHON_BASE_IMAGE='python:3.11-slim@sha256:<approved-digest>'
export VECTOR_IMAGE='timberio/vector@sha256:<approved-digest>'
bash scripts/package_k3s_deploy.sh --include-vector
```

脚本会基于当前源码重建镜像，并在成功后替换
`dist/defensive-ai-gateway-k3s-deploy.tar.gz` 及其校验文件。部署包只包含目标环境运行
所需的镜像、校验文件、k3s 清单和导入脚本，不包含源码与构建工具。

目标服务器通过权限为 `600` 的 `.env` 设置五个独立角色 Token、TLS Secret、生产域名、
来源 CIDR 和模型参数。生产默认只创建 ClusterIP 和 TLS Ingress，并拒绝 `latest`、
脏工作区、空或弱凭据、全网段来源及缺失 TLS；升级前自动备份 SQLite，失败时恢复旧镜像
与数据库。仅在隔离的临时演示环境中，才可显式使用 `bash install.sh --demo-mode` 增加明文
hostPort。详细说明见 [`deploy/k3s/README.md`](deploy/k3s/README.md)。

### 接入验证

可模拟五类设备分别通过不同 TCP 端口发送 Syslog，验证采集、映射与产品路由：

```bash
python3 -m defensive_ai_gateway --config config/dev.yaml
python3 scripts/simulate_syslog_ports.py --config config/dev.yaml
```

Syslog 模拟器默认刷新五类原始日志的事件 ID 和时间，并使用管理员 API Token 生成
HMAC 测试标记。Gateway 仅在可信采集路由确认来源为本机且签名正确时，将其标记为
运行验证样本；此类 Case 不写长期记忆，也不生成生产审批。使用已运行的外置 Vector 时，
添加 `--running-collector`，并通过环境变量提供管理员 Token：

```bash
DEFENSIVE_AI_API_TOKEN='<admin-token>' \
python3 scripts/simulate_syslog_ports.py --config config/container.yaml --running-collector
```

仅在明确需要产生生产记忆与审批的测试中使用 `--production-event`；历史身份重放另加
`--preserve-fixture-identity`。

## 测试与质量检查

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m compileall -q defensive_ai_gateway scripts tests
```

涉及前端静态资源时，还应对变更的 JavaScript 文件执行 `node --check`。涉及部署配置时，
应同时运行对应预检脚本，并在目标环境验证 Gateway、反向代理、Collector、监听端口及
真实端到端样本；就绪检查通过不代表完整链路验证完成。

## 文档索引

- [总体架构](docs/ARCHITECTURE.md)
- [风险控制](docs/RISK_CONTROLS.md)
- [离线迁移](docs/OFFLINE_MIGRATION.md)
- [回放评测](docs/HARNESS.md)
- [Response Agent](docs/RESPONSE_AGENT.md)
- [自动化响应](docs/AUTOMATED_RESPONSE.md)
- [记忆管理与治理](docs/MEMORY.md)
- [Syslog 接入](docs/SYSLOG_INGESTION.md)

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
  response.py         生成审批请求与结构化处置建议的 Response Advisor
  response_agent.py   Case 级持久化 ReAct 调查、只读工具、深度报告与门禁
  response_automation.py 审批后处置任务、连接器调用、核验与回滚
  llm.py              默认本地 LLM 适配器与企业网关接口
  policy.py           沙箱策略、脱敏、工具权限控制
  memory.py           多层记忆管理（短期Case/产品长期/资产画像/组织知识 + 证据库）
  memory_matcher.py   跨模型统一的长期记忆混合评分、阈值决策与安全合并
  agents/             HIPS/RASP/NDR/WAF/SIEM 专属 Agent
  static/             Dashboard 前端
config/
  dev.yaml            开发与功能验证配置
  container.yaml      Docker/k3s 容器运行配置
  prod.example.yaml   生产配置模板
deploy/
  docker/             容器部署参考
  k3s/                k3s 部署与 syslog collector 清单
  systemd/            Linux systemd 部署参考
docs/
  ARCHITECTURE.md     总体架构
  RISK_CONTROLS.md    风险控制与信任边界
  RESPONSE_AGENT.md   Response Agent 设计
  AUTOMATED_RESPONSE.md 自动化处置控制与运维
  MEMORY.md           多层记忆管理与治理
  SYSLOG_INGESTION.md Syslog Collector 接入说明
samples/              标准告警样例
scripts/              发送、回放、打包和运维脚本
tests/                单元与回归测试
```

## 安全默认值

- 默认执行只读分析，不直接实施封禁、隔离或策略变更。
- 进入提示词前对字段脱敏，原始证据保留在事实库中。
- Agent Run、LLM 调用、策略拦截、审批和响应结果均写入审计记录。
- 高影响动作默认只生成 `approve_required` 建议。
- 仅 Validator 状态为 `passed` 的建议可以进入审批队列。只有明确的来源 IP 临时封禁，
  才能在策略开启、审批达标且连接器健康时进入受控执行；其他高影响动作保持只读。
- 自动化处置默认关闭，支持影子、手工和自动模式。连接器凭据仅从环境变量读取，
  规则必须经过设备核验，并在 TTL 到期、Case 关闭或误报确认后回滚。完整契约见
  [自动化响应文档](docs/AUTOMATED_RESPONSE.md)。
- Response Agent 使用 Case 锁定的只读工具执行 ReAct 调查，关联已入库遥测，并由控制器
  约束证据身份、调查缺口、权限和审批边界。完整设计见
  [Response Agent 文档](docs/RESPONSE_AGENT.md)。
- 生产模板要求两个不同的服务端认证主体投票；隔离演示配置保持单签。
- 演示样本真值仅在回环请求携带 `X-Defensive-AI-Demo-Sample: 1` 时生效，普通告警不能
  通过请求体自证结论。
