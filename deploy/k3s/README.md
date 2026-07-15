# k3s 离线生产部署

生产路径与本地 Demo 明确分离：基础清单只有 ClusterIP；生产安装器增加 TLS
Ingress、来源 CIDR 白名单、双人审批、强角色凭据、不可变镜像和升级前 SQLite
备份。只有显式 `--demo-mode` 才会增加明文 `hostPort: 8080`，且该模式不应用于
生产。

## 1. 构建不可变离线包

发布构建拒绝脏工作区，并要求基础镜像和可选 Vector 镜像通过 digest 固定。先从
企业镜像仓库或签核清单取得真实 digest：

```bash
export PYTHON_BASE_IMAGE='python:3.11-slim@sha256:<approved-64-hex-digest>'
bash scripts/package_k3s_deploy.sh --platform linux/amd64
```

同时交付 syslog collector：

```bash
export VECTOR_IMAGE='timberio/vector@sha256:<approved-64-hex-digest>'
bash scripts/package_k3s_deploy.sh --include-vector
```

输出为：

```text
dist/defensive-ai-gateway-k3s-deploy.tar.gz
dist/defensive-ai-gateway-k3s-deploy.tar.gz.sha256
```

每个镜像 tar 都带 `.sha256` 和 `.ref`：前者校验字节内容，后者记录清单使用的
不可变引用。Gateway 构建会按实际 image ID 重标记为 `sha256-<64hex>` 内容地址
标签（企业镜像也可直接使用 digest），从而避免同名 tag 被覆盖后回滚仍指向新内容。
使用企业已扫描镜像时，目录也必须具备这三个文件：

```bash
bash scripts/package_k3s_deploy.sh --image-dir /path/to/approved-images
```

`--allow-dirty` 只用于临时验收包；其 MANIFEST 会明确标记 `Source state: dirty`，
不能作为可复现发布物。

## 2. 准备生产环境

解压部署包并创建权限为 600 的环境文件：

```bash
tar -xzf defensive-ai-gateway-k3s-deploy.tar.gz
cd defensive-ai-gateway-k3s-deploy
cp .env.example .env
chmod 600 .env
vi .env
```

生产必须配置四个不同且不少于 32 字符的角色 Token：管理员、HTTP 告警接入、
运营和审批。安装器拒绝 `change-me`、`replace-*` 等占位值。还必须设置：

- `DEFENSIVE_AI_PUBLIC_HOST`：生产 HTTPS 域名；
- `DEFENSIVE_AI_TLS_SECRET`：已存在于 `defensive-ai-gateway` Namespace 的 TLS Secret；
- `DEFENSIVE_AI_ALLOWED_SOURCE_CIDRS`：允许运营人员访问的内网 CIDR，拒绝全网段；
- 模型 provider、endpoint、model 与 allowed hosts；
- 数据、审计与记忆事件保留期。

先创建 TLS Secret（证书文件不能放进部署包）：

```bash
kubectl create namespace defensive-ai-gateway --dry-run=client -o yaml | kubectl apply -f -
kubectl -n defensive-ai-gateway create secret tls defensive-ai-gateway-tls \
  --cert=/secure/path/tls.crt --key=/secure/path/tls.key
```

默认 overlay 使用 k3s 自带 Traefik 的 Middleware CRD执行来源白名单。缺少该 CRD
或 TLS Secret 时安装器会在修改工作负载前失败关闭。

## 3. 模型配置

本地规则模型：

```text
DEFENSIVE_AI_LLM_PROVIDER=local
DEFENSIVE_AI_LLM_ENDPOINT=
DEFENSIVE_AI_LLM_MODEL=local-rule-analyst
```

独立 Ollama 服务：

```text
DEFENSIVE_AI_LLM_PROVIDER=ollama
DEFENSIVE_AI_LLM_ENDPOINT=http://ollama.ai-platform.svc:11434
DEFENSIVE_AI_LLM_MODEL=qwen3:8b
DEFENSIVE_AI_LLM_ALLOWED_HOSTS=ollama.ai-platform.svc
```

企业 Gateway 必须使用 HTTPS，endpoint 主机必须在 allowlist，API key 不少于
32 字符：

```text
DEFENSIVE_AI_LLM_PROVIDER=gateway
DEFENSIVE_AI_LLM_ENDPOINT=https://llm-gateway.internal.example/v1/security/analyze
DEFENSIVE_AI_LLM_MODEL=enterprise-sec-analyst
DEFENSIVE_AI_LLM_ALLOWED_HOSTS=llm-gateway.internal.example
DEFENSIVE_AI_LLM_API_KEY=<secret>
```

可只做本地校验，不连接集群：

```bash
bash install.sh --preflight-only
```

## 4. 部署、升级与回滚

```bash
bash install.sh
```

若已有 Deployment，安装器先通过 SQLite online backup API 把一致性快照写入 PVC
的 `/data/backups/`，并保存 Gateway/Vector 的完整 Deployment、Service、Secret 与
暴露契约，再更新 Secret、不可变镜像和生产 overlay。滚动失败会在确认旧镜像仍
存在于离线节点后，恢复旧工作负载契约及对应数据库快照；旧镜像若已被 GC，会在
停机前失败而不会扩大故障。成功后输出回滚点，例如：

```bash
bash install.sh --rollback 20260714t083000z-0042
```

默认只保留最近 5 个回滚点，并在创建新快照前检查 PVC 可用空间；可用
`DEFENSIVE_AI_BACKUP_RETENTION_COUNT` 在 1–20 之间调整。`--skip-backup` 是需要明确输入的 break-glass 选项。SQLite 单写者约束下 Deployment
保持 `replicas: 1` 和 `Recreate`，不会让两个版本同时写同一数据库。

探针职责分离：`/api/live` 只判断进程存活；`/api/ready` 检查数据库、schema、队列
和后台工作器，只有 ready 的 Pod 才接收生产流量。

## 5. Syslog collector

`.env` 中设置设备来源网段，再部署：

```text
DEFENSIVE_AI_SYSLOG_SOURCE_CIDRS=10.20.0.0/16,10.21.0.0/16
```

```bash
bash install.sh --with-syslog
```

LoadBalancer 使用 `loadBalancerSourceRanges`，并在生产安装时生成同源 CIDR 的
`syslog-collector-ingress` NetworkPolicy，阻止其他外部来源和集群 Pod 绕过 Service
直接向 Vector 注入日志。Vector 只持有 ingest
Token，并使用磁盘缓冲。传统 UDP/TCP syslog 本身不提供端到端机密性；应放在安全
设备专网或 VPN 中，能支持 TLS 的设备应由企业 TLS syslog relay 转发。

## 6. 隔离 Demo

仅临时、受信任、隔离环境可运行：

```bash
bash install.sh --demo-mode
```

该命令保持 Demo 单签并增加节点 `8080` 明文入口。生产默认从不暴露 hostPort，
也不会在缺少凭据、TLS 或来源白名单时自动退化成 Demo。
