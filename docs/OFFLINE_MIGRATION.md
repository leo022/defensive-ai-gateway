# k3s 离线迁移步骤

## 1. 外网构建机生成部署包

构建机需要 Docker 和基础镜像访问能力。每次项目迭代后从仓库根目录执行：

```bash
python3 -m unittest discover -s tests
export PYTHON_BASE_IMAGE='python:3.11-slim@sha256:<approved-digest>'
bash scripts/package_k3s_deploy.sh --platform linux/amd64
```

需要 syslog collector 时设置 digest 固定的 `VECTOR_IMAGE` 并增加
`--include-vector`。脚本拒绝脏工作区，并把 Gateway 按实际镜像 ID 重标记为
`sha256-<64hex>` 内容地址标签；只有构建、校验和压缩全部成功后才替换 `dist` 中的旧部署包。

## 2. 传入企业内网

只需传输以下两个文件，不需要传输源码目录、完整 `deploy/` 或中间镜像目录：

```text
dist/defensive-ai-gateway-k3s-deploy.tar.gz
dist/defensive-ai-gateway-k3s-deploy.tar.gz.sha256
```

在目标服务器校验压缩包：

```bash
sha256sum -c defensive-ai-gateway-k3s-deploy.tar.gz.sha256
```

## 3. 解压并覆盖部署

```bash
tar -xzf defensive-ai-gateway-k3s-deploy.tar.gz
cd defensive-ai-gateway-k3s-deploy
cp .env.example .env
chmod 600 .env
vi .env
bash install.sh --preflight-only
bash install.sh
```

生产默认要求四个不同且不少于 32 字符的角色 Token、已有的 TLS Secret、HTTPS
域名以及受限来源 CIDR；还会把审批 quorum 固定为 2。缺少任一前提都会失败关闭。
只有受信任、隔离且临时的展示环境可使用 `bash install.sh --demo-mode`。

部署 syslog collector 前，在 `.env` 中设置独立的 `DEFENSIVE_AI_INGEST_TOKEN`（不可与管理员 Token 相同）。生成包时必须使用 `--include-vector`：

```bash
bash install.sh --with-syslog
```

重复安装导入内容地址不可变镜像。变更前会把 SQLite 一致性快照写入 PVC，并保存
Gateway/Vector 的完整 Deployment、Service、Secret 与暴露契约。发布失败自动恢复
旧工作负载与快照；回滚前会先确认旧镜像仍在离线节点，成功后打印可手工执行的回滚命令。
PVC 不会被删除。

## 4. 验证

```bash
kubectl -n defensive-ai-gateway get pods
kubectl -n defensive-ai-gateway rollout status deployment/defensive-ai-gateway
curl --fail https://gateway.internal.example/api/ready
```

首批业务验收至少包括：脱敏 WAF 告警、SIEM 聚合路由、LLM Gateway 断链、审计
日志完整性、误报记忆写入，以及真实 RASP 日志 Mapping Profile dry-run。
