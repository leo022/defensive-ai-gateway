# k3s 离线部署物料

这套物料用于服务器不直接安装 Python 的部署方式。Python 运行时和离线默认配置封装在网关镜像里，目标服务器只需要有 k3s/containerd、kubectl 和 k3s 默认 local-path 存储。

## 物料清单

- `deploy/docker/Dockerfile`：网关镜像构建文件。
- `deploy/k3s/gateway.yaml`：Namespace、Secret、PVC、Deployment 和 Service；通过节点 `hostPort: 8080` 直接暴露。
- `deploy/k3s/syslog-collector-vector.yaml`：可选的 Vector syslog collector。
- `deploy/k3s/env.example`：生产 Secret 环境变量模板。
- `deploy/k3s/build-offline-images.sh`：在构建机上构建并导出离线镜像 tar。
- `deploy/k3s/install-k3s-bundle.sh`：在 k3s 服务器上导入镜像并部署。

## 1. 在构建机生成离线镜像

构建机需要 Docker，并能访问基础镜像 `python:3.11-slim`。如果要部署 syslog collector，还需要能拉取 `timberio/vector:0.39.0-alpine`。默认构建 `linux/amd64`，适合常见 x86_64 服务器；ARM 服务器可改为 `--platform linux/arm64`。

```bash
bash deploy/k3s/build-offline-images.sh
```

如需连同 Vector 镜像一起导出：

```bash
bash deploy/k3s/build-offline-images.sh --include-vector
```

指定平台示例：

```bash
bash deploy/k3s/build-offline-images.sh --platform linux/amd64 --include-vector
```

默认输出：

```text
dist/k3s-images/defensive-ai-gateway-latest.tar
dist/k3s-images/defensive-ai-gateway-latest.tar.sha256
dist/k3s-images/vector-0.39.0-alpine.tar              # 仅 --include-vector
```

## 2. 准备一包式部署包

```bash
bash scripts/package_k3s_deploy.sh
```

默认输出：

```text
dist/defensive-ai-gateway-k3s-deploy.tar.gz
```

如果 `dist/k3s-images/` 下已经有镜像 tar 和 `.sha256`，打包脚本会自动放入部署包根目录的 `images/`。企业内网服务器拿到这个压缩包后不需要 Docker，也不需要联网拉取镜像。

## 3. 在 k3s 服务器部署或覆盖旧物料

把部署包拷到服务器后：

```bash
tar -xzf defensive-ai-gateway-k3s-deploy.tar.gz
cd defensive-ai-gateway-k3s-deploy
```

部署网关：

```bash
bash install.sh
```

无需创建 `.env`。默认使用本地确定性分析器，数据写入 PVC，并允许可信隔离内网直接使用。启用 Bearer Token 时再执行：

```bash
cp .env.example .env
vi .env
bash install.sh --require-token
```

如果同时部署 syslog collector：

```bash
bash install.sh --with-syslog
```

重复执行 `bash install.sh` 会重新校验并导入镜像，`kubectl apply` 覆盖已有 Deployment、Service、PVC 等物料，更新可选 Secret，并重启网关 Deployment。

## 4. 验证

```bash
kubectl -n defensive-ai-gateway get pods
kubectl -n defensive-ai-gateway get svc
kubectl -n defensive-ai-gateway rollout status deployment/defensive-ai-gateway
curl http://127.0.0.1:8080/api/health
```

局域网客户端直接访问：

```text
http://<k3s节点内网IP>:8080
```

零配置模式以隔离内网为前提。跨安全域或生产长期运行时，应设置 `DEFENSIVE_AI_API_TOKEN`，并由现有反向代理补充 TLS/mTLS 和来源访问控制。
