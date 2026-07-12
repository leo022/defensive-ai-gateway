#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-"$ROOT_DIR/dist"}"
BUNDLE_NAME="${BUNDLE_NAME:-defensive-ai-gateway-k3s-deploy}"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/${BUNDLE_NAME}.XXXXXX")"
BUNDLE_DIR="$STAGE/$BUNDLE_NAME"
ARCHIVE="$OUT_DIR/$BUNDLE_NAME.tar.gz"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$OUT_DIR" "$BUNDLE_DIR"

cd "$ROOT_DIR"

tar \
  --exclude="./.git" \
  --exclude="./data" \
  --exclude="./dist" \
  --exclude="./outputs" \
  --exclude="./__pycache__" \
  --exclude="./.pytest_cache" \
  --exclude="./.DS_Store" \
  --exclude="./*.pyc" \
  -czf "$BUNDLE_DIR/defensive-ai-gateway-source.tar.gz" \
  .

mkdir -p "$BUNDLE_DIR/deploy" "$BUNDLE_DIR/scripts" "$BUNDLE_DIR/images"
cp -R "$ROOT_DIR/deploy/docker" "$BUNDLE_DIR/deploy/"
cp -R "$ROOT_DIR/deploy/k3s" "$BUNDLE_DIR/deploy/"
cp "$ROOT_DIR/scripts/package_offline.sh" "$BUNDLE_DIR/scripts/"
cp "$ROOT_DIR/scripts/package_k3s_deploy.sh" "$BUNDLE_DIR/scripts/"
cp "$ROOT_DIR/deploy/k3s/env.example" "$BUNDLE_DIR/.env.example"
if [ -d "$ROOT_DIR/dist/k3s-images" ]; then
  find "$ROOT_DIR/dist/k3s-images" -maxdepth 1 -type f \( -name "*.tar" -o -name "*.sha256" \) -exec cp {} "$BUNDLE_DIR/images/" \;
fi

cat > "$BUNDLE_DIR/install.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$ROOT_DIR/deploy/k3s/install-k3s-bundle.sh" "$@"
EOF
chmod +x "$BUNDLE_DIR/install.sh"

{
  echo "# Defensive AI Gateway k3s bundle manifest"
  echo "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo
  echo "Images:"
  if compgen -G "$BUNDLE_DIR/images/*.tar" >/dev/null; then
    for image in "$BUNDLE_DIR"/images/*.tar; do
      [ -f "$image" ] || continue
      size="$(du -h "$image" | awk '{print $1}')"
      echo "- $(basename "$image") ($size)"
    done
  else
    echo "- none bundled; build with deploy/k3s/build-offline-images.sh first"
  fi
} > "$BUNDLE_DIR/MANIFEST.txt"

cat > "$BUNDLE_DIR/README.md" <<'EOF'
# Defensive AI Gateway k3s 部署包

此包用于企业内网 k3s 离线部署。目标服务器不需要安装 Python、不需要访问镜像仓库，也不需要预先填写应用配置。导入后默认使用本地确定性分析器和 SQLite，并通过节点 `8080` 端口直接访问。

## 内容

- `defensive-ai-gateway-source.tar.gz`：完整应用源码，用于在构建机重建镜像。
- `deploy/docker/Dockerfile`：镜像构建文件。
- `deploy/k3s/`：k3s 清单、Secret 模板、构建和部署脚本。
- `images/`：已打包的离线镜像 tar，以及对应 `.sha256`。
- `.env.example`：可选的鉴权和企业 LLM Secret 模板。
- `install.sh`：一键导入镜像并部署/覆盖当前 k3s 物料。

## 直接部署或覆盖

在 k3s 服务器解压后：

```bash
bash install.sh
```

部署完成后直接访问：

```text
http://<内网服务器IP>:8080
```

如需启用 Bearer Token，再创建 `.env` 后重复安装：

```bash
cp .env.example .env
vi .env
bash install.sh --require-token
```

如需同时部署 syslog collector：

```bash
bash install.sh --with-syslog
```

安装脚本会：

- 校验 `images/*.tar.sha256`。
- 导入 `images/*.tar` 到 k3s/containerd。
- `kubectl apply` 网关清单，覆盖已有 ConfigMap、Deployment、Service、Ingress 等物料。
- 更新 Secret 并重启 Deployment。

## 重建镜像

如需在有 Docker 的构建机上重建镜像，默认产出 `linux/amd64` 镜像；ARM 服务器请改用 `--platform linux/arm64`：

```bash
mkdir -p source
tar -xzf defensive-ai-gateway-source.tar.gz -C source
cd source
bash deploy/k3s/build-offline-images.sh --platform linux/amd64 --include-vector
```

把 `source/dist/k3s-images/*.tar*` 拷贝回本包 `images/` 目录后，再执行：

```bash
bash install.sh --with-syslog
```
EOF

tar -czf "$ARCHIVE" -C "$STAGE" "$BUNDLE_NAME"
if command -v sha256sum >/dev/null 2>&1; then
  archive_sha="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
else
  archive_sha="$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')"
fi
printf '%s  %s\n' "$archive_sha" "$(basename "$ARCHIVE")" > "$ARCHIVE.sha256"
echo "$ARCHIVE"
