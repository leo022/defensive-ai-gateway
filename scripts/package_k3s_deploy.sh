#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-"$ROOT_DIR/dist"}"
BUNDLE_NAME="${BUNDLE_NAME:-defensive-ai-gateway-k3s-deploy}"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/${BUNDLE_NAME}.XXXXXX")"
BUNDLE_DIR="$STAGE/$BUNDLE_NAME"
ARCHIVE="$OUT_DIR/$BUNDLE_NAME.tar.gz"

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
ENV_FILE="${K3S_ENV_FILE:-$ROOT_DIR/.env}"
ALLOW_EMPTY_TOKEN=0
SHOW_HELP=0

for arg in "$@"; do
  case "$arg" in
    --allow-empty-token)
      ALLOW_EMPTY_TOKEN=1
      ;;
    -h|--help)
      SHOW_HELP=1
      ;;
  esac
done

if [ ! -f "$ENV_FILE" ] && [ "$ALLOW_EMPTY_TOKEN" -ne 1 ] && [ "$SHOW_HELP" -ne 1 ]; then
  cat >&2 <<MSG
[k3s-install] ERROR: $ENV_FILE not found.
[k3s-install] Copy .env.example to .env, edit DEFENSIVE_AI_API_TOKEN, then rerun:
[k3s-install]   cp .env.example .env
[k3s-install]   vi .env
[k3s-install]   bash install.sh
MSG
  exit 1
fi

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

此包用于企业内网 k3s 离线部署。目标服务器不需要安装 Python，网关运行时由容器镜像提供；已有部署可通过重复执行安装脚本覆盖更新。

## 内容

- `defensive-ai-gateway-source.tar.gz`：完整应用源码，用于在构建机重建镜像。
- `deploy/docker/Dockerfile`：镜像构建文件。
- `deploy/k3s/`：k3s 清单、Secret 模板、构建和部署脚本。
- `images/`：已打包的离线镜像 tar，以及对应 `.sha256`。
- `.env.example`：生产 Secret 环境变量模板。
- `install.sh`：一键导入镜像并部署/覆盖当前 k3s 物料。

## 直接部署或覆盖

在 k3s 服务器解压后：

```bash
cp .env.example .env
vi .env
bash install.sh
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
echo "$ARCHIVE"
