#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/dist"
BUNDLE_NAME="${BUNDLE_NAME:-defensive-ai-gateway-k3s-deploy}"
PLATFORM="${PLATFORM:-linux/amd64}"
IMAGE_DIR=""
INCLUDE_VECTOR=0
PYTHON_BASE_IMAGE="${PYTHON_BASE_IMAGE:-}"
VECTOR_IMAGE="${VECTOR_IMAGE:-}"
ALLOW_DIRTY=0

usage() {
  cat <<'EOF'
Usage:
  bash scripts/package_k3s_deploy.sh [options]

Build the current source into a fresh container image and atomically replace the
existing k3s offline deployment bundle.

Options:
  --out-dir DIR        Output directory. Defaults to ./dist.
  --platform PLATFORM  Target platform. Defaults to linux/amd64.
  --include-vector     Include the Vector image for the optional syslog collector.
  --python-base IMAGE  Digest-pinned Python base image for a release build.
  --vector-image IMAGE Digest-pinned Vector image used with --include-vector.
  --image-dir DIR      Package prebuilt image tar files instead of running Docker.
                       Every *.tar needs matching .sha256 and .ref sidecars.
  --allow-dirty        Explicitly create a non-release artifact from local changes.
  -h, --help           Show this help.
EOF
}

die() {
  printf '[k3s-package] ERROR: %s\n' "$*" >&2
  exit 1
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

is_content_addressed_gateway_ref() {
  ref="$1"
  case "$ref" in
    *@sha256:*) digest="${ref##*@sha256:}" ;;
    *:sha256-*) digest="${ref##*:sha256-}" ;;
    *) return 1 ;;
  esac
  [ "${#digest}" -eq 64 ] || return 1
  case "$digest" in *[!0-9a-fA-F]*) return 1 ;; esac
  return 0
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out-dir)
      [ "$#" -ge 2 ] || die "--out-dir requires a value"
      OUT_DIR="$2"
      shift 2
      ;;
    --platform)
      [ "$#" -ge 2 ] || die "--platform requires a value"
      PLATFORM="$2"
      shift 2
      ;;
    --include-vector)
      INCLUDE_VECTOR=1
      shift
      ;;
    --python-base)
      [ "$#" -ge 2 ] || die "--python-base requires a value"
      PYTHON_BASE_IMAGE="$2"
      shift 2
      ;;
    --vector-image)
      [ "$#" -ge 2 ] || die "--vector-image requires a value"
      VECTOR_IMAGE="$2"
      shift 2
      ;;
    --image-dir)
      [ "$#" -ge 2 ] || die "--image-dir requires a value"
      IMAGE_DIR="$2"
      shift 2
      ;;
    --allow-dirty)
      ALLOW_DIRTY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

if [ "$ALLOW_DIRTY" -ne 1 ] && [ -n "$(git -C "$ROOT_DIR" status --porcelain 2>/dev/null || true)" ]; then
  die "refusing to package a dirty worktree; commit/stash changes or pass --allow-dirty"
fi

umask 077
mkdir -p "$OUT_DIR"
WORK_DIR="$(mktemp -d "$OUT_DIR/.${BUNDLE_NAME}.XXXXXX")"
BUNDLE_DIR="$WORK_DIR/$BUNDLE_NAME"
BUILT_IMAGE_DIR="$WORK_DIR/built-images"
ARCHIVE_TMP="$WORK_DIR/$BUNDLE_NAME.tar.gz"
CHECKSUM_TMP="$ARCHIVE_TMP.sha256"
ARCHIVE="$OUT_DIR/$BUNDLE_NAME.tar.gz"
CHECKSUM="$ARCHIVE.sha256"
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$BUNDLE_DIR/deploy/k3s" "$BUNDLE_DIR/images"

if [ -z "$IMAGE_DIR" ]; then
  build_args=(
    --out-dir "$BUILT_IMAGE_DIR"
    --platform "$PLATFORM"
    --python-base "$PYTHON_BASE_IMAGE"
  )
  if [ "$INCLUDE_VECTOR" -eq 1 ]; then
    build_args+=(--include-vector --vector-image "$VECTOR_IMAGE")
  fi
  if [ "$ALLOW_DIRTY" -eq 1 ]; then
    build_args+=(--allow-dirty)
  fi
  printf '[k3s-package] rebuilding images from current source\n'
  bash "$ROOT_DIR/deploy/k3s/build-offline-images.sh" "${build_args[@]}"
  IMAGE_DIR="$BUILT_IMAGE_DIR"
else
  [ -d "$IMAGE_DIR" ] || die "image directory not found: $IMAGE_DIR"
  printf '[k3s-package] using explicitly supplied images: %s\n' "$IMAGE_DIR"
fi

shopt -s nullglob
image_tars=("$IMAGE_DIR"/*.tar)
[ "${#image_tars[@]}" -gt 0 ] || die "no image tar files found in $IMAGE_DIR"

GATEWAY_IMAGE_REF=""
VECTOR_IMAGE_REF=""
for image_tar in "${image_tars[@]}"; do
  image_name="$(basename "$image_tar")"
  checksum_file="$image_tar.sha256"
  ref_file="$image_tar.ref"
  [ -f "$checksum_file" ] || die "missing checksum: $checksum_file"
  [ -f "$ref_file" ] || die "missing image reference: $ref_file"

  expected="$(awk '{print $1; exit}' "$checksum_file")"
  actual="$(sha256_of "$image_tar")"
  [ -n "$expected" ] || die "empty checksum: $checksum_file"
  [ "$expected" = "$actual" ] || die "checksum mismatch: $image_tar"

  image_ref="$(sed -n '1p' "$ref_file")"
  [ -n "$image_ref" ] || die "empty image reference: $ref_file"
  case "$image_ref" in *[!A-Za-z0-9._/:@-]*) die "unsafe image reference: $image_ref" ;; esac
  case "$image_ref" in *:latest|*:dev) die "mutable image reference is forbidden: $image_ref" ;; esac

  cp "$image_tar" "$BUNDLE_DIR/images/$image_name"
  printf '%s  %s\n' "$actual" "$image_name" > "$BUNDLE_DIR/images/$image_name.sha256"
  printf '%s\n' "$image_ref" > "$BUNDLE_DIR/images/$image_name.ref"
  case "$image_ref" in
    defensive-ai-gateway:*|*/defensive-ai-gateway:*|defensive-ai-gateway@*|*/defensive-ai-gateway@*)
      [ -z "$GATEWAY_IMAGE_REF" ] || die "multiple gateway images supplied"
      is_content_addressed_gateway_ref "$image_ref" \
        || die "gateway image reference must contain its sha256 content identity: $image_ref"
      GATEWAY_IMAGE_REF="$image_ref"
      ;;
    timberio/vector:*|*/timberio/vector:*|timberio/vector@*|*/timberio/vector@*)
      [ -z "$VECTOR_IMAGE_REF" ] || die "multiple Vector images supplied"
      VECTOR_IMAGE_REF="$image_ref"
      ;;
  esac
done
[ -n "$GATEWAY_IMAGE_REF" ] || die "required defensive-ai-gateway image reference not found"

sed "s|@@GATEWAY_IMAGE@@|$GATEWAY_IMAGE_REF|g" \
  "$ROOT_DIR/deploy/k3s/gateway.yaml" > "$BUNDLE_DIR/deploy/k3s/gateway.yaml"
cp "$ROOT_DIR/deploy/k3s/install-k3s-bundle.sh" "$BUNDLE_DIR/deploy/k3s/"
if [ -n "$VECTOR_IMAGE_REF" ]; then
  sed "s|@@VECTOR_IMAGE@@|$VECTOR_IMAGE_REF|g" \
    "$ROOT_DIR/deploy/k3s/syslog-collector-vector.yaml" > "$BUNDLE_DIR/deploy/k3s/syslog-collector-vector.yaml"
else
  cp "$ROOT_DIR/deploy/k3s/syslog-collector-vector.yaml" "$BUNDLE_DIR/deploy/k3s/"
fi
cp "$ROOT_DIR/deploy/k3s/production-exposure.yaml" "$BUNDLE_DIR/deploy/k3s/"
cp "$ROOT_DIR/deploy/k3s/demo-exposure-patch.yaml" "$BUNDLE_DIR/deploy/k3s/"
cp "$ROOT_DIR/deploy/k3s/env.example" "$BUNDLE_DIR/.env.example"
chmod 600 "$BUNDLE_DIR/.env.example"

cat > "$BUNDLE_DIR/install.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$ROOT_DIR/deploy/k3s/install-k3s-bundle.sh" "$@"
EOF
chmod +x "$BUNDLE_DIR/install.sh" "$BUNDLE_DIR/deploy/k3s/install-k3s-bundle.sh"

SOURCE_REVISION="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || printf 'unknown')"
if [ -n "$(git -C "$ROOT_DIR" status --porcelain 2>/dev/null || true)" ]; then
  SOURCE_STATE="dirty"
else
  SOURCE_STATE="clean"
fi

{
  echo "# Defensive AI Gateway k3s bundle manifest"
  echo "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "Source revision: $SOURCE_REVISION"
  echo "Source state: $SOURCE_STATE"
  echo "Target platform: $PLATFORM"
  echo "Gateway image: $GATEWAY_IMAGE_REF"
  if [ -n "$VECTOR_IMAGE_REF" ]; then
    echo "Vector image: $VECTOR_IMAGE_REF"
  fi
  echo
  echo "Images:"
  for image_tar in "$BUNDLE_DIR"/images/*.tar; do
    image_name="$(basename "$image_tar")"
    image_size="$(du -h "$image_tar" | awk '{print $1}')"
    image_sha="$(sha256_of "$image_tar")"
    image_ref="$(sed -n '1p' "$image_tar.ref")"
    echo "- $image_name ($image_size, sha256:$image_sha, ref:$image_ref)"
  done
} > "$BUNDLE_DIR/MANIFEST.txt"

cat > "$BUNDLE_DIR/README.md" <<'EOF'
# Defensive AI Gateway k3s 离线部署包

本目录只包含企业内网 k3s 运行时所需物料。目标服务器需要 k3s、kubectl
和 k3s 默认 local-path 存储，不需要 Python、Docker、源码或外网镜像仓库。

## 部署或升级

```bash
cp .env.example .env
chmod 600 .env
vi .env
bash install.sh
```

生产必须提供四个不同的强角色 Token、TLS Secret 名、HTTPS 域名和来源 CIDR
白名单。可先执行 `bash install.sh --preflight-only`；缺少任何安全前提时安装器
失败关闭，不会自动暴露明文端口。

安装脚本校验 `.tar.sha256` 与不可变 `.tar.ref`、导入镜像，并在升级前创建
SQLite 一致性备份。失败会恢复旧镜像及对应数据库；成功输出可重复使用的回滚点：

```bash
bash install.sh --rollback <backup-id>
```

如果本包的 `images/` 中包含 Vector 镜像，可同时部署 syslog collector：

```bash
bash install.sh --with-syslog
```

验证：

```bash
kubectl -n defensive-ai-gateway rollout status deployment/defensive-ai-gateway
curl --fail https://$DEFENSIVE_AI_PUBLIC_HOST/api/ready
```

只有隔离临时展示可运行 `bash install.sh --demo-mode`；该模式才增加节点 8080
明文 hostPort，并保持 Demo 单签。
EOF

tar -czf "$ARCHIVE_TMP" -C "$WORK_DIR" "$BUNDLE_NAME"
archive_sha="$(sha256_of "$ARCHIVE_TMP")"
printf '%s  %s\n' "$archive_sha" "$(basename "$ARCHIVE")" > "$CHECKSUM_TMP"

# Both temporary files live under OUT_DIR, so replacing an old archive cannot
# expose a partially written tarball if a build or packaging step fails.
mv -f "$ARCHIVE_TMP" "$ARCHIVE"
mv -f "$CHECKSUM_TMP" "$CHECKSUM"

printf '[k3s-package] wrote %s\n' "$ARCHIVE"
printf '[k3s-package] wrote %s\n' "$CHECKSUM"
