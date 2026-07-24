from __future__ import annotations

import hashlib
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from defensive_ai_gateway.config import load_config


ROOT = Path(__file__).resolve().parents[1]


class ContainerDefaultsTest(unittest.TestCase):
    def test_container_defaults_are_offline_and_fail_closed_remotely(self):
        config = load_config(str(ROOT / "config" / "container.yaml"))
        self.assertEqual(config.server.host, "0.0.0.0")
        self.assertEqual(config.server.port, 8080)
        self.assertEqual(config.database.path, "/data/gateway.db")
        self.assertEqual(config.llm.provider, "local")
        self.assertEqual(config.llm.endpoint, "")
        self.assertTrue(config.auth.require_token_when_remote)
        self.assertFalse(config.auth.demo_mode)
        self.assertTrue(config.processing.async_enabled)
        self.assertEqual(config.policy.approval_quorum, 1)
        self.assertEqual(
            config.syslog.gateway_profiles,
            {product: f"auto-{product}-json" for product in ("waf", "hips", "ndr", "rasp", "siem")},
        )
        self.assertEqual(config.syslog.product_protocols["rasp"], "tcp")
        self.assertEqual(config.syslog.max_frame_bytes, 2_000_000)

    def test_container_environment_can_select_remote_model_and_retention(self):
        with patch.dict(
            os.environ,
            {
                "DEFENSIVE_AI_LLM_PROVIDER": "ollama",
                "DEFENSIVE_AI_LLM_ENDPOINT": "http://ollama.ai-platform.svc:11434/api/generate",
                "DEFENSIVE_AI_LLM_MODEL": "qwen3:8b",
                "DEFENSIVE_AI_LLM_ALLOWED_HOSTS": "ollama.ai-platform.svc",
                "DEFENSIVE_AI_DATA_RETENTION_DAYS": "120",
                "DEFENSIVE_AI_AUDIT_RETENTION_DAYS": "730",
                "DEFENSIVE_AI_MEMORY_EVENT_RETENTION_DAYS": "540",
            },
        ):
            config = load_config(str(ROOT / "config" / "container.yaml"))
        self.assertEqual(config.llm.provider, "ollama")
        self.assertEqual(config.llm.model, "qwen3:8b")
        self.assertEqual(config.llm.allowed_hosts, ["ollama.ai-platform.svc"])
        self.assertEqual(config.operations.data_retention_days, 120)
        self.assertEqual(config.operations.audit_retention_days, 730)
        self.assertEqual(config.operations.memory_history_retention_days, 540)

    def test_dockerfile_uses_minimal_non_root_runtime_contract(self):
        dockerfile = (ROOT / "deploy" / "docker" / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn('USER 10001:10001', dockerfile)
        self.assertIn('CMD ["--config", "config/container.yaml"]', dockerfile)
        self.assertIn('HEALTHCHECK', dockerfile)
        self.assertIn('ARG PYTHON_BASE_IMAGE=', dockerfile)
        self.assertIn('/api/ready', dockerfile)
        self.assertNotIn('COPY . /app', dockerfile)

    def test_production_compose_is_loopback_only_and_requires_role_tokens(self):
        compose = (ROOT / "deploy" / "docker" / "compose.production.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn('127.0.0.1:${DEFENSIVE_AI_LOCAL_PORT:-8080}:8080', compose)
        self.assertIn("DEFENSIVE_AI_APPROVAL_QUORUM: \"2\"", compose)
        self.assertIn('DEFENSIVE_AI_DEMO_MODE: "0"', compose)
        self.assertIn("DEFENSIVE_AI_LLM_MODEL", compose)
        self.assertIn("DEFENSIVE_AI_LLM_ALLOWED_HOSTS", compose)
        self.assertIn("no-new-privileges:true", compose)

    def test_single_host_caddy_config_has_an_ip_certificate_fallback(self):
        caddyfile = (ROOT / "deploy" / "docker" / "Caddyfile.single-host").read_text(
            encoding="utf-8"
        )
        self.assertIn(":443", caddyfile)
        self.assertIn("admin 127.0.0.1:2019", caddyfile)
        self.assertIn("tls /etc/caddy/defensive-ai-gateway.crt", caddyfile)
        self.assertIn("@gateway host __PUBLIC_HOST__", caddyfile)
        self.assertNotIn("tls internal", caddyfile)

    def test_single_host_vector_watches_an_atomic_config_directory(self):
        compose = (ROOT / "deploy" / "docker" / "compose.single-host.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("context: ../..", compose)
        self.assertIn("dockerfile: deploy/docker/Dockerfile", compose)
        self.assertIn('command: ["--config", "/etc/vector/vector.toml", "--watch-config"]', compose)
        self.assertIn('/vector:/etc/vector:ro', compose)
        self.assertIn('/vector:/var/lib/vector', compose)

    def test_systemd_installer_never_writes_known_tokens_and_keeps_demo_loopback(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        service = (ROOT / "deploy" / "systemd" / "defensive-ai-gateway.service").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("replace-with-a-strong-token", installer)
        self.assertIn("production role tokens must be distinct", installer)
        self.assertIn("APPROVAL_QUORUM=2", installer)
        self.assertIn('SERVER_HOST="127.0.0.1"', installer)
        self.assertIn("EnvironmentFile=$ENV_FILE", installer)
        self.assertIn("DEFENSIVE_AI_DEMO_MODE=", installer)
        self.assertIn("MemoryMax=2G", installer)
        self.assertIn("ProtectHome=read-only", installer)
        self.assertIn("systemctl is-active --quiet defensive-ai-gateway.service", installer)
        self.assertIn("http://127.0.0.1:8080/api/ready", installer)
        self.assertIn("EnvironmentFile=/etc/defensive-ai-gateway/env", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertNotIn("replace-with-a-strong-token", service)
        self.assertNotIn('. "$ENV_FILE"', installer)

    def test_systemd_installer_demo_dry_run_needs_no_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    "bash",
                    str(ROOT / "install.sh"),
                    "--demo-mode",
                    "--dry-run",
                    "--config-dir",
                    str(Path(tmp) / "config"),
                    "--data-dir",
                    str(Path(tmp) / "data"),
                ],
                cwd=ROOT,
                env={"PATH": os.environ.get("PATH", "")},
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("loopback-only", result.stdout)

    def test_installer_rejects_switching_an_exposed_config_to_demo_without_rewrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp) / "config"
            config_dir.mkdir()
            (config_dir / "prod.yaml").write_text(
                """
server:
  host: "0.0.0.0"
  port: 8080
policy:
  approval_quorum: 2
auth:
  allow_loopback_no_token: false
  require_token_when_remote: true
  demo_mode: false
""".strip()
                + "\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    "bash",
                    str(ROOT / "install.sh"),
                    "--demo-mode",
                    "--dry-run",
                    "--config-dir",
                    str(config_dir),
                    "--data-dir",
                    str(Path(tmp) / "data"),
                ],
                cwd=ROOT,
                env={"PATH": os.environ.get("PATH", "")},
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("--force-config", result.stderr)


class K3sManifestTest(unittest.TestCase):
    def setUp(self):
        self.manifest = (ROOT / "deploy" / "k3s" / "gateway.yaml").read_text(encoding="utf-8")

    def test_base_manifest_is_cluster_only_and_production_exposure_is_tls_allowlisted(self):
        self.assertNotIn("hostPort: 8080", self.manifest)
        self.assertIn("containerPort: 8080", self.manifest)
        self.assertNotIn("kind: Ingress", self.manifest)
        production = (ROOT / "deploy" / "k3s" / "production-exposure.yaml").read_text(
            encoding="utf-8"
        )
        demo = (ROOT / "deploy" / "k3s" / "demo-exposure-patch.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("kind: Ingress", production)
        self.assertIn("secretName: \"@@TLS_SECRET@@\"", production)
        self.assertIn('sourceRange: "@@SOURCE_CIDRS_JSON@@"', production)
        self.assertIn("kind: NetworkPolicy", production)
        self.assertIn("hostPort: 8080", demo)

    def test_manifest_is_air_gapped_and_single_node_upgrade_safe(self):
        self.assertIn("imagePullPolicy: Never", self.manifest)
        self.assertIn("type: Recreate", self.manifest)
        self.assertIn('image: "@@GATEWAY_IMAGE@@"', self.manifest)
        self.assertIn("readOnlyRootFilesystem: true", self.manifest)
        self.assertIn("automountServiceAccountToken: false", self.manifest)
        self.assertIn("mountPath: /data", self.manifest)
        self.assertIn("ephemeral-storage: 256Mi", self.manifest)
        self.assertIn("path: /api/live", self.manifest)
        self.assertIn("path: /api/ready", self.manifest)

    def test_bundle_installer_does_not_require_optional_env_file(self):
        package_script = (ROOT / "scripts" / "package_k3s_deploy.sh").read_text(encoding="utf-8")
        installer = (ROOT / "deploy" / "k3s" / "install-k3s-bundle.sh").read_text(encoding="utf-8")
        self.assertIn("refusing to package a dirty worktree", package_script)
        self.assertIn("build-offline-images.sh", package_script)
        self.assertNotIn("defensive-ai-gateway-source.tar.gz", package_script)
        self.assertNotIn('cp -R "$ROOT_DIR/deploy/docker"', package_script)
        self.assertIn("--preflight-only", installer)
        self.assertIn("--demo-mode", installer)
        self.assertIn("production role tokens must be distinct", installer)
        self.assertIn("DEFENSIVE_AI_ALLOWED_SOURCE_CIDRS", installer)
        self.assertIn("backup_database", installer)
        self.assertIn("restore_database", installer)
        self.assertIn("copy_runtime_secret", installer)
        self.assertIn("exposure_mode", installer)
        self.assertIn("--from-env-file=", installer)
        self.assertIn("DEFENSIVE_AI_DEMO_MODE=", installer)
        self.assertNotIn("--from-literal=DEFENSIVE_AI_API_TOKEN", installer)
        self.assertNotIn("${DEFENSIVE_AI_INGEST_TOKEN:-${DEFENSIVE_AI_API_TOKEN:-}}", installer)
        self.assertIn("rollout restart deployment/syslog-collector-vector", installer)
        self.assertIn("awk '/^defensive-ai-gateway-backup-/'", installer)
        self.assertIn('delete configmap "defensive-ai-syslog-backup-$old_id"', installer)
        self.assertIn("restore_vector_contract \"$backup_id\"", installer)
        self.assertIn("gateway-deployment-spec.json", installer)
        self.assertIn("gateway-service-spec.json", installer)
        self.assertIn("vector-deployment-spec.json", installer)
        self.assertIn("--syslog-console-config", installer)
        self.assertIn("load_syslog_console_config", installer)
        self.assertIn("Syslog console config contains an unsupported line", installer)
        self.assertNotIn('. "$syslog_console_file"', installer)
        self.assertIn(r'{\"op\":\"replace\",\"path\":\"/spec\"', installer)
        self.assertIn("require_runtime_image", installer)
        self.assertIn('if bash "$0" --rollback "$BACKUP_ID"', installer)
        self.assertNotIn('restore_database "$BACKUP_ID" "$PREVIOUS_IMAGE" ||', installer)

    def test_bundle_installer_accepts_only_the_console_exported_source_cidr_key(self):
        installer = ROOT / "deploy" / "k3s" / "install-k3s-bundle.sh"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_file = tmp_path / "production.env"
            env_file.write_text(
                "\n".join(
                    [
                        "DEFENSIVE_AI_API_TOKEN=" + "a" * 32,
                        "DEFENSIVE_AI_INGEST_TOKEN=" + "b" * 32,
                        "DEFENSIVE_AI_OPERATOR_TOKEN=" + "c" * 32,
                        "DEFENSIVE_AI_APPROVER_TOKEN=" + "d" * 32,
                        "DEFENSIVE_AI_PUBLIC_HOST=gateway.internal.example",
                        "DEFENSIVE_AI_TLS_SECRET=defensive-ai-gateway-tls",
                        "DEFENSIVE_AI_ALLOWED_SOURCE_CIDRS=10.0.0.0/8",
                        "DEFENSIVE_AI_LLM_PROVIDER=local",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            env_file.chmod(0o600)
            console_file = tmp_path / "defensive-ai-syslog-console.env"
            console_file.write_text(
                "# Console export; no credential is included.\n"
                "DEFENSIVE_AI_SYSLOG_SOURCE_CIDRS=10.20.10.15/32,10.20.11.0/24\n",
                encoding="utf-8",
            )
            environment = {"PATH": os.environ.get("PATH", ""), "K3S_ENV_FILE": str(env_file)}
            result = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--with-syslog",
                    "--syslog-console-config",
                    str(console_file),
                    "--preflight-only",
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("preflight passed", result.stdout)

            console_file.write_text(
                "DEFENSIVE_AI_SYSLOG_SOURCE_CIDRS=10.20.10.15/32\n"
                "UNEXPECTED_SHELL_ASSIGNMENT=1\n",
                encoding="utf-8",
            )
            rejected = subprocess.run(
                [
                    "bash",
                    str(installer),
                    "--with-syslog",
                    "--syslog-console-config",
                    str(console_file),
                    "--preflight-only",
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("unsupported line", rejected.stderr)

    def test_package_script_builds_minimal_runtime_bundle_from_approved_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            image_dir = tmp_path / "images"
            out_dir = tmp_path / "dist"
            image_dir.mkdir()
            image = image_dir / "defensive-ai-gateway-latest.tar"
            image.write_bytes(b"test image archive")
            digest = hashlib.sha256(image.read_bytes()).hexdigest()
            image.with_suffix(".tar.sha256").write_text(
                f"{digest}  {image.name}\n", encoding="utf-8"
            )
            image.with_suffix(".tar.ref").write_text(
                f"defensive-ai-gateway:sha256-{'b' * 64}\n", encoding="utf-8"
            )

            subprocess.run(
                [
                    "bash",
                    str(ROOT / "scripts" / "package_k3s_deploy.sh"),
                    "--image-dir",
                    str(image_dir),
                    "--out-dir",
                    str(out_dir),
                    "--allow-dirty",
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )

            archive = out_dir / "defensive-ai-gateway-k3s-deploy.tar.gz"
            checksum = Path(f"{archive}.sha256")
            self.assertTrue(archive.is_file())
            self.assertEqual(
                checksum.read_text(encoding="utf-8").split()[0],
                hashlib.sha256(archive.read_bytes()).hexdigest(),
            )
            with tarfile.open(archive, "r:gz") as bundle:
                names = set(bundle.getnames())
            prefix = "defensive-ai-gateway-k3s-deploy"
            self.assertIn(f"{prefix}/install.sh", names)
            self.assertIn(f"{prefix}/deploy/k3s/gateway.yaml", names)
            self.assertIn(f"{prefix}/deploy/k3s/production-exposure.yaml", names)
            self.assertIn(f"{prefix}/images/{image.name}", names)
            self.assertNotIn(f"{prefix}/defensive-ai-gateway-source.tar.gz", names)
            self.assertNotIn(f"{prefix}/deploy/docker/Dockerfile", names)
            with tarfile.open(archive, "r:gz") as bundle:
                rendered = bundle.extractfile(f"{prefix}/deploy/k3s/gateway.yaml")
                assert rendered is not None
                manifest = rendered.read().decode("utf-8")
            self.assertIn(
                f'image: "defensive-ai-gateway:sha256-{"b" * 64}"',
                manifest,
            )
            self.assertNotIn("@@GATEWAY_IMAGE@@", manifest)

    def test_failed_packaging_preserves_previous_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            out_dir = tmp_path / "dist"
            out_dir.mkdir()
            archive = out_dir / "defensive-ai-gateway-k3s-deploy.tar.gz"
            archive.write_bytes(b"previous successful bundle")

            result = subprocess.run(
                [
                    "bash",
                    str(ROOT / "scripts" / "package_k3s_deploy.sh"),
                    "--image-dir",
                    str(tmp_path / "missing-images"),
                    "--out-dir",
                    str(out_dir),
                    "--allow-dirty",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(archive.read_bytes(), b"previous successful bundle")

    def test_package_rejects_mutable_gateway_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            image_dir = tmp_path / "images"
            out_dir = tmp_path / "dist"
            image_dir.mkdir()
            image = image_dir / "gateway.tar"
            image.write_bytes(b"legacy mutable image")
            digest = hashlib.sha256(image.read_bytes()).hexdigest()
            image.with_suffix(".tar.sha256").write_text(
                f"{digest}  {image.name}\n", encoding="utf-8"
            )
            image.with_suffix(".tar.ref").write_text(
                "defensive-ai-gateway:release-2026-07-14\n", encoding="utf-8"
            )

            result = subprocess.run(
                [
                    "bash",
                    str(ROOT / "scripts" / "package_k3s_deploy.sh"),
                    "--image-dir",
                    str(image_dir),
                    "--out-dir",
                    str(out_dir),
                    "--allow-dirty",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("sha256 content identity", result.stderr)

    def test_vector_bundle_renders_digest_image_but_defers_source_cidrs(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            image_dir = tmp_path / "images"
            out_dir = tmp_path / "dist"
            image_dir.mkdir()
            refs = {
                "gateway.tar": f"defensive-ai-gateway:sha256-{'b' * 64}",
                "vector.tar": "timberio/vector@sha256:" + "a" * 64,
            }
            for name, image_ref in refs.items():
                image = image_dir / name
                image.write_bytes(name.encode("utf-8"))
                digest = hashlib.sha256(image.read_bytes()).hexdigest()
                image.with_suffix(".tar.sha256").write_text(
                    f"{digest}  {name}\n", encoding="utf-8"
                )
                image.with_suffix(".tar.ref").write_text(f"{image_ref}\n", encoding="utf-8")

            subprocess.run(
                [
                    "bash",
                    str(ROOT / "scripts" / "package_k3s_deploy.sh"),
                    "--image-dir",
                    str(image_dir),
                    "--out-dir",
                    str(out_dir),
                    "--allow-dirty",
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            archive = out_dir / "defensive-ai-gateway-k3s-deploy.tar.gz"
            member = (
                "defensive-ai-gateway-k3s-deploy/deploy/k3s/"
                "syslog-collector-vector.yaml"
            )
            with tarfile.open(archive, "r:gz") as bundle:
                extracted = bundle.extractfile(member)
                assert extracted is not None
                manifest = extracted.read().decode("utf-8")
            self.assertIn(refs["vector.tar"], manifest)
            self.assertNotIn("@@VECTOR_IMAGE@@", manifest)
            self.assertIn("@@SYSLOG_SOURCE_CIDRS_JSON@@", manifest)

    def test_syslog_collector_uses_only_the_ingest_role_token(self):
        collector = (ROOT / "deploy" / "k3s" / "syslog-collector-vector.yaml").read_text(
            encoding="utf-8"
        )
        installer = (ROOT / "deploy" / "k3s" / "install-k3s-bundle.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('Bearer ${DEFENSIVE_AI_INGEST_TOKEN}', collector)
        self.assertIn("key: DEFENSIVE_AI_INGEST_TOKEN", collector)
        self.assertNotIn('Bearer ${DEFENSIVE_AI_API_TOKEN}', collector)
        self.assertNotIn("key: DEFENSIVE_AI_API_TOKEN", collector)
        self.assertIn('loadBalancerSourceRanges: "@@SYSLOG_SOURCE_CIDRS_JSON@@"', collector)
        self.assertIn("externalTrafficPolicy: Local", collector)
        self.assertIn('image: "@@VECTOR_IMAGE@@"', collector)
        self.assertEqual(collector.count("max_events = 1"), 2)
        self.assertEqual(collector.count('framing.method = "newline_delimited"'), 2)
        self.assertEqual(collector.count("request.retry_attempts = 4294967295"), 2)
        self.assertEqual(collector.count("acknowledgements.enabled = false"), 2)
        self.assertNotIn("acknowledgements.enabled = true", collector)
        self.assertIn('"profile_id": .gateway_profile', collector)
        self.assertNotIn("?profile={{ _gateway_profile }}", collector)
        self.assertIn('(to_string(structured.data_type) ?? "")', collector)
        self.assertNotIn('\n    else if product ==', collector)
        self.assertIn("syslog-collector-ingress", installer)
        self.assertIn("render_syslog_network_policy", installer)
        self.assertIn("{protocol: UDP, port: 15143}", installer)

    def test_single_host_vector_renderer_keeps_profile_id_out_of_the_uri(self):
        renderer = ROOT / "deploy" / "docker" / "render-single-host-vector-config.sh"
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "vector.toml"
            result = subprocess.run(
                ["bash", str(renderer), str(output)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            rendered = output.read_text(encoding="utf-8")
        self.assertIn('"profile_id": .gateway_profile', rendered)
        self.assertIn('uri = "http://127.0.0.1:8080/api/alerts"', rendered)
        self.assertNotIn("{{ _gateway_profile }}", rendered)
        self.assertIn('address = "127.0.0.1:8686"', rendered)

    def test_role_tokens_are_wired_through_secret_env_and_installer(self):
        env_example = (ROOT / "deploy" / "k3s" / "env.example").read_text(encoding="utf-8")
        installer = (ROOT / "deploy" / "k3s" / "install-k3s-bundle.sh").read_text(
            encoding="utf-8"
        )
        for name in (
            "DEFENSIVE_AI_API_TOKEN",
            "DEFENSIVE_AI_INGEST_TOKEN",
            "DEFENSIVE_AI_OPERATOR_TOKEN",
            "DEFENSIVE_AI_APPROVER_TOKEN",
        ):
            self.assertIn(f"{name}=", env_example)
            self.assertIn(name, installer)
        self.assertNotIn("kind: Secret", self.manifest)
        self.assertIn("--from-env-file=", installer)

    def test_manifests_and_prod_config_express_least_privilege_defaults(self):
        collector = (ROOT / "deploy" / "k3s" / "syslog-collector-vector.yaml").read_text(
            encoding="utf-8"
        )
        prod = (ROOT / "config" / "prod.example.yaml").read_text(encoding="utf-8")
        for product in ("waf", "hips", "ndr", "rasp", "siem"):
            self.assertIn(f'gateway_profile = "auto-{product}-json"', collector)
        self.assertIn("approval_quorum: 2", prod)
        self.assertIn("data_retention_days: 90", prod)

    def test_production_preflight_accepts_strong_values_and_rejects_placeholders(self):
        installer = ROOT / "deploy" / "k3s" / "install-k3s-bundle.sh"
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env.update(
                {
                    "K3S_ENV_FILE": str(Path(tmp) / "missing.env"),
                    "DEFENSIVE_AI_API_TOKEN": "a" * 32,
                    "DEFENSIVE_AI_INGEST_TOKEN": "b" * 32,
                    "DEFENSIVE_AI_OPERATOR_TOKEN": "c" * 32,
                    "DEFENSIVE_AI_APPROVER_TOKEN": "d" * 32,
                    "DEFENSIVE_AI_PUBLIC_HOST": "gateway.internal.example",
                    "DEFENSIVE_AI_TLS_SECRET": "defensive-ai-gateway-tls",
                    "DEFENSIVE_AI_ALLOWED_SOURCE_CIDRS": "10.0.0.0/8",
                    "DEFENSIVE_AI_LLM_PROVIDER": "local",
                }
            )
            accepted = subprocess.run(
                ["bash", str(installer), "--preflight-only"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            env["DEFENSIVE_AI_API_TOKEN"] = "replace-with-a-strong-token-value"
            rejected = subprocess.run(
                ["bash", str(installer), "--preflight-only"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("non-placeholder", rejected.stderr)

            env["DEFENSIVE_AI_API_TOKEN"] = "a" * 32
            env["DEFENSIVE_AI_ALLOWED_SOURCE_CIDRS"] = "0.0.0.0/00"
            rejected_cidr = subprocess.run(
                ["bash", str(installer), "--preflight-only"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(rejected_cidr.returncode, 0)
            self.assertIn("restricted CIDRs", rejected_cidr.stderr)

    def test_release_scripts_pin_supply_chain_and_exclude_env_files(self):
        build = (ROOT / "deploy" / "k3s" / "build-offline-images.sh").read_text(
            encoding="utf-8"
        )
        package = (ROOT / "scripts" / "package_offline.sh").read_text(encoding="utf-8")
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
        self.assertIn("PYTHON_BASE_IMAGE", build)
        self.assertIn("must pin Vector by sha256 digest", build)
        self.assertIn("GATEWAY_IMAGE_ID", build)
        self.assertIn(":sha256-${GATEWAY_IMAGE_ID#sha256:}", build)
        self.assertIn("is_content_addressed_gateway_ref", (
            ROOT / "scripts" / "package_k3s_deploy.sh"
        ).read_text(encoding="utf-8"))
        self.assertIn("refusing to build release images from a dirty worktree", build)
        self.assertIn('--exclude="./.env"', package)
        self.assertIn('--exclude="*/.env"', package)
        self.assertIn(".env", ignore)
        self.assertIn(".env", dockerignore)
        self.assertIn("**/.env", dockerignore)
        self.assertIn("config/prod.yaml", dockerignore)

    def test_production_env_examples_are_valid_shell_files(self):
        for path in (
            ROOT / "deploy" / "docker" / "env.production.example",
            ROOT / "deploy" / "k3s" / "env.example",
        ):
            result = subprocess.run(
                ["bash", "-n", str(path)], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, f"{path}: {result.stderr}")


if __name__ == "__main__":
    unittest.main()
