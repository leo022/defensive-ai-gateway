from __future__ import annotations

import unittest
from pathlib import Path

from defensive_ai_gateway.config import load_config


ROOT = Path(__file__).resolve().parents[1]


class ContainerDefaultsTest(unittest.TestCase):
    def test_container_defaults_are_offline_and_directly_accessible(self):
        config = load_config(str(ROOT / "config" / "container.yaml"))
        self.assertEqual(config.server.host, "0.0.0.0")
        self.assertEqual(config.server.port, 8080)
        self.assertEqual(config.database.path, "/data/gateway.db")
        self.assertEqual(config.llm.provider, "local")
        self.assertEqual(config.llm.endpoint, "")
        self.assertFalse(config.auth.require_token_when_remote)
        self.assertTrue(config.processing.async_enabled)

    def test_dockerfile_uses_minimal_non_root_runtime_contract(self):
        dockerfile = (ROOT / "deploy" / "docker" / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn('USER 10001:10001', dockerfile)
        self.assertIn('CMD ["--config", "config/container.yaml"]', dockerfile)
        self.assertIn('HEALTHCHECK', dockerfile)
        self.assertNotIn('COPY . /app', dockerfile)


class K3sManifestTest(unittest.TestCase):
    def setUp(self):
        self.manifest = (ROOT / "deploy" / "k3s" / "gateway.yaml").read_text(encoding="utf-8")

    def test_manifest_exposes_node_port_8080_without_ingress_configuration(self):
        self.assertIn("hostPort: 8080", self.manifest)
        self.assertIn("containerPort: 8080", self.manifest)
        self.assertNotIn("kind: Ingress", self.manifest)

    def test_manifest_is_air_gapped_and_single_node_upgrade_safe(self):
        self.assertIn("imagePullPolicy: Never", self.manifest)
        self.assertIn("type: Recreate", self.manifest)
        self.assertIn("readOnlyRootFilesystem: true", self.manifest)
        self.assertIn("automountServiceAccountToken: false", self.manifest)
        self.assertIn("mountPath: /data", self.manifest)

    def test_bundle_installer_does_not_require_optional_env_file(self):
        package_script = (ROOT / "scripts" / "package_k3s_deploy.sh").read_text(encoding="utf-8")
        installer = (ROOT / "deploy" / "k3s" / "install-k3s-bundle.sh").read_text(encoding="utf-8")
        self.assertNotIn(".env not found", package_script)
        self.assertIn("--require-token", installer)
        self.assertNotIn("DEFENSIVE_AI_API_TOKEN is required. Copy", installer)

    def test_optional_syslog_collector_supports_empty_or_configured_token(self):
        collector = (ROOT / "deploy" / "k3s" / "syslog-collector-vector.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn('Bearer ${DEFENSIVE_AI_API_TOKEN}', collector)
        self.assertNotIn('DEFENSIVE_AI_API_TOKEN:?', collector)


if __name__ == "__main__":
    unittest.main()
