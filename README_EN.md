# Defensive AI Gateway

English | [中文](README.md)

Defensive AI Gateway is an MVP for banking security operations. It is designed to be developed and validated outside the enterprise network first, then packaged and migrated into an internal environment.

## Technical Approach

- Python standard library first: the initial version avoids pip/npm dependencies to reduce supply-chain review friction during internal migration.
- SQLite fact store: ready for PoC use and replaceable with PostgreSQL for production.
- HTTP API + static Dashboard: ingests HIPS/RASP/NDR/WAF/SIEM alerts and displays cases in real time.
- Async alert queue: the HTTP intake path authenticates, maps, and queues alerts while background workers run analysis, avoiding high-QPS intake blocking.
- Agent/Skill/Harness layering: product-specific prompts, memory namespaces, policy checks, and offline replay evolve independently.
- Pluggable LLM: the development configuration defaults to the deterministic local analyzer `local-rule-analyst`; switch to local Ollama or an internal LLM Gateway from the Dashboard when you need model-backed validation.
- Random samples + memory-based noise reduction: sample scripts can generate attack / false-positive alerts, and approved product long-term memory helps identify repeated false positives from the same system.

## Quick Start

```bash
python3 -m defensive_ai_gateway --config config/dev.yaml
```

The service listens on `127.0.0.1:8080` by default:

- Dashboard: `http://127.0.0.1:8080/`
- Health check: `GET /api/health`
- Submit alert: `POST /api/alerts`
- List cases: `GET /api/cases`

## Submit Sample Alerts

```bash
python3 scripts/send_sample.py --file samples/waf_alert.json
python3 scripts/send_sample.py --file samples/siem_case.json
```

You can also generate random attack or false-positive alerts:

```bash
python3 scripts/send_sample.py --random --count 5 --product waf --scenario random
python3 scripts/send_sample.py --random --count 3 --product waf --scenario false_positive --seed 42
```

## Real Log Format Adaptation

The Dashboard's Adapter page can configure Mapping Profiles that map real internal security logs into the stable internal `RawAlert` format. The dry-run preview shows both `RawAlert` and `NormalizedEvent`. For production ingestion, submit real logs through `POST /api/alerts?profile=<profile_id>` or include `profile_id` in the request body. Logs that fail mapping are not sent to LLM analysis.

The harness can also replay sanitized real logs through a profile:

```bash
python3 scripts/run_harness.py --samples real_logs/rasp --mapping-profile demo-rasp-json
python3 scripts/run_harness.py --samples real_logs/rasp --mapping-profile-file config/rasp-prod-profile.json
```

## Offline Replay and Packaging

```bash
python3 scripts/run_harness.py --samples samples --fail-on-low-confidence 0.5
python3 scripts/run_harness.py --samples samples --random-count 10 --random-scenario random --seed 42
python3 scripts/run_harness.py --samples samples --random-count 5 --random-product waf --random-scenario false_positive --seed-demo-memory
python3 scripts/run_harness.py --samples samples --config config/dev.yaml --use-config-llm
bash scripts/package_offline.sh ../outputs
```

`--use-config-llm` uses the default `local-rule-analyst` from `config/dev.yaml`. To replay with a model-backed LLM, switch the config or Dashboard to local Ollama / an internal LLM Gateway first.

## k3s and Syslog Ingestion

For production ingestion, deploy an independent collector in k3s to receive syslog and forward it to the gateway HTTP endpoint:

```text
Security Product -> Syslog UDP/TCP 15140-15144 -> Collector -> POST /api/alerts
```

Reference manifests:

- `deploy/k3s/gateway.yaml`: gateway Deployment, Service, Ingress, PVC, and production configuration.
- `deploy/k3s/syslog-collector-vector.yaml`: Vector syslog collector reference manifest that converts syslog into standard alert JSON.
- `docs/SYSLOG_INGESTION.md`: security product configuration, Mapping Profile integration, and operations notes.

You can locally simulate five security devices sending syslog to different TCP ports and verify that routing does not confuse product types:

```bash
python3 -m defensive_ai_gateway --config config/dev.yaml
python3 scripts/simulate_syslog_ports.py --config config/dev.yaml
```

## Project Structure

```text
defensive_ai_gateway/
  app.py              HTTP API and Dashboard service
  config.py           YAML-subset configuration parser and environment overrides
  database.py         SQLite schema and repository
  models.py           Event, Case, and Agent output models
  normalizer.py       Multi-product event normalization
  orchestrator.py     Agent routing and execution loop
  llm.py              Default local LLM adapter and enterprise gateway client
  policy.py           Sandbox policy, redaction, and tool permission controls
  memory.py           Multi-layer memory management plus evidence store
  agents/             HIPS/RASP/NDR/WAF/SIEM product-specific agents
  static/             Dashboard frontend
config/
  dev.yaml            External development configuration
  prod.example.yaml   Internal production configuration template
deploy/
  docker/             Container deployment reference
  k3s/                k3s deployment and syslog collector manifests
  systemd/            Linux systemd deployment reference
docs/
  TECHNICAL_PLAN.md   Technical plan and migration path
  OFFLINE_MIGRATION.md Offline migration steps
  HARNESS.md          Replay evaluation guide
  MEMORY.md           Multi-layer memory governance
  SYSLOG_INGESTION.md Syslog collector ingestion guide
```

## Security Defaults

- Read-only analysis by default; no blocking, isolation, policy changes, or account disabling are executed.
- Fields are redacted before prompts; raw evidence remains in the database.
- Every Agent Run, LLM call, policy interception, and output is written to audit records.
- High-impact actions only produce `approve_required` recommendations.
