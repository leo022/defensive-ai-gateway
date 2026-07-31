# Defensive AI Gateway

[Simplified Chinese](README.md) | English

Defensive AI Gateway is an alert investigation and response gateway for security operations
centers (SOCs). It provides a unified path for ingesting HIPS, RASP, NDR, WAF, and SIEM alerts,
normalizing data, queueing work durably, performing AI-assisted analysis, applying deterministic
validation, obtaining human approval, executing controlled responses, and preserving a complete
audit trail.

This repository is a runnable reference implementation intended for solution validation,
integration testing, and deployment in controlled environments. Before production use, complete
the identity and secret management, network isolation, capacity planning, disaster recovery, and
security compliance work required by your organization.

## Core Capabilities

| Capability | Description |
| --- | --- |
| Multi-source ingestion | Ingest HIPS, RASP, NDR, WAF, and SIEM data through the HTTP API or a Syslog Collector |
| Stable data contract | Convert vendor-native logs into `RawAlert` and `NormalizedEvent` records through Mapping Profiles |
| Reliable asynchronous processing | Persist alerts in a SQLite-backed queue before returning `202`, with bounded retries, deferred recovery, and a queryable DLQ |
| Layered intelligent analysis | Route product-specific Agents, Skills, and memory namespaces to the local rule analyzer, Ollama, or a compatible enterprise LLM Gateway |
| Validation and governance | Use the Validator to check evidence traceability, prompt injection, sensitive output, and action permissions |
| Human-governed response | Investigate, review, approve, execute, verify, and roll back response actions from the Case workbench |
| Offline evaluation and delivery | Use reproducible fixtures, randomized scenarios, Harness replay, offline packaging, and Docker/k3s deployment references |

## Processing Flow

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

## Requirements

- Python 3.11 (recommended)
- SQLite (included in the Python standard library)
- No required pip or npm runtime dependencies
- Optional: Docker, k3s, Ollama, or a compatible enterprise LLM Gateway

## Quick Start

```bash
python3 -m defensive_ai_gateway --config config/dev.yaml
```

The service listens on `127.0.0.1:8080` by default:

| Purpose | Address or endpoint |
| --- | --- |
| Dashboard | `http://127.0.0.1:8080/` |
| Liveness | `GET /api/live` |
| Readiness | `GET /api/ready` |
| Runtime status | `GET /api/health` |
| Submit an alert | `POST /api/alerts` |
| List Cases | `GET /api/cases` |
| Query deferred work | `GET /api/alerts/inbox?status=deferred&limit=100&offset=0` |
| Query the dead-letter queue | `GET /api/alerts/inbox?status=dead_letter&limit=100&offset=0` |

The development configuration uses the deterministic `local-rule-analyst` by default, so the
gateway can run without an external model service.

## Model Service Configuration

The Dashboard's "Model Service -> Internal Gateway" option supports enterprise model services
that implement an OpenAI-compatible HTTP API. The equivalent environment variable configuration
is:

```bash
export DEFENSIVE_AI_LLM_PROVIDER=gateway
export DEFENSIVE_AI_LLM_ENDPOINT="https://llm-gateway.example.com/v1/responses"
export DEFENSIVE_AI_LLM_API_KEY="<api-key>"
export DEFENSIVE_AI_LLM_MODEL="<model-id>"
export DEFENSIVE_AI_LLM_ALLOWED_HOSTS="llm-gateway.example.com"
```

The Gateway supports `/v1/responses`, `/v1/chat/completions`, Anthropic Messages, and the existing
enterprise JSON protocol. Use Anthropic Messages only with a service that actually implements the
protocol. When `ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN` are set, the endpoint is normalized
to `/v1/messages`.

Credentials are used only for the configured same-origin endpoint. Inject secrets through
environment variables or a dedicated secret manager; never write them to YAML, README files,
logs, or other repository content.

The Gateway calls request-response HTTP APIs only. It does not support `wss://`, `/v1/realtime`,
`/ws`, or other WebSocket endpoints. If the service returns HTTP 426
`WebSocket upgrade required`, use its `/v1/responses` or `/v1/chat/completions` HTTP endpoint
instead of retrying the same URL.

## Sample Alerts and Validation

```bash
python3 scripts/send_sample.py --file samples/waf_alert.json
python3 scripts/send_sample.py --file samples/siem_case.json
python3 scripts/send_demo_alerts.py
```

`alert_id` is the idempotency key for an alert occurrence. Before transmission, the sample sender
generates the current timestamp and a unique instance ID by default. Embedded event IDs and
timestamps in vendor-native logs are refreshed as well. Preserve fixture identity only when
testing historical replay or idempotency:

```bash
python3 scripts/send_sample.py --file samples/waf_alert.json --preserve-fixture-identity
```

If the same `alert_id` arrives with different timestamps, fields, or evidence, the API returns
`409 alert_id_conflict`. Upstream systems must assign a unique ID to every new alert occurrence
so the gateway never silently drops or rewrites audit evidence. Same-type alerts with different
IDs can still be grouped into one Case within the default one-hour correlation window. This is
correlation, not replacement.

`send_demo_alerts.py` submits 16 demonstration alerts covering five product types, including a
WAF XSS prompt-injection fixture that is expected to produce Validator status `review` without
creating an approval item. The script waits until all target alerts enter `completed` or
`dead_letter`; use `--wait-seconds 0` to submit without waiting.

`clean_alerts_and_memory.py` clears the durable inbox together with alert and memory data. It
refuses to run while any work remains in `pending`, `retry`, `deferred`, or `processing`, preventing
the removal of facts that are still being processed.

In production, durable queue admission is governed by `processing.queue_max_size` (unfinished
items), `processing.queue_max_bytes` (raw alert JSON bytes for unfinished items), and
`processing.min_free_bytes` (reserved free space on the database filesystem). The corresponding
environment variables are `DEFENSIVE_AI_QUEUE_MAX_SIZE`, `DEFENSIVE_AI_QUEUE_MAX_BYTES`, and
`DEFENSIVE_AI_MIN_FREE_BYTES`. Reaching a capacity threshold pauses new ingestion without taking
the single Gateway instance out of readiness. Current usage, oldest backlog age, and disk
headroom are reported by `GET /api/health`.

For a Case held by this validation gate, an analyst can inspect the raw logs and evidence in the
response workbench and choose to continue it to approval. The action requires a review rationale.
The original validation remains `review`, and automatic memory writes remain suppressed. A
non-executing approval item is created only when `prompt_injection_detected` is the sole finding
and all other deterministic checks pass.

To demonstrate this negative validation path separately:

```bash
python3 scripts/send_demo_alerts.py --batch validation-review
```

The Validator gate checks evidence traceability, prompt injection, sensitive output, and action
permissions in the analysis result; it does not replace WAF threat rules. A WAF alert can match
XSS and be classified as a real attack while the gate reports `passed`. In that context, `passed`
means the analysis output is compliant and eligible for approval, not that the alert is benign.

You can also generate attack or false-positive alerts with randomized characteristics:

```bash
# --file preserves rule and evidence semantics while generating a current time and unique ID
python3 scripts/send_sample.py --file samples/ndr_alert.json

# --mutate also randomizes variable fields such as IPs, sessions, and rates
python3 scripts/send_sample.py --file samples/ndr_alert.json --mutate --count 2

# Preserve fixed IDs and timestamps only for historical or idempotency replay
python3 scripts/send_sample.py --file samples/ndr_alert.json --preserve-fixture-identity

# --random selects a product, scenario, and supported product feature
python3 scripts/send_sample.py --random --count 5 --product waf --scenario random
python3 scripts/send_sample.py --random --count 3 --product waf --scenario false_positive --seed 42

# Keep the product feature fixed while allowing the scenario to vary
python3 scripts/send_sample.py --random --count 3 --product ndr --feature brute_force --scenario attack
python3 scripts/send_sample.py --random --count 3 --product ndr --feature sql_injection --scenario attack

# List supported feature IDs; aliases such as sqli, bruteforce, and c2 are accepted
python3 scripts/send_sample.py --list-features
```

`--file` and `--random` are mutually exclusive sending modes. `--feature` controls the attack
feature, while `--scenario` controls whether the sample represents an attack, a review case, or a
false positive. When `--feature` is omitted, the product feature is selected randomly.
`--preserve-generated-identity` remains available as a compatibility alias; new commands should
use `--preserve-fixture-identity`. The offline Harness supports the same controls:

```bash
python3 scripts/run_harness.py --samples samples --random-count 10 --random-product ndr --random-feature brute_force
```

## Real Log Format Adaptation

The Dashboard's Adapter page configures Mapping Profiles that map vendor-native alerts into stable
`RawAlert` records. Its dry-run preview displays both `RawAlert` and `NormalizedEvent`. For
production ingestion, submit source logs through `POST /api/alerts?profile=<profile_id>` or include
`profile_id` in the request body. Data that fails mapping is not sent to LLM analysis.

When vendor-native logs are submitted without a `profile`, the gateway attempts source
identification from content fingerprints. For example, `data_type=attack_event` can identify a
RASP event. WAF, HIPS, NDR, RASP, and SIEM each register an `auto-<product>-json` Profile and apply
deep field mapping after identification. Data that has no explicit `product`, cannot be
identified, and does not contain standard alert fields is rejected with `400`.

For compatibility with existing standard `RawAlert` clients, a request containing `event_type`,
`severity`, `alert_id`, `source`, or `timestamp` but no `product` is still treated as SIEM data.
Production integrations should always supply an explicit `product` or Mapping Profile.

The Harness can replay sanitized source logs through a profile:

```bash
python3 scripts/run_harness.py --samples real_logs/rasp --mapping-profile demo-rasp-json
python3 scripts/run_harness.py --samples real_logs/rasp --mapping-profile-file config/rasp-prod-profile.json
```

## Offline Replay and Packaging

```bash
python3 scripts/run_harness.py --samples samples --fail-on-low-confidence 0.5
python3 scripts/run_harness.py --samples samples --fail-on-validation-review
python3 scripts/run_harness.py --samples samples --random-count 10 --random-scenario random --seed 42
python3 scripts/run_harness.py --samples samples --random-count 5 --random-product waf --random-scenario false_positive --seed-demo-memory
python3 scripts/run_harness.py --samples samples --config config/dev.yaml --use-config-llm
bash scripts/package_offline.sh ../outputs
```

`--use-config-llm` uses the default `local-rule-analyst` from `config/dev.yaml`. To replay with a
model-backed LLM, switch the configuration or Dashboard to Ollama or an enterprise LLM Gateway.

After extracting an offline package, run the installation checks to generate the production
configuration and data directory:

```bash
export DEFENSIVE_AI_API_TOKEN='<32+ chars>'
export DEFENSIVE_AI_INGEST_TOKEN='<different 32+ chars>'
export DEFENSIVE_AI_OPERATOR_TOKEN='<different 32+ chars>'
export DEFENSIVE_AI_APPROVER_TOKEN='<different 32+ chars>'
export DEFENSIVE_AI_RESPONDER_TOKEN='<different 32+ chars>'
bash install.sh
python3 -m defensive_ai_gateway --config config/prod.yaml
```

To install a systemd service:

```bash
sudo --preserve-env=DEFENSIVE_AI_API_TOKEN,DEFENSIVE_AI_INGEST_TOKEN,DEFENSIVE_AI_OPERATOR_TOKEN,DEFENSIVE_AI_APPROVER_TOKEN,DEFENSIVE_AI_RESPONDER_TOKEN \
  bash install.sh --systemd --enable --start
```

Production installation rejects empty, known-placeholder, or duplicate role tokens. It requires
two approvals by default and disables loopback authentication bypass. The systemd service listens
on `127.0.0.1:8080` only; expose it through a same-host TLS/mTLS reverse proxy so bearer tokens do
not traverse node-level plaintext HTTP.

`bash install.sh --demo-mode` generates loopback and single-approval settings only. It does not
change the existing `config/dev.yaml` demonstration workflow.

## Containerized Deployment and Syslog Ingestion

### Docker Demonstration Environment

The image includes an offline runtime configuration with the local rule analyzer,
`0.0.0.0:8080`, and SQLite at `/data/gateway.db`. It can run without mounting a configuration
file:

```bash
docker build -t defensive-ai-gateway:latest -f deploy/docker/Dockerfile .
docker run --rm -p 127.0.0.1:8080:8080 \
  -e DEFENSIVE_AI_AUTH_REQUIRE_REMOTE_TOKEN=0 \
  -e DEFENSIVE_AI_DEMO_MODE=1 \
  -v defensive-ai-data:/data defensive-ai-gateway:latest
```

Open `http://127.0.0.1:8080`. The two environment variables above are for isolated demonstration
environments only. Production deployments should use the Compose reference below and replace
loopback bypass, demonstration flags, and single-approval settings with production values.

### Docker Production Reference

`deploy/docker/compose.production.yaml` is the production Docker reference. The application binds
to the host loopback interface and must be exposed through a same-host TLS/mTLS reverse proxy. The
preflight script validates immutable image digests, five distinct strong tokens, and
local/Ollama/Gateway model settings:

```bash
set -a
. /secure/path/defensive-ai.env
set +a
bash deploy/docker/validate-production-env.sh
docker compose -f deploy/docker/compose.production.yaml up -d
```

### k3s and Syslog

For production ingestion, deploy an independent collector in k3s to receive Syslog and forward it
to the Gateway HTTP endpoint:

```text
Security Product -> Syslog 15140-15144 (RASP 15143 uses TCP; UDP is migration-only) -> Collector -> POST /api/alerts
```

Reference manifests:

- `deploy/k3s/gateway.yaml`: a Gateway Deployment, Service, and PVC that fail closed when remote
  authentication is not configured.
- `deploy/k3s/syslog-collector-vector.yaml`: a Vector Syslog Collector reference that uses a
  dedicated ingest token and forwards data through the five built-in product Mapping Profiles.
- `docs/SYSLOG_INGESTION.md`: security product configuration, Mapping Profile integration, and
  operations guidance.

If the target server does not have Python installed, build the k3s deployment bundle:

```bash
export PYTHON_BASE_IMAGE='python:3.11-slim@sha256:<approved-digest>'
export VECTOR_IMAGE='timberio/vector@sha256:<approved-digest>'
bash scripts/package_k3s_deploy.sh --include-vector
```

The script rebuilds images from the current source and replaces
`dist/defensive-ai-gateway-k3s-deploy.tar.gz` and its checksum only after a successful build. The
bundle contains the images, checksums, k3s manifests, and import scripts required by the target
environment; it does not contain source code or build tools.

On the target server, configure five distinct role tokens, a TLS Secret, the production domain,
source CIDRs, and model settings in a mode-`600` `.env` file. Production defaults create only a
ClusterIP and TLS Ingress and reject `latest` tags, dirty worktrees, empty or weak credentials,
unrestricted source ranges, and missing TLS. Upgrades back up SQLite first and restore the
previous image and database on failure. Use `bash install.sh --demo-mode` to add a plaintext
hostPort only in an isolated, temporary demonstration environment. See
[`deploy/k3s/README.md`](deploy/k3s/README.md) for the complete procedure.

### Ingestion Verification

Simulate five security devices sending Syslog to separate TCP ports to verify collection, mapping,
and product routing:

```bash
python3 -m defensive_ai_gateway --config config/dev.yaml
python3 scripts/simulate_syslog_ports.py --config config/dev.yaml
```

The Syslog simulator refreshes event IDs and timestamps in all five source fixtures and signs an
HMAC test marker with the administrator API token. The Gateway marks an event as an operational
test sample only when the trusted ingestion path confirms a loopback source and a valid signature.
These Cases do not write long-term memory or create production approvals.

When using an already-running external Vector instance, add `--running-collector` and supply the
administrator token through the environment:

```bash
DEFENSIVE_AI_API_TOKEN='<admin-token>' \
python3 scripts/simulate_syslog_ports.py --config config/container.yaml --running-collector
```

Use `--production-event` only for tests that intentionally create production memory and approvals.
Add `--preserve-fixture-identity` when historical identity replay is also required.

## Tests and Quality Checks

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m compileall -q defensive_ai_gateway scripts tests
```

For frontend asset changes, also run `node --check` on every changed JavaScript file. For
deployment changes, run the relevant preflight scripts and verify the Gateway, reverse proxy,
Collector, listeners, and a real end-to-end sample in the target environment. A passing readiness
check alone does not validate the complete path.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Risk controls](docs/RISK_CONTROLS.md)
- [Offline migration](docs/OFFLINE_MIGRATION.md)
- [Replay evaluation](docs/HARNESS.md)
- [Response Agent](docs/RESPONSE_AGENT.md)
- [Automated response](docs/AUTOMATED_RESPONSE.md)
- [Memory management and governance](docs/MEMORY.md)
- [Syslog ingestion](docs/SYSLOG_INGESTION.md)

## Project Structure

```text
defensive_ai_gateway/
  app.py              HTTP API and Dashboard service
  config.py           YAML-subset configuration parser and environment overrides
  database.py         SQLite schema and repository
  models.py           Event, Case, and Agent output models
  normalizer.py       Multi-product event normalization
  orchestrator.py     Agent routing and execution loop
  skills.py           Versioned Skill registry and permission boundaries
  validation.py       Deterministic evidence and policy Validator
  response.py         Approval requests and structured response recommendations
  response_agent.py   Persistent Case-level ReAct investigation and read-only tools
  response_automation.py Post-approval tasks, connector execution, verification, and rollback
  llm.py              Local analyzer and enterprise gateway adapters
  policy.py           Sandbox policy, redaction, and tool permissions
  memory.py           Layered memory management and evidence store
  memory_matcher.py   Cross-model memory scoring, threshold decisions, and safe merging
  agents/             HIPS/RASP/NDR/WAF/SIEM product-specific Agents
  static/             Dashboard frontend
config/
  dev.yaml            Development and functional validation configuration
  container.yaml      Docker/k3s runtime configuration
  prod.example.yaml   Production configuration template
deploy/
  docker/             Container deployment references
  k3s/                k3s deployment and Syslog Collector manifests
  systemd/            Linux systemd deployment reference
docs/
  ARCHITECTURE.md     System architecture
  RISK_CONTROLS.md    Risk controls and trust boundaries
  RESPONSE_AGENT.md   Response Agent design
  AUTOMATED_RESPONSE.md Automated response controls and operations
  MEMORY.md           Layered memory management and governance
  SYSLOG_INGESTION.md Syslog Collector integration
samples/              Standard alert fixtures
scripts/              Sending, replay, packaging, and operations scripts
tests/                Unit and regression tests
```

## Security Defaults

- Analysis is read-only by default. The system does not directly block, isolate, or change policy.
- Fields are redacted before entering prompts; raw evidence remains in the fact store.
- Agent Runs, LLM calls, policy blocks, approvals, and response results are recorded in the audit
  trail.
- High-impact actions produce `approve_required` recommendations by default.
- Only recommendations with Validator status `passed` can enter the approval queue. A narrowly
  defined temporary source-IP block can enter controlled execution only when response policy is
  enabled, approval requirements are met, and the connector is healthy. Other high-impact actions
  remain read-only.
- Automated response is disabled by default and supports shadow, manual, and automatic modes.
  Connector credentials are read only from environment variables. Rules must be verified on the
  target device and rolled back when their TTL expires, the Case closes, or a false positive is
  confirmed. See [Automated response](docs/AUTOMATED_RESPONSE.md).
- The Response Agent uses Case-locked read-only tools for ReAct investigation, correlates stored
  telemetry, and relies on the controller to enforce evidence identity, investigation gaps,
  permissions, and approval boundaries. See [Response Agent](docs/RESPONSE_AGENT.md).
- The production template requires votes from two distinct authenticated server-side principals;
  isolated demonstration settings use a single approval.
- Demonstration ground truth is honored only for loopback requests carrying
  `X-Defensive-AI-Demo-Sample: 1`. Ordinary alerts cannot assert their own verdict in the request
  body.
