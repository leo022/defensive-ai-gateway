from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .json_safety import loads_bounded_json
from .models import (
    SERVER_OWNED_ALERT_PAYLOAD_FIELDS,
    AgentResult,
    NormalizedEvent,
    RawAlert,
    ValidationResult,
    now_ms,
)
from .validation import can_continue_after_manual_review


_RESPONSE_AGENT_CORRELATION_ALIASES = {
    "agent_host": "host",
    "app": "app",
    "application": "app",
    "application_name": "app",
    "asset": "host",
    "asset_name": "host",
    "account": "user",
    "account_name": "user",
    "client_ip": "src_ip",
    "computer_name": "host",
    "correlation_id": "trace_id",
    "destination": "host",
    "destination_host": "host",
    "destination_ip": "dst_ip",
    "device": "host",
    "device_name": "host",
    "dst_host": "host",
    "dst_ip": "dst_ip",
    "fqdn": "host",
    "host": "host",
    "host_name": "host",
    "hostname": "host",
    "image": "process",
    "process": "process",
    "process_executable": "process",
    "process_name": "process",
    "request_id": "request_id",
    "request_uri": "url",
    "rasp_trace_id": "trace_id",
    "route": "url",
    "rule": "rule",
    "rule_id": "rule",
    "rule_name": "rule",
    "server": "host",
    "server_ip": "dst_ip",
    "service": "app",
    "service_name": "app",
    "signature": "rule",
    "source_ip": "src_ip",
    "source_host": "host",
    "src_host": "host",
    "src_ip": "src_ip",
    "trace_id": "trace_id",
    "uri": "url",
    "url": "url",
    "url_original": "url",
    "user": "user",
    "user_name": "user",
    "username": "user",
    "x_request_id": "request_id",
}
_RESPONSE_AGENT_CORRELATION_FIELDS = (
    "trace_id",
    "request_id",
    "host",
    "src_ip",
    "dst_ip",
    "user",
    "app",
    "process",
    "rule",
    "url",
)
PROVISIONAL_CASE_STATUSES = frozenset(
    {"analyzing", "analysis_deferred", "analysis_failed"}
)
_RESPONSE_AGENT_CORRELATION_WEIGHTS = {
    "trace_id": 8,
    "request_id": 8,
    "src_ip": 5,
    "dst_ip": 5,
    "host": 5,
    "user": 4,
    "app": 3,
    "process": 3,
    "rule": 2,
    "url": 2,
}
_RESPONSE_AGENT_MIN_CORRELATION_SCORE = 5
_RESPONSE_AGENT_HTTP_METHODS = frozenset(
    {
        "CONNECT",
        "DELETE",
        "GET",
        "HEAD",
        "OPTIONS",
        "PATCH",
        "POST",
        "PROPFIND",
        "PUT",
        "TRACE",
    }
)
_RESPONSE_AGENT_SYSLOG_ENVELOPE_PATHS = (
    ("/_syslog_envelope", ("_syslog_envelope",)),
    ("/syslog_route", ("syslog_route",)),
    ("/syslog_envelope", ("syslog_envelope",)),
)

# Raw payloads are attacker-controlled evidence. Correlation pivots may only
# come from explicit telemetry metadata paths; request bodies, parameters,
# headers and arbitrary nested business objects are deliberately absent.
_RESPONSE_AGENT_RAW_CORRELATION_PATHS = {
    ("source", "ip"): "src_ip",
    ("source", "address"): "src_ip",
    ("client", "ip"): "src_ip",
    ("client", "address"): "src_ip",
    ("destination", "ip"): "dst_ip",
    ("destination", "address"): "dst_ip",
    ("server", "ip"): "dst_ip",
    ("server", "address"): "dst_ip",
    ("destination", "domain"): "host",
    ("destination", "hostname"): "host",
    ("host", "name"): "host",
    ("host", "hostname"): "host",
    ("agent", "host"): "host",
    ("agent", "hostname"): "host",
    ("agent", "name"): "host",
    ("server", "hostname"): "host",
    ("runtime", "host"): "host",
    ("user", "name"): "user",
    ("user", "id"): "user",
    ("process", "name"): "process",
    ("process", "executable"): "process",
    ("service", "name"): "app",
    ("rule", "id"): "rule",
    ("rule", "name"): "rule",
    ("url", "original"): "url",
    ("url", "full"): "url",
    ("url", "path"): "url",
    ("request", "id"): "request_id",
    ("request", "url"): "url",
    ("request", "uri"): "url",
    ("http", "client_ip"): "src_ip",
    ("http", "request", "id"): "request_id",
    ("http", "request", "url"): "url",
    ("trace", "id"): "trace_id",
    ("event", "request_id"): "request_id",
    ("event", "trace_id"): "trace_id",
    ("event", "rasp_trace_id"): "trace_id",
    ("event", "attack_source"): "src_ip",
    ("event", "server_hostname"): "host",
    ("event", "server_domain"): "host",
    ("event", "app_name"): "app",
    ("event", "application_name"): "app",
    ("event", "request_message", "url"): "url",
    ("event", "request_message", "request_id"): "request_id",
}
for _alias, _field in _RESPONSE_AGENT_CORRELATION_ALIASES.items():
    _RESPONSE_AGENT_RAW_CORRELATION_PATHS[(_alias,)] = _field
    _RESPONSE_AGENT_RAW_CORRELATION_PATHS[("mapped_entities", _alias)] = _field
_RESPONSE_AGENT_RAW_CORRELATION_PREFIXES = {
    path[:index]
    for path in _RESPONSE_AGENT_RAW_CORRELATION_PATHS
    for index in range(1, len(path))
}


SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER PRIMARY KEY,
  applied_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS raw_alerts (
  alert_id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  product TEXT NOT NULL,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS normalized_events (
  event_id TEXT PRIMARY KEY,
  alert_id TEXT NOT NULL,
  source TEXT NOT NULL,
  product TEXT NOT NULL,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  entities_json TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  sensitivity_tags_json TEXT NOT NULL,
  evidence_hash TEXT NOT NULL DEFAULT '',
  event_at_ms INTEGER NOT NULL DEFAULT 0,
  created_at_ms INTEGER NOT NULL,
  FOREIGN KEY (alert_id) REFERENCES raw_alerts(alert_id)
);
CREATE TABLE IF NOT EXISTS cases (
  case_id TEXT PRIMARY KEY,
  correlation_key TEXT NOT NULL DEFAULT '',
  product TEXT NOT NULL,
  status TEXT NOT NULL,
  severity TEXT NOT NULL,
  classification TEXT NOT NULL,
  confidence REAL NOT NULL,
  summary TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  last_alert_at_ms INTEGER NOT NULL DEFAULT 0,
  closed_at_ms INTEGER
);
CREATE TABLE IF NOT EXISTS agent_runs (
  run_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  event_id TEXT NOT NULL DEFAULT '',
  agent TEXT NOT NULL,
  product TEXT NOT NULL,
  prompt_version TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  FOREIGN KEY (case_id) REFERENCES cases(case_id)
);
CREATE TABLE IF NOT EXISTS case_alert_links (
  case_id TEXT NOT NULL,
  alert_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (case_id, alert_id, event_id),
  FOREIGN KEY (case_id) REFERENCES cases(case_id),
  FOREIGN KEY (alert_id) REFERENCES raw_alerts(alert_id),
  FOREIGN KEY (event_id) REFERENCES normalized_events(event_id)
);
CREATE TABLE IF NOT EXISTS memory_entries (
  memory_id TEXT PRIMARY KEY,
  layer TEXT NOT NULL DEFAULT 'product_long_term',
  namespace TEXT NOT NULL,
  retrieval_key TEXT NOT NULL DEFAULT '',
  content TEXT NOT NULL,
  source_case_id TEXT NOT NULL DEFAULT '',
  scope TEXT NOT NULL DEFAULT '',
  trust_level TEXT NOT NULL DEFAULT 'low',
  status TEXT NOT NULL DEFAULT 'active',
  sensitivity_ok INTEGER NOT NULL DEFAULT 1,
  approved_by TEXT,
  expires_at_ms INTEGER,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL DEFAULT 0,
  CHECK (layer IN ('case_short_term','product_long_term','asset_profile','org_knowledge','evidence'))
);
CREATE TABLE IF NOT EXISTS memory_events (
  event_id TEXT PRIMARY KEY,
  memory_id TEXT NOT NULL,
  layer TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS memory_matches (
  match_id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL,
  alert_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  analysis_run_id TEXT NOT NULL,
  memory_id TEXT NOT NULL,
  matcher_version TEXT NOT NULL,
  rank INTEGER NOT NULL,
  structured_score REAL NOT NULL,
  semantic_score REAL NOT NULL,
  retrieval_score REAL NOT NULL,
  overall_score REAL NOT NULL,
  decision TEXT NOT NULL,
  final_effect TEXT NOT NULL,
  matched_features_json TEXT NOT NULL,
  score_breakdown_json TEXT NOT NULL,
  match_level TEXT NOT NULL DEFAULT 'weak',
  title_eligible INTEGER NOT NULL DEFAULT 0,
  comparison_json TEXT NOT NULL DEFAULT '{}',
  apply_threshold REAL NOT NULL DEFAULT 1.0,
  policy_effect TEXT NOT NULL DEFAULT 'review_only',
  selected_candidate INTEGER NOT NULL DEFAULT 0,
  attack_signal_veto INTEGER NOT NULL DEFAULT 0,
  attack_signal_reasons_json TEXT NOT NULL DEFAULT '[]',
  config_snapshot_json TEXT NOT NULL DEFAULT '{}',
  created_at_ms INTEGER NOT NULL,
  UNIQUE (analysis_run_id, memory_id)
);
CREATE TABLE IF NOT EXISTS audit_log (
  audit_id TEXT PRIMARY KEY,
  trace_id TEXT NOT NULL,
  case_id TEXT NOT NULL DEFAULT '',
  memory_id TEXT NOT NULL DEFAULT '',
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS mapping_profiles (
  profile_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  profile_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS validation_runs (
  validation_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  validator TEXT NOT NULL,
  validator_version TEXT NOT NULL,
  status TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  FOREIGN KEY (case_id) REFERENCES cases(case_id),
  FOREIGN KEY (event_id) REFERENCES normalized_events(event_id),
  CHECK (status IN ('passed','review','blocked'))
);
CREATE TABLE IF NOT EXISTS validation_review_resolutions (
  resolution_id TEXT PRIMARY KEY,
  validation_id TEXT NOT NULL UNIQUE,
  case_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  decision TEXT NOT NULL,
  actor TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  CHECK (decision = 'continue')
);
CREATE TABLE IF NOT EXISTS action_approvals (
  approval_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  validation_id TEXT NOT NULL DEFAULT '',
  review_resolution_id TEXT NOT NULL DEFAULT '',
  action_json TEXT NOT NULL,
  status TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  decided_by TEXT NOT NULL DEFAULT '',
  decision_reason TEXT NOT NULL DEFAULT '',
  execution_status TEXT NOT NULL DEFAULT 'not_executed',
  required_approvals INTEGER NOT NULL DEFAULT 1,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  FOREIGN KEY (case_id) REFERENCES cases(case_id),
  FOREIGN KEY (event_id) REFERENCES normalized_events(event_id),
  CHECK (status IN ('pending','approved','rejected','cancelled')),
  CHECK (required_approvals BETWEEN 1 AND 5),
  CHECK (execution_status = 'not_executed')
);
CREATE TABLE IF NOT EXISTS approval_votes (
  approval_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  decision TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (approval_id, actor),
  FOREIGN KEY (approval_id) REFERENCES action_approvals(approval_id) ON DELETE CASCADE,
  CHECK (decision IN ('approved','rejected','cancelled'))
);
CREATE TABLE IF NOT EXISTS response_connectors (
  connector_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  connector_type TEXT NOT NULL DEFAULT 'generic_webhook',
  endpoint TEXT NOT NULL,
  secret_env TEXT NOT NULL DEFAULT '',
  execution_mode TEXT NOT NULL DEFAULT 'shadow',
  enabled INTEGER NOT NULL DEFAULT 0,
  max_ttl_seconds INTEGER NOT NULL DEFAULT 3600,
  timeout_seconds INTEGER NOT NULL DEFAULT 10,
  health_status TEXT NOT NULL DEFAULT 'untested',
  last_error TEXT NOT NULL DEFAULT '',
  last_test_at_ms INTEGER,
  version INTEGER NOT NULL DEFAULT 1,
  created_by TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  CHECK (connector_type = 'generic_webhook'),
  CHECK (execution_mode IN ('shadow','manual','auto')),
  CHECK (enabled IN (0,1)),
  CHECK (health_status IN ('untested','healthy','error'))
);
CREATE TABLE IF NOT EXISTS response_policy (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  enabled INTEGER NOT NULL DEFAULT 0,
  default_ttl_seconds INTEGER NOT NULL DEFAULT 1800,
  max_ttl_seconds INTEGER NOT NULL DEFAULT 86400,
  protected_cidrs_json TEXT NOT NULL DEFAULT '[]',
  updated_by TEXT NOT NULL DEFAULT 'system',
  updated_at_ms INTEGER NOT NULL DEFAULT 0,
  CHECK (enabled IN (0,1))
);
INSERT OR IGNORE INTO response_policy(
  singleton, enabled, default_ttl_seconds, max_ttl_seconds,
  protected_cidrs_json, updated_by, updated_at_ms
) VALUES (1, 0, 1800, 86400, '[]', 'system', 0);
CREATE TABLE IF NOT EXISTS response_tasks (
  task_id TEXT PRIMARY KEY,
  approval_id TEXT NOT NULL UNIQUE,
  case_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  action_type TEXT NOT NULL,
  action_json TEXT NOT NULL,
  connector_id TEXT,
  connector_version INTEGER NOT NULL DEFAULT 0,
  connector_snapshot_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  available_at_ms INTEGER NOT NULL,
  claimed_at_ms INTEGER,
  remote_rule_id TEXT NOT NULL DEFAULT '',
  last_error TEXT NOT NULL DEFAULT '',
  verified_at_ms INTEGER,
  expires_at_ms INTEGER,
  created_by TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  FOREIGN KEY (approval_id) REFERENCES action_approvals(approval_id),
  FOREIGN KEY (case_id) REFERENCES cases(case_id),
  FOREIGN KEY (event_id) REFERENCES normalized_events(event_id),
  FOREIGN KEY (connector_id) REFERENCES response_connectors(connector_id),
  CHECK (action_type = 'network.block_ip'),
  CHECK (status IN (
    'waiting_configuration','waiting_dispatch','paused','queued','running',
    'retry_wait','verified','shadowed','failed','cancelled',
    'rollback_queued','rollback_running','rollback_retry','rolled_back','rollback_failed'
  ))
);
CREATE TABLE IF NOT EXISTS response_attempts (
  attempt_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  attempt_no INTEGER NOT NULL,
  request_hash TEXT NOT NULL DEFAULT '',
  http_status INTEGER,
  outcome TEXT NOT NULL,
  response_excerpt TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL,
  FOREIGN KEY (task_id) REFERENCES response_tasks(task_id) ON DELETE CASCADE,
  CHECK (operation IN ('health_check','apply','verify','rollback'))
);
CREATE TABLE IF NOT EXISTS case_response_artifacts (
  artifact_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  artifact_type TEXT NOT NULL DEFAULT 'response_pack',
  version INTEGER NOT NULL,
  schema_version TEXT NOT NULL,
  source_snapshot_hash TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  content_json TEXT NOT NULL,
  validation_status TEXT NOT NULL,
  validation_json TEXT NOT NULL,
  generator TEXT NOT NULL,
  model_metadata_json TEXT NOT NULL DEFAULT '{}',
  created_by TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  FOREIGN KEY (case_id) REFERENCES cases(case_id),
  UNIQUE (case_id, version),
  UNIQUE (case_id, source_snapshot_hash, content_hash),
  CHECK (artifact_type = 'response_pack'),
  CHECK (validation_status IN ('passed','review','blocked'))
);
CREATE TABLE IF NOT EXISTS case_response_artifact_refs (
  artifact_id TEXT NOT NULL,
  claim_scope TEXT NOT NULL,
  ref_type TEXT NOT NULL,
  ref_id TEXT NOT NULL,
  source_event_id TEXT NOT NULL DEFAULT '',
  source_hash TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (artifact_id, claim_scope, ref_type, ref_id, source_event_id),
  FOREIGN KEY (artifact_id) REFERENCES case_response_artifacts(artifact_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS response_agent_sessions (
  session_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  source_snapshot_hash TEXT NOT NULL,
  source_json TEXT NOT NULL,
  goal TEXT NOT NULL,
  status TEXT NOT NULL,
  plan_json TEXT NOT NULL DEFAULT '[]',
  budget_json TEXT NOT NULL DEFAULT '{}',
  usage_json TEXT NOT NULL DEFAULT '{}',
  model_metadata_json TEXT NOT NULL DEFAULT '{}',
  report_id TEXT,
  last_error TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  claimed_at_ms INTEGER,
  completed_at_ms INTEGER,
  FOREIGN KEY (case_id) REFERENCES cases(case_id),
  FOREIGN KEY (artifact_id) REFERENCES case_response_artifacts(artifact_id),
  CHECK (status IN (
    'queued','running','waiting_input','paused','synthesizing','validating',
    'completed','review','blocked','failed','cancelled','budget_exhausted'
  ))
);
CREATE TABLE IF NOT EXISTS response_agent_steps (
  step_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  phase TEXT NOT NULL,
  status TEXT NOT NULL,
  title TEXT NOT NULL,
  rationale TEXT NOT NULL DEFAULT '',
  detail_json TEXT NOT NULL DEFAULT '{}',
  evidence_refs_json TEXT NOT NULL DEFAULT '[]',
  created_at_ms INTEGER NOT NULL,
  completed_at_ms INTEGER,
  FOREIGN KEY (session_id) REFERENCES response_agent_sessions(session_id) ON DELETE CASCADE,
  UNIQUE (session_id, sequence)
);
CREATE TABLE IF NOT EXISTS response_agent_tool_calls (
  call_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  step_id TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  tool_version TEXT NOT NULL,
  arguments_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  result_json TEXT NOT NULL DEFAULT '{}',
  result_hash TEXT NOT NULL DEFAULT '',
  evidence_refs_json TEXT NOT NULL DEFAULT '[]',
  error TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL,
  completed_at_ms INTEGER,
  FOREIGN KEY (session_id) REFERENCES response_agent_sessions(session_id) ON DELETE CASCADE,
  FOREIGN KEY (step_id) REFERENCES response_agent_steps(step_id) ON DELETE CASCADE,
  CHECK (status IN ('running','completed','failed'))
);
CREATE TABLE IF NOT EXISTS response_agent_reports (
  report_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL UNIQUE,
  case_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  schema_version TEXT NOT NULL,
  source_snapshot_hash TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  content_json TEXT NOT NULL,
  validation_status TEXT NOT NULL,
  validation_json TEXT NOT NULL,
  model_metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at_ms INTEGER NOT NULL,
  FOREIGN KEY (session_id) REFERENCES response_agent_sessions(session_id) ON DELETE CASCADE,
  FOREIGN KEY (case_id) REFERENCES cases(case_id),
  UNIQUE (case_id, version),
  CHECK (validation_status IN ('passed','review','blocked'))
);
CREATE TABLE IF NOT EXISTS response_agent_report_refs (
  report_id TEXT NOT NULL,
  claim_id TEXT NOT NULL,
  ref_type TEXT NOT NULL,
  ref_id TEXT NOT NULL,
  source_event_id TEXT NOT NULL DEFAULT '',
  source_hash TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (report_id, claim_id, ref_type, ref_id, source_event_id),
  FOREIGN KEY (report_id) REFERENCES response_agent_reports(report_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS alert_dispositions (
  alert_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  disposition TEXT NOT NULL,
  actor TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  FOREIGN KEY (alert_id) REFERENCES raw_alerts(alert_id),
  FOREIGN KEY (case_id) REFERENCES cases(case_id),
  CHECK (disposition IN ('open','closed','false_positive'))
);
CREATE TABLE IF NOT EXISTS runtime_settings (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS durable_alert_inbox (
  alert_id TEXT PRIMARY KEY,
  raw_alert_json TEXT NOT NULL,
  source TEXT NOT NULL,
  product TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 2,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  available_at_ms INTEGER NOT NULL,
  claimed_at_ms INTEGER,
  completed_at_ms INTEGER,
  last_error TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  CHECK (status IN ('pending','processing','retry','deferred','completed','dead_letter'))
);
CREATE TABLE IF NOT EXISTS inbox_capacity_state (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  unfinished_count INTEGER NOT NULL DEFAULT 0,
  unfinished_bytes INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO inbox_capacity_state(singleton, unfinished_count, unfinished_bytes)
VALUES (1, 0, 0);
CREATE INDEX IF NOT EXISTS idx_normalized_alert ON normalized_events(alert_id);
CREATE INDEX IF NOT EXISTS idx_raw_alert_created
  ON raw_alerts(created_at_ms DESC, alert_id);
CREATE INDEX IF NOT EXISTS idx_raw_alert_product_created
  ON raw_alerts(product, created_at_ms DESC, alert_id);
CREATE INDEX IF NOT EXISTS idx_agent_runs_case ON agent_runs(case_id);
CREATE INDEX IF NOT EXISTS idx_agent_runs_case_created
  ON agent_runs(case_id, created_at_ms DESC, run_id);
CREATE INDEX IF NOT EXISTS idx_case_links_alert ON case_alert_links(alert_id);
CREATE INDEX IF NOT EXISTS idx_case_links_case ON case_alert_links(case_id);
CREATE INDEX IF NOT EXISTS idx_case_links_case_created ON case_alert_links(case_id, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_cases_status_created ON cases(status, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_cases_product_created ON cases(product, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_cases_severity_created ON cases(severity, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_memory_lookup ON memory_entries(layer, namespace, status);
CREATE INDEX IF NOT EXISTS idx_memory_lookup_created ON memory_entries(layer, namespace, status, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_memory_entries_created_id
  ON memory_entries(created_at_ms DESC, memory_id);
CREATE INDEX IF NOT EXISTS idx_memory_expiry ON memory_entries(status, expires_at_ms);
CREATE INDEX IF NOT EXISTS idx_memory_events_mem ON memory_events(memory_id);
CREATE INDEX IF NOT EXISTS idx_memory_events_created_id
  ON memory_events(created_at_ms DESC, event_id);
CREATE INDEX IF NOT EXISTS idx_memory_matches_event ON memory_matches(event_id, overall_score DESC);
CREATE INDEX IF NOT EXISTS idx_memory_matches_memory ON memory_matches(memory_id, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_memory_matches_case ON memory_matches(case_id, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_log(case_id, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_audit_memory ON audit_log(memory_id, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_validation_case ON validation_runs(case_id, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_validation_review_case ON validation_review_resolutions(case_id, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_approvals_case ON action_approvals(case_id, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON action_approvals(status, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_approval_votes_approval ON approval_votes(approval_id, created_at_ms ASC);
CREATE INDEX IF NOT EXISTS idx_response_tasks_status ON response_tasks(status, available_at_ms, created_at_ms);
CREATE INDEX IF NOT EXISTS idx_response_tasks_case ON response_tasks(case_id, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_response_tasks_created_id
  ON response_tasks(created_at_ms DESC, task_id);
CREATE INDEX IF NOT EXISTS idx_response_attempts_task ON response_attempts(task_id, created_at_ms ASC);
CREATE INDEX IF NOT EXISTS idx_case_response_artifacts_case
  ON case_response_artifacts(case_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_case_response_refs_ref
  ON case_response_artifact_refs(ref_type, ref_id);
CREATE INDEX IF NOT EXISTS idx_response_agent_sessions_case
  ON response_agent_sessions(case_id, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_response_agent_sessions_claim
  ON response_agent_sessions(status, created_at_ms ASC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_response_agent_one_active_case
  ON response_agent_sessions(case_id)
  WHERE status IN (
    'queued','running','waiting_input','paused','synthesizing','validating'
  );
CREATE INDEX IF NOT EXISTS idx_response_agent_steps_session
  ON response_agent_steps(session_id, sequence ASC);
CREATE INDEX IF NOT EXISTS idx_response_agent_tool_calls_session
  ON response_agent_tool_calls(session_id, created_at_ms ASC);
CREATE INDEX IF NOT EXISTS idx_response_agent_reports_case
  ON response_agent_reports(case_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_response_agent_report_refs_ref
  ON response_agent_report_refs(ref_type, ref_id);
CREATE INDEX IF NOT EXISTS idx_alert_dispositions_case ON alert_dispositions(case_id, updated_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_inbox_claim ON durable_alert_inbox(status, available_at_ms, created_at_ms);
CREATE INDEX IF NOT EXISTS idx_inbox_status_created ON durable_alert_inbox(status, created_at_ms);
CREATE TRIGGER IF NOT EXISTS trg_inbox_capacity_insert
AFTER INSERT ON durable_alert_inbox
WHEN NEW.status IN ('pending','retry','deferred','processing')
BEGIN
  UPDATE inbox_capacity_state
  SET unfinished_count = unfinished_count + 1,
      unfinished_bytes = unfinished_bytes + length(CAST(NEW.raw_alert_json AS BLOB))
  WHERE singleton = 1;
END;
CREATE TRIGGER IF NOT EXISTS trg_inbox_capacity_update
AFTER UPDATE OF status, raw_alert_json ON durable_alert_inbox
BEGIN
  UPDATE inbox_capacity_state
  SET unfinished_count = unfinished_count
        - CASE WHEN OLD.status IN ('pending','retry','deferred','processing') THEN 1 ELSE 0 END
        + CASE WHEN NEW.status IN ('pending','retry','deferred','processing') THEN 1 ELSE 0 END,
      unfinished_bytes = unfinished_bytes
        - CASE WHEN OLD.status IN ('pending','retry','deferred','processing')
               THEN length(CAST(OLD.raw_alert_json AS BLOB)) ELSE 0 END
        + CASE WHEN NEW.status IN ('pending','retry','deferred','processing')
               THEN length(CAST(NEW.raw_alert_json AS BLOB)) ELSE 0 END
  WHERE singleton = 1;
END;
CREATE TRIGGER IF NOT EXISTS trg_inbox_capacity_delete
AFTER DELETE ON durable_alert_inbox
WHEN OLD.status IN ('pending','retry','deferred','processing')
BEGIN
  UPDATE inbox_capacity_state
  SET unfinished_count = MAX(0, unfinished_count - 1),
      unfinished_bytes = MAX(
        0,
        unfinished_bytes - length(CAST(OLD.raw_alert_json AS BLOB))
      )
  WHERE singleton = 1;
END;
"""

SCHEMA_VERSION = 19
_LLM_DEFERRED_ERROR_PREFIX = "analysis_deferred:"
_LEGACY_LLM_DEFERRED_ERROR_FRAGMENT = "remote LLM analysis deferred"
_TERMINAL_LLM_ERROR_FRAGMENTS = (
    "LLMEndpointConfigurationError",
    "LLMResponseContractError",
)


class AlertIdentityConflict(ValueError):
    """An alert ID was reused for a different source event."""

    def __init__(self, alert_id: str):
        self.alert_id = str(alert_id)
        super().__init__(
            f"alert_id collision: {self.alert_id} is already bound to different alert evidence; "
            "use a new alert_id for a new alert occurrence"
        )


class Repository:
    def __init__(self, db_path: str):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # A single shared connection guarded by ``_lock``. ``check_same_thread=False``
        # only silences the thread-affinity guard; concurrent use of one connection
        # is made safe by serializing every access through ``_lock`` (and the
        # ``transaction()`` context manager). This keeps the stdlib-only, single-file
        # SQLite MVP honest under ``ThreadingHTTPServer`` without a connection pool.
        self._lock = threading.RLock()
        self._tx_state = threading.local()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self._migrate()

    # ---- concurrency / transactions ---------------------------------------

    @property
    def lock(self) -> threading.RLock:
        """Expose the serializing lock so callers can compose multi-step ops."""
        return self._lock

    def transaction(self):
        """Context manager yielding a transactional connection.

        All writes performed inside the block commit atomically on clean exit and
        roll back on any exception. Methods that accept ``_commit=False`` skip
        their own ``commit()`` so they can participate in an outer transaction.
        Reentrant on the same thread: nested ``transaction()`` blocks share the
        outer transaction and only the outermost commits/rolls back.
        """
        return _Transaction(self)

    def _tx_depth(self) -> int:
        return getattr(self._tx_state, "depth", 0)

    def _migrate(self) -> None:
        with self._lock:
            # Determine current version (0 = pre-versioning legacy DB).
            row = self.conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
            current = int((row["v"] if row else 0) or 0)

            if current < 1:
                # v1: legacy column backfills from the original hand-rolled migration.
                norm_columns = {
                    row["name"]
                    for row in self.conn.execute("PRAGMA table_info(normalized_events)").fetchall()
                }
                if "source" not in norm_columns:
                    self.conn.execute("ALTER TABLE normalized_events ADD COLUMN source TEXT NOT NULL DEFAULT 'unknown'")
                mem_columns = {row["name"] for row in self.conn.execute("PRAGMA table_info(memory_entries)").fetchall()}
                additions = {
                    "layer": "TEXT NOT NULL DEFAULT 'product_long_term'",
                    "retrieval_key": "TEXT NOT NULL DEFAULT ''",
                    "scope": "TEXT NOT NULL DEFAULT ''",
                    "status": "TEXT NOT NULL DEFAULT 'active'",
                    "sensitivity_ok": "INTEGER NOT NULL DEFAULT 1",
                    "approved_by": "TEXT",
                    "updated_at_ms": "INTEGER NOT NULL DEFAULT 0",
                }
                for col, decl in additions.items():
                    if col not in mem_columns:
                        self.conn.execute(f"ALTER TABLE memory_entries ADD COLUMN {col} {decl}")
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (1, ?)",
                    (now_ms(),),
                )

            if current < 2:
                # v2: immutable-evidence support — add evidence_hash if missing.
                norm_columns = {
                    row["name"]
                    for row in self.conn.execute("PRAGMA table_info(normalized_events)").fetchall()
                }
                if "evidence_hash" not in norm_columns:
                    self.conn.execute("ALTER TABLE normalized_events ADD COLUMN evidence_hash TEXT NOT NULL DEFAULT ''")
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (2, ?)",
                    (now_ms(),),
                )

            if current < 3:
                # v3: case disposition remains in the existing cases.status field.
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (3, ?)",
                    (now_ms(),),
                )

            if current < 4:
                # v4: durable idempotency for alert retries plus indexes for the
                # high-volume case list and layered-memory retrieval paths.
                run_columns = {
                    row["name"]
                    for row in self.conn.execute("PRAGMA table_info(agent_runs)").fetchall()
                }
                if "event_id" not in run_columns:
                    self.conn.execute("ALTER TABLE agent_runs ADD COLUMN event_id TEXT NOT NULL DEFAULT ''")
                self.conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_runs_event ON agent_runs(event_id)")
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_case_links_case_created "
                    "ON case_alert_links(case_id, created_at_ms DESC)"
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_memory_lookup_created "
                    "ON memory_entries(layer, namespace, status, created_at_ms DESC)"
                )
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (4, ?)",
                    (now_ms(),),
                )

            if current < 5:
                # v5 tables are created by SCHEMA for both new and existing DBs.
                # Record the migration only after verifying their required safety
                # columns exist, so a partial upgrade cannot be reported healthy.
                approval_columns = {
                    row["name"] for row in self.conn.execute("PRAGMA table_info(action_approvals)").fetchall()
                }
                required = {"approval_id", "status", "execution_status", "action_json"}
                if not required.issubset(approval_columns):
                    raise RuntimeError("action_approvals schema is incomplete")
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (5, ?)",
                    (now_ms(),),
                )

            if current < 6:
                # v6: durable alert-to-memory association scores. The table and
                # indexes are created by SCHEMA before migrations run.
                match_columns = {
                    row["name"] for row in self.conn.execute("PRAGMA table_info(memory_matches)").fetchall()
                }
                required = {
                    "match_id", "event_id", "memory_id", "matcher_version", "overall_score",
                    "decision", "final_effect", "score_breakdown_json",
                }
                if not required.issubset(match_columns):
                    raise RuntimeError("memory_matches schema is incomplete")
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (6, ?)",
                    (now_ms(),),
                )

            if current < 7:
                # v7: production operations foundations. Existing Case identifiers
                # stay valid; correlation metadata is backfilled so only new alerts
                # are subject to time-window/terminal-case rollover.
                case_columns = {
                    row["name"] for row in self.conn.execute("PRAGMA table_info(cases)").fetchall()
                }
                case_additions = {
                    "correlation_key": "TEXT NOT NULL DEFAULT ''",
                    "last_alert_at_ms": "INTEGER NOT NULL DEFAULT 0",
                    "closed_at_ms": "INTEGER",
                }
                for column, declaration in case_additions.items():
                    if column not in case_columns:
                        self.conn.execute(f"ALTER TABLE cases ADD COLUMN {column} {declaration}")
                self.conn.execute(
                    "UPDATE cases SET correlation_key = case_id WHERE correlation_key = ''"
                )
                self.conn.execute(
                    "UPDATE cases SET last_alert_at_ms = updated_at_ms WHERE last_alert_at_ms = 0"
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_cases_correlation "
                    "ON cases(correlation_key, last_alert_at_ms DESC)"
                )
                required_tables = {
                    "alert_dispositions",
                    "runtime_settings",
                    "durable_alert_inbox",
                }
                actual_tables = {
                    row["name"]
                    for row in self.conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
                if not required_tables.issubset(actual_tables):
                    raise RuntimeError("schema v7 operational tables are incomplete")
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (7, ?)",
                    (now_ms(),),
                )

            if current < 8:
                approval_columns = {
                    row["name"]
                    for row in self.conn.execute("PRAGMA table_info(action_approvals)").fetchall()
                }
                if "required_approvals" not in approval_columns:
                    self.conn.execute(
                        "ALTER TABLE action_approvals "
                        "ADD COLUMN required_approvals INTEGER NOT NULL DEFAULT 1"
                    )
                vote_table = self.conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'approval_votes'"
                ).fetchone()
                if not vote_table:
                    raise RuntimeError("schema v8 approval_votes table is missing")
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (8, ?)",
                    (now_ms(),),
                )

            if current < 9:
                # v9 makes governance history independent from raw operational
                # retention. Memory-match rows keep immutable identifiers/scores
                # after their Case/event payloads are removed, so their FKs must
                # not silently extend the raw-data retention window.
                if self.conn.execute("PRAGMA foreign_key_list(memory_matches)").fetchall():
                    self.conn.execute("DROP INDEX IF EXISTS idx_memory_matches_event")
                    self.conn.execute("DROP INDEX IF EXISTS idx_memory_matches_memory")
                    self.conn.execute("DROP INDEX IF EXISTS idx_memory_matches_case")
                    self.conn.execute("ALTER TABLE memory_matches RENAME TO memory_matches_v8")
                    self.conn.execute(
                        """
                        CREATE TABLE memory_matches (
                          match_id TEXT PRIMARY KEY,
                          event_id TEXT NOT NULL,
                          alert_id TEXT NOT NULL,
                          case_id TEXT NOT NULL,
                          analysis_run_id TEXT NOT NULL,
                          memory_id TEXT NOT NULL,
                          matcher_version TEXT NOT NULL,
                          rank INTEGER NOT NULL,
                          structured_score REAL NOT NULL,
                          semantic_score REAL NOT NULL,
                          retrieval_score REAL NOT NULL,
                          overall_score REAL NOT NULL,
                          decision TEXT NOT NULL,
                          final_effect TEXT NOT NULL,
                          matched_features_json TEXT NOT NULL,
                          score_breakdown_json TEXT NOT NULL,
                          created_at_ms INTEGER NOT NULL,
                          UNIQUE (event_id, memory_id)
                        )
                        """
                    )
                    self.conn.execute(
                        """
                        INSERT INTO memory_matches
                        SELECT match_id, event_id, alert_id, case_id, analysis_run_id,
                               memory_id, matcher_version, rank, structured_score,
                               semantic_score, retrieval_score, overall_score,
                               decision, final_effect, matched_features_json,
                               score_breakdown_json, created_at_ms
                        FROM memory_matches_v8
                        """
                    )
                    self.conn.execute("DROP TABLE memory_matches_v8")
                    self.conn.execute(
                        "CREATE INDEX idx_memory_matches_event "
                        "ON memory_matches(event_id, overall_score DESC)"
                    )
                    self.conn.execute(
                        "CREATE INDEX idx_memory_matches_memory "
                        "ON memory_matches(memory_id, created_at_ms DESC)"
                    )
                    self.conn.execute(
                        "CREATE INDEX idx_memory_matches_case "
                        "ON memory_matches(case_id, created_at_ms DESC)"
                    )

                audit_columns = {
                    row["name"]
                    for row in self.conn.execute("PRAGMA table_info(audit_log)").fetchall()
                }
                if "case_id" not in audit_columns:
                    self.conn.execute(
                        "ALTER TABLE audit_log ADD COLUMN case_id TEXT NOT NULL DEFAULT ''"
                    )
                if "memory_id" not in audit_columns:
                    self.conn.execute(
                        "ALTER TABLE audit_log ADD COLUMN memory_id TEXT NOT NULL DEFAULT ''"
                    )

                # Backfill legacy randomized traces from their structured detail,
                # then propagate that link to every audit row sharing the trace.
                legacy_rows = self.conn.execute(
                    "SELECT audit_id, trace_id, detail_json FROM audit_log"
                ).fetchall()
                trace_cases: dict[str, str] = {}
                trace_memories: dict[str, str] = {}
                parsed_links: dict[str, tuple[str, str]] = {}
                for row in legacy_rows:
                    try:
                        detail = json.loads(row["detail_json"] or "{}")
                    except (TypeError, json.JSONDecodeError):
                        detail = {}
                    case_id = str(detail.get("case_id") or "") if isinstance(detail, dict) else ""
                    memory_id = str(detail.get("memory_id") or "") if isinstance(detail, dict) else ""
                    parsed_links[str(row["audit_id"])] = (case_id, memory_id)
                    if case_id:
                        trace_cases[str(row["trace_id"])] = case_id
                    if memory_id:
                        trace_memories[str(row["trace_id"])] = memory_id
                for row in legacy_rows:
                    trace_id = str(row["trace_id"])
                    case_id, memory_id = parsed_links[str(row["audit_id"])]
                    case_id = case_id or trace_cases.get(trace_id, "")
                    memory_id = memory_id or trace_memories.get(trace_id, "")
                    if not case_id and self.conn.execute(
                        "SELECT 1 FROM cases WHERE case_id = ?", (trace_id,)
                    ).fetchone():
                        case_id = trace_id
                    if not memory_id and self.conn.execute(
                        "SELECT 1 FROM memory_entries WHERE memory_id = ?", (trace_id,)
                    ).fetchone():
                        memory_id = trace_id
                    self.conn.execute(
                        "UPDATE audit_log SET case_id = ?, memory_id = ? WHERE audit_id = ?",
                        (case_id, memory_id, row["audit_id"]),
                    )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_audit_case "
                    "ON audit_log(case_id, created_at_ms DESC)"
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_audit_memory "
                    "ON audit_log(memory_id, created_at_ms DESC)"
                )
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (9, ?)",
                    (now_ms(),),
                )

            if current < 10:
                # v10 stores normalized event time separately from insertion
                # time. Cross-product correlation can then bound candidates by
                # the actual event window before applying its defensive limit.
                norm_columns = {
                    row["name"]
                    for row in self.conn.execute("PRAGMA table_info(normalized_events)").fetchall()
                }
                if "event_at_ms" not in norm_columns:
                    self.conn.execute(
                        "ALTER TABLE normalized_events "
                        "ADD COLUMN event_at_ms INTEGER NOT NULL DEFAULT 0"
                    )
                legacy_rows = self.conn.execute(
                    "SELECT event_id, timestamp FROM normalized_events WHERE event_at_ms <= 0"
                ).fetchall()
                self.conn.executemany(
                    "UPDATE normalized_events SET event_at_ms = ? WHERE event_id = ?",
                    [
                        (self.timestamp_ms(str(row["timestamp"])), str(row["event_id"]))
                        for row in legacy_rows
                    ],
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_normalized_event_time "
                    "ON normalized_events(event_at_ms DESC, product)"
                )
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (10, ?)",
                    (now_ms(),),
                )

            if current < 11:
                # v11 adds an append-only human decision for the narrow
                # prompt-injection review continuation path. The original
                # validation stays ``review``; approvals can prove their
                # explicit review provenance through these columns.
                approval_columns = {
                    row["name"]
                    for row in self.conn.execute("PRAGMA table_info(action_approvals)").fetchall()
                }
                additions = {
                    "validation_id": "TEXT NOT NULL DEFAULT ''",
                    "review_resolution_id": "TEXT NOT NULL DEFAULT ''",
                }
                for column, declaration in additions.items():
                    if column not in approval_columns:
                        self.conn.execute(
                            f"ALTER TABLE action_approvals ADD COLUMN {column} {declaration}"
                        )
                resolution_table = self.conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'validation_review_resolutions'"
                ).fetchone()
                if not resolution_table:
                    raise RuntimeError("schema v11 validation review resolutions table is missing")
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_validation_review_case "
                    "ON validation_review_resolutions(case_id, created_at_ms DESC)"
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_approvals_review_resolution "
                    "ON action_approvals(review_resolution_id, created_at_ms DESC)"
                )
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (11, ?)",
                    (now_ms(),),
                )

            if current < 12:
                # v12 separates remote-model deferrals from ordinary retryable
                # processing failures.  The dispatcher must never reclaim a
                # deferred alert on its normal polling loop: maintenance or an
                # analyst explicitly releases it once model recovery is due.
                # SQLite cannot alter a CHECK constraint in place, so rebuild
                # the small inbox table atomically while preserving every row.
                inbox_row = self.conn.execute(
                    "SELECT sql FROM sqlite_master WHERE type = 'table' "
                    "AND name = 'durable_alert_inbox'"
                ).fetchone()
                inbox_sql = str((inbox_row["sql"] if inbox_row else "") or "").lower()
                if "'deferred'" not in inbox_sql:
                    self.conn.execute("DROP INDEX IF EXISTS idx_inbox_claim")
                    self.conn.execute(
                        "ALTER TABLE durable_alert_inbox RENAME TO durable_alert_inbox_v11"
                    )
                    self.conn.execute(
                        """
                        CREATE TABLE durable_alert_inbox (
                          alert_id TEXT PRIMARY KEY,
                          raw_alert_json TEXT NOT NULL,
                          source TEXT NOT NULL,
                          product TEXT NOT NULL,
                          status TEXT NOT NULL DEFAULT 'pending',
                          attempts INTEGER NOT NULL DEFAULT 0,
                          max_attempts INTEGER NOT NULL DEFAULT 5,
                          available_at_ms INTEGER NOT NULL,
                          claimed_at_ms INTEGER,
                          completed_at_ms INTEGER,
                          last_error TEXT NOT NULL DEFAULT '',
                          created_at_ms INTEGER NOT NULL,
                          updated_at_ms INTEGER NOT NULL,
                          CHECK (status IN ('pending','processing','retry','deferred','completed','dead_letter'))
                        )
                        """
                    )
                    self.conn.execute(
                        """
                        INSERT INTO durable_alert_inbox
                        (alert_id, raw_alert_json, source, product, status, attempts, max_attempts,
                         available_at_ms, claimed_at_ms, completed_at_ms, last_error,
                         created_at_ms, updated_at_ms)
                        SELECT alert_id, raw_alert_json, source, product,
                               CASE
                                 WHEN status = 'retry'
                                      AND (last_error LIKE ? OR last_error LIKE ?)
                                   THEN 'deferred'
                                 ELSE status
                               END,
                               attempts, max_attempts, available_at_ms, claimed_at_ms,
                               completed_at_ms, last_error, created_at_ms, updated_at_ms
                        FROM durable_alert_inbox_v11
                        """,
                        (
                            f"{_LLM_DEFERRED_ERROR_PREFIX}%",
                            f"%{_LEGACY_LLM_DEFERRED_ERROR_FRAGMENT}%",
                        ),
                    )
                    self.conn.execute("DROP TABLE durable_alert_inbox_v11")
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_inbox_claim "
                    "ON durable_alert_inbox(status, available_at_ms, created_at_ms)"
                )
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (12, ?)",
                    (now_ms(),),
                )

            if current < 13:
                # v13 adds priority/fair dispatch and constant-time byte/count
                # admission accounting. Recreate triggers because the v12 table
                # rebuild may have removed triggers created by the base schema.
                inbox_columns = {
                    row["name"]
                    for row in self.conn.execute(
                        "PRAGMA table_info(durable_alert_inbox)"
                    ).fetchall()
                }
                if "priority" not in inbox_columns:
                    self.conn.execute(
                        "ALTER TABLE durable_alert_inbox "
                        "ADD COLUMN priority INTEGER NOT NULL DEFAULT 2"
                    )
                priority_rows = self.conn.execute(
                    "SELECT alert_id, raw_alert_json FROM durable_alert_inbox"
                ).fetchall()
                for inbox_row in priority_rows:
                    try:
                        raw_alert = json.loads(inbox_row["raw_alert_json"] or "{}")
                    except (TypeError, json.JSONDecodeError):
                        raw_alert = {}
                    severity = str(raw_alert.get("severity") or "medium").lower()
                    priority = {"critical": 0, "high": 1, "medium": 2}.get(severity, 3)
                    self.conn.execute(
                        "UPDATE durable_alert_inbox SET priority = ? WHERE alert_id = ?",
                        (priority, inbox_row["alert_id"]),
                    )
                self.conn.execute("DROP INDEX IF EXISTS idx_inbox_claim")
                self.conn.execute(
                    "CREATE INDEX idx_inbox_claim ON durable_alert_inbox"
                    "(status, priority, available_at_ms, created_at_ms)"
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_inbox_status_created "
                    "ON durable_alert_inbox(status, created_at_ms)"
                )
                self.conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS inbox_capacity_state (
                      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                      unfinished_count INTEGER NOT NULL DEFAULT 0,
                      unfinished_bytes INTEGER NOT NULL DEFAULT 0
                    );
                    INSERT OR IGNORE INTO inbox_capacity_state
                      (singleton, unfinished_count, unfinished_bytes)
                    VALUES (1, 0, 0);
                    DROP TRIGGER IF EXISTS trg_inbox_capacity_insert;
                    DROP TRIGGER IF EXISTS trg_inbox_capacity_update;
                    DROP TRIGGER IF EXISTS trg_inbox_capacity_delete;
                    CREATE TRIGGER trg_inbox_capacity_insert
                    AFTER INSERT ON durable_alert_inbox
                    WHEN NEW.status IN ('pending','retry','deferred','processing')
                    BEGIN
                      UPDATE inbox_capacity_state
                      SET unfinished_count = unfinished_count + 1,
                          unfinished_bytes = unfinished_bytes
                            + length(CAST(NEW.raw_alert_json AS BLOB))
                      WHERE singleton = 1;
                    END;
                    CREATE TRIGGER trg_inbox_capacity_update
                    AFTER UPDATE OF status, raw_alert_json ON durable_alert_inbox
                    BEGIN
                      UPDATE inbox_capacity_state
                      SET unfinished_count = unfinished_count
                            - CASE WHEN OLD.status IN ('pending','retry','deferred','processing') THEN 1 ELSE 0 END
                            + CASE WHEN NEW.status IN ('pending','retry','deferred','processing') THEN 1 ELSE 0 END,
                          unfinished_bytes = unfinished_bytes
                            - CASE WHEN OLD.status IN ('pending','retry','deferred','processing')
                                   THEN length(CAST(OLD.raw_alert_json AS BLOB)) ELSE 0 END
                            + CASE WHEN NEW.status IN ('pending','retry','deferred','processing')
                                   THEN length(CAST(NEW.raw_alert_json AS BLOB)) ELSE 0 END
                      WHERE singleton = 1;
                    END;
                    CREATE TRIGGER trg_inbox_capacity_delete
                    AFTER DELETE ON durable_alert_inbox
                    WHEN OLD.status IN ('pending','retry','deferred','processing')
                    BEGIN
                      UPDATE inbox_capacity_state
                      SET unfinished_count = MAX(0, unfinished_count - 1),
                          unfinished_bytes = MAX(
                            0,
                            unfinished_bytes - length(CAST(OLD.raw_alert_json AS BLOB))
                          )
                      WHERE singleton = 1;
                    END;
                    """
                )
                self.conn.execute(
                    """
                    UPDATE inbox_capacity_state
                    SET unfinished_count = (
                          SELECT COUNT(*) FROM durable_alert_inbox
                          WHERE status IN ('pending','retry','deferred','processing')
                        ),
                        unfinished_bytes = COALESCE((
                          SELECT SUM(length(CAST(raw_alert_json AS BLOB)))
                          FROM durable_alert_inbox
                          WHERE status IN ('pending','retry','deferred','processing')
                        ), 0)
                    WHERE singleton = 1
                    """
                )
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (13, ?)",
                    (now_ms(),),
                )

            if current < 14:
                # v14 keeps the queue's time/status/product/severity searches on
                # ordered indexes as the Case history grows.
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_cases_created "
                    "ON cases(created_at_ms DESC)"
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_cases_status_created "
                    "ON cases(status, created_at_ms DESC)"
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_cases_product_created "
                    "ON cases(product, created_at_ms DESC)"
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_cases_severity_created "
                    "ON cases(severity, created_at_ms DESC)"
                )
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (14, ?)",
                    (now_ms(),),
                )

            if current < 15:
                required_tables = {
                    "response_connectors",
                    "response_policy",
                    "response_tasks",
                    "response_attempts",
                }
                actual_tables = {
                    row["name"]
                    for row in self.conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
                if not required_tables.issubset(actual_tables):
                    raise RuntimeError("schema v15 response automation tables are incomplete")
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (15, ?)",
                    (now_ms(),),
                )

            if current < 16:
                required_tables = {
                    "case_response_artifacts",
                    "case_response_artifact_refs",
                }
                actual_tables = {
                    row["name"]
                    for row in self.conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
                if not required_tables.issubset(actual_tables):
                    raise RuntimeError("schema v16 Case Response Pack tables are incomplete")
                response_required_columns = {
                    "response_connectors": {"connector_type", "endpoint"},
                    "response_policy": {"enabled"},
                    "response_tasks": {"status", "action_json"},
                    "response_attempts": {"operation"},
                }
                for table, required in response_required_columns.items():
                    columns = {
                        row["name"]
                        for row in self.conn.execute(
                            f"PRAGMA table_info({table})"
                        ).fetchall()
                    }
                    if not required.issubset(columns):
                        raise RuntimeError(
                            f"schema v15 response automation table is incomplete: {table}"
                        )
                artifact_columns = {
                    row["name"]
                    for row in self.conn.execute(
                        "PRAGMA table_info(case_response_artifacts)"
                    ).fetchall()
                }
                required_columns = {
                    "artifact_id",
                    "case_id",
                    "version",
                    "source_snapshot_hash",
                    "content_hash",
                    "content_json",
                    "validation_status",
                }
                if not required_columns.issubset(artifact_columns):
                    raise RuntimeError("schema v16 Case Response Pack columns are incomplete")
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_memory_entries_created_id "
                    "ON memory_entries(created_at_ms DESC, memory_id)"
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_memory_events_created_id "
                    "ON memory_events(created_at_ms DESC, event_id)"
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_response_tasks_created_id "
                    "ON response_tasks(created_at_ms DESC, task_id)"
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_agent_runs_case_created "
                    "ON agent_runs(case_id, created_at_ms DESC, run_id)"
                )
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (16, ?)",
                    (now_ms(),),
                )

            if current < 17:
                required_tables = {
                    "response_agent_sessions",
                    "response_agent_steps",
                    "response_agent_tool_calls",
                    "response_agent_reports",
                    "response_agent_report_refs",
                }
                actual_tables = {
                    row["name"]
                    for row in self.conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
                if not required_tables.issubset(actual_tables):
                    raise RuntimeError("schema v17 Response Agent tables are incomplete")
                session_columns = {
                    row["name"]
                    for row in self.conn.execute(
                        "PRAGMA table_info(response_agent_sessions)"
                    ).fetchall()
                }
                if not {
                    "session_id",
                    "case_id",
                    "artifact_id",
                    "source_snapshot_hash",
                    "source_json",
                    "status",
                    "budget_json",
                    "usage_json",
                }.issubset(session_columns):
                    raise RuntimeError("schema v17 Response Agent session columns are incomplete")
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (17, ?)",
                    (now_ms(),),
                )

            if current < 18:
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_raw_alert_created "
                    "ON raw_alerts(created_at_ms DESC, alert_id)"
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_raw_alert_product_created "
                    "ON raw_alerts(product, created_at_ms DESC, alert_id)"
                )
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (18, ?)",
                    (now_ms(),),
                )

            if current < 19:
                match_columns = {
                    row["name"]
                    for row in self.conn.execute("PRAGMA table_info(memory_matches)").fetchall()
                }
                required_match_columns = {
                    "match_level",
                    "title_eligible",
                    "comparison_json",
                    "apply_threshold",
                    "policy_effect",
                    "selected_candidate",
                    "attack_signal_veto",
                    "attack_signal_reasons_json",
                    "config_snapshot_json",
                }
                table_row = self.conn.execute(
                    "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'memory_matches'"
                ).fetchone()
                table_sql = " ".join(str(table_row["sql"] or "").lower().split()) if table_row else ""
                run_uniqueness = bool(
                    re.search(
                        r"unique\s*\(\s*analysis_run_id\s*,\s*memory_id\s*\)",
                        table_sql,
                    )
                )
                if not run_uniqueness or not required_match_columns.issubset(match_columns):
                    self.conn.execute("DROP INDEX IF EXISTS idx_memory_matches_event")
                    self.conn.execute("DROP INDEX IF EXISTS idx_memory_matches_memory")
                    self.conn.execute("DROP INDEX IF EXISTS idx_memory_matches_case")
                    self.conn.execute("ALTER TABLE memory_matches RENAME TO memory_matches_v18")
                    self.conn.execute(
                        """
                        CREATE TABLE memory_matches (
                          match_id TEXT PRIMARY KEY,
                          event_id TEXT NOT NULL,
                          alert_id TEXT NOT NULL,
                          case_id TEXT NOT NULL,
                          analysis_run_id TEXT NOT NULL,
                          memory_id TEXT NOT NULL,
                          matcher_version TEXT NOT NULL,
                          rank INTEGER NOT NULL,
                          structured_score REAL NOT NULL,
                          semantic_score REAL NOT NULL,
                          retrieval_score REAL NOT NULL,
                          overall_score REAL NOT NULL,
                          decision TEXT NOT NULL,
                          final_effect TEXT NOT NULL,
                          matched_features_json TEXT NOT NULL,
                          score_breakdown_json TEXT NOT NULL,
                          match_level TEXT NOT NULL DEFAULT 'weak',
                          title_eligible INTEGER NOT NULL DEFAULT 0,
                          comparison_json TEXT NOT NULL DEFAULT '{}',
                          apply_threshold REAL NOT NULL DEFAULT 1.0,
                          policy_effect TEXT NOT NULL DEFAULT 'review_only',
                          selected_candidate INTEGER NOT NULL DEFAULT 0,
                          attack_signal_veto INTEGER NOT NULL DEFAULT 0,
                          attack_signal_reasons_json TEXT NOT NULL DEFAULT '[]',
                          config_snapshot_json TEXT NOT NULL DEFAULT '{}',
                          created_at_ms INTEGER NOT NULL,
                          UNIQUE (analysis_run_id, memory_id)
                        )
                        """
                    )
                    self.conn.execute(
                        """
                        INSERT INTO memory_matches
                        (match_id, event_id, alert_id, case_id, analysis_run_id, memory_id,
                         matcher_version, rank, structured_score, semantic_score, retrieval_score,
                         overall_score, decision, final_effect, matched_features_json,
                         score_breakdown_json, match_level, title_eligible, comparison_json,
                         apply_threshold, policy_effect, selected_candidate, attack_signal_veto,
                         attack_signal_reasons_json, config_snapshot_json, created_at_ms)
                        SELECT match_id, event_id, alert_id, case_id, analysis_run_id, memory_id,
                               matcher_version, rank, structured_score, semantic_score,
                               retrieval_score, overall_score, decision, final_effect,
                               matched_features_json, score_breakdown_json, 'legacy', 0, '{}',
                               1.0,
                               CASE WHEN decision IN ('apply', 'downgraded_to_benign',
                                                      'classification_reinforced')
                                    THEN 'downgrade_to_benign' ELSE 'review_only' END,
                               CASE WHEN rank = 1 THEN 1 ELSE 0 END,
                               CASE WHEN decision = 'attack_signal_veto' THEN 1 ELSE 0 END,
                               '[]', '{}', created_at_ms
                        FROM memory_matches_v18
                        """
                    )
                    self.conn.execute("DROP TABLE memory_matches_v18")
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_memory_matches_event "
                    "ON memory_matches(event_id, overall_score DESC)"
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_memory_matches_memory "
                    "ON memory_matches(memory_id, created_at_ms DESC)"
                )
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_memory_matches_case "
                    "ON memory_matches(case_id, created_at_ms DESC)"
                )
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at_ms) VALUES (19, ?)",
                    (now_ms(),),
                )

            self.conn.commit()

    def readiness_check(self) -> dict[str, Any]:
        """Verify that the live database has the expected schema and is writable.

        The no-op update runs inside a savepoint and is rolled back, so readiness
        does not mutate governance history while still detecting a read-only/full
        SQLite database that a plain ``SELECT 1`` would incorrectly accept.
        """
        with self._lock:
            check = {
                "ok": False,
                "schema_version": 0,
                "expected_schema_version": SCHEMA_VERSION,
                "readable": False,
                "writable": False,
            }
            savepoint_open = False
            try:
                self.conn.execute("SELECT 1").fetchone()
                check["readable"] = True
                row = self.conn.execute(
                    "SELECT MAX(version) AS version FROM schema_version"
                ).fetchone()
                check["schema_version"] = int((row["version"] if row else 0) or 0)
                if check["schema_version"] != SCHEMA_VERSION:
                    check["error"] = "schema_version_mismatch"
                    return check
                self.conn.execute("SAVEPOINT gateway_readiness")
                savepoint_open = True
                self.conn.execute(
                    "UPDATE schema_version SET applied_at_ms = applied_at_ms WHERE version = ?",
                    (SCHEMA_VERSION,),
                )
                self.conn.execute("ROLLBACK TO gateway_readiness")
                self.conn.execute("RELEASE gateway_readiness")
                savepoint_open = False
                check["writable"] = True
                check["ok"] = True
            except sqlite3.Error as exc:
                check["error"] = type(exc).__name__
                if savepoint_open:
                    try:
                        self.conn.execute("ROLLBACK TO gateway_readiness")
                        self.conn.execute("RELEASE gateway_readiness")
                    except sqlite3.Error:
                        pass
            return check

    def insert_raw_alert(self, alert: RawAlert, _commit: bool = True) -> bool:
        with self._lock:
            # ``INSERT OR REPLACE`` deletes the old row before re-inserting it.
            # That violates the normalized_events foreign key on a retry. An
            # alert_id is our idempotency key, so preserve the first raw evidence
            # and let the caller reuse its immutable normalized event instead.
            cur = self.conn.execute(
                """
                INSERT OR IGNORE INTO raw_alerts
                (alert_id, source, product, event_type, severity, timestamp, payload_json, created_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.source,
                    alert.product.lower(),
                    alert.event_type,
                    alert.severity.lower(),
                    alert.timestamp,
                    json.dumps(alert.payload, ensure_ascii=False, sort_keys=True),
                    now_ms(),
                ),
            )
            if _commit:
                self.conn.commit()
            return cur.rowcount > 0

    def get_raw_alert(self, alert_id: str) -> RawAlert | None:
        """Rehydrate preserved intake evidence for an analyst-requested replay."""
        with self._lock:
            row = self.conn.execute(
                """
                SELECT alert_id, source, product, event_type, severity, timestamp, payload_json
                FROM raw_alerts WHERE alert_id = ?
                """,
                (alert_id,),
            ).fetchone()
            if not row:
                return None
            return RawAlert(
                alert_id=str(row["alert_id"]),
                source=str(row["source"]),
                product=str(row["product"]),
                event_type=str(row["event_type"]),
                severity=str(row["severity"]),
                timestamp=str(row["timestamp"]),
                payload=json.loads(row["payload_json"]),
            )

    def insert_normalized_event(self, event: NormalizedEvent, _commit: bool = True) -> bool:
        """Append-only insert of a normalized event.

        Evidence is immutable: re-normalizing the same ``event_id`` does NOT
        overwrite the stored evidence. Returns True if a new row was inserted,
        False if an event with this id already existed (caller can treat the
        existing row as authoritative). The ``evidence_hash`` column records the
        hash of the evidence at first insertion for tamper detection.
        """
        with self._lock:
            evidence_json = json.dumps(event.evidence, ensure_ascii=False, sort_keys=True)
            evidence_hash = hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
            cur = self.conn.execute(
                """
                INSERT OR IGNORE INTO normalized_events
                (event_id, alert_id, source, product, event_type, severity, timestamp,
                 entities_json, evidence_json, sensitivity_tags_json, evidence_hash, event_at_ms, created_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.raw_ref,
                    event.source,
                    event.product,
                    event.event_type,
                    event.severity,
                    event.timestamp,
                    json.dumps(event.entities, ensure_ascii=False, sort_keys=True),
                    evidence_json,
                    json.dumps(event.sensitivity_tags, ensure_ascii=False),
                    evidence_hash,
                    self.timestamp_ms(event.timestamp),
                    now_ms(),
                ),
            )
            if _commit:
                self.conn.commit()
            return cur.rowcount > 0

    def upsert_case(
        self,
        result: AgentResult,
        product: str,
        _commit: bool = True,
        correlation_key: str | None = None,
        alert_at_ms: int | None = None,
    ) -> None:
        with self._lock:
            # Cases are a live aggregate. SQLite ``REPLACE`` deletes the existing
            # parent row before inserting, which breaks its agent-run and alert-link
            # foreign keys. A true conflict update preserves created_at_ms and the
            # analyst-controlled status while refreshing the latest assessment.
            self.conn.execute(
                """
                INSERT INTO cases
                (case_id, correlation_key, product, status, severity, classification,
                 confidence, summary, created_at_ms, updated_at_ms, last_alert_at_ms, closed_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT(case_id) DO UPDATE SET
                  correlation_key = CASE
                    WHEN cases.correlation_key = '' THEN excluded.correlation_key
                    ELSE cases.correlation_key
                  END,
                  product = excluded.product,
                  status = CASE
                    WHEN cases.status IN ('analyzing', 'analysis_deferred', 'analysis_failed')
                      THEN excluded.status
                    ELSE cases.status
                  END,
                  severity = excluded.severity,
                  classification = excluded.classification,
                  confidence = excluded.confidence,
                  summary = excluded.summary,
                  updated_at_ms = excluded.updated_at_ms,
                  last_alert_at_ms = MAX(cases.last_alert_at_ms, excluded.last_alert_at_ms),
                  closed_at_ms = CASE
                    WHEN cases.status IN ('analyzing', 'analysis_deferred', 'analysis_failed')
                      THEN NULL
                    ELSE cases.closed_at_ms
                  END
                """,
                (
                    result.case_id,
                    correlation_key or result.case_id,
                    product,
                    "open",
                    result.severity,
                    result.classification,
                    result.confidence,
                    result.summary,
                    result.created_at_ms,
                    now_ms(),
                    alert_at_ms or result.created_at_ms,
                ),
            )
            if _commit:
                self.conn.commit()

    def ensure_provisional_case(
        self,
        *,
        case_id: str,
        correlation_key: str,
        product: str,
        severity: str,
        event_type: str,
        alert_at_ms: int,
        _commit: bool = True,
    ) -> bool:
        """Make a normalized alert visible before remote analysis completes.

        Retries may move only machine-owned provisional states back to
        ``analyzing``. Existing analyst-controlled or completed Case state is
        never overwritten.
        """
        with self._lock:
            created_at = now_ms()
            summary = f"告警已接收，AI 研判进行中 · {event_type}"
            cur = self.conn.execute(
                """
                INSERT OR IGNORE INTO cases
                (case_id, correlation_key, product, status, severity, classification,
                 confidence, summary, created_at_ms, updated_at_ms, last_alert_at_ms, closed_at_ms)
                VALUES (?, ?, ?, 'analyzing', ?, 'pending_analysis', 0, ?, ?, ?, ?, NULL)
                """,
                (
                    case_id,
                    correlation_key,
                    product,
                    severity,
                    summary,
                    created_at,
                    created_at,
                    alert_at_ms,
                ),
            )
            created = cur.rowcount > 0
            if not created:
                self.conn.execute(
                    """
                    UPDATE cases
                    SET status = 'analyzing',
                        severity = ?,
                        classification = 'pending_analysis',
                        confidence = 0,
                        summary = ?,
                        updated_at_ms = ?,
                        last_alert_at_ms = MAX(last_alert_at_ms, ?),
                        closed_at_ms = NULL
                    WHERE case_id = ?
                      AND status IN ('analyzing', 'analysis_deferred', 'analysis_failed')
                    """,
                    (severity, summary, created_at, alert_at_ms, case_id),
                )
            if _commit:
                self.conn.commit()
            return created

    def update_provisional_case_status(
        self,
        case_id: str,
        status: str,
        event_type: str,
        _commit: bool = True,
    ) -> bool:
        """Transition only a still-provisional Case to another machine state."""
        if status not in PROVISIONAL_CASE_STATUSES:
            raise ValueError(f"unsupported provisional Case status: {status}")
        summaries = {
            "analyzing": f"告警已接收，AI 研判进行中 · {event_type}",
            "analysis_deferred": f"远程模型暂不可用，告警等待自动重试 · {event_type}",
            "analysis_failed": f"AI 研判失败，告警证据已保留 · {event_type}",
        }
        with self._lock:
            cur = self.conn.execute(
                """
                UPDATE cases
                SET status = ?, classification = 'pending_analysis', confidence = 0,
                    summary = ?, updated_at_ms = ?, closed_at_ms = NULL
                WHERE case_id = ?
                  AND status IN ('analyzing', 'analysis_deferred', 'analysis_failed')
                """,
                (status, summaries[status], now_ms(), case_id),
            )
            if _commit:
                self.conn.commit()
            return cur.rowcount > 0

    def insert_agent_run(
        self, run_id: str, result: AgentResult, product: str, prompt_version: str, event_id: str, _commit: bool = True
    ) -> None:
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO agent_runs
                (run_id, case_id, event_id, agent, product, prompt_version, result_json, created_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    result.case_id,
                    event_id,
                    result.agent,
                    product,
                    prompt_version,
                    json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True),
                    now_ms(),
                ),
            )
            if _commit:
                self.conn.commit()

    def insert_validation(self, validation: dict[str, Any], _commit: bool = True) -> None:
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO validation_runs
                (validation_id, case_id, event_id, validator, validator_version, status, result_json, created_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    validation["validation_id"],
                    validation["case_id"],
                    validation["event_id"],
                    validation["validator"],
                    validation["validator_version"],
                    validation["status"],
                    json.dumps(validation, ensure_ascii=False, sort_keys=True),
                    int(validation["created_at_ms"]),
                ),
            )
            if _commit:
                self.conn.commit()

    def get_validation(self, validation_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT result_json FROM validation_runs WHERE validation_id = ?",
                (validation_id,),
            ).fetchone()
            return json.loads(row["result_json"]) if row else None

    def get_validation_review_resolution(self, validation_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM validation_review_resolutions WHERE validation_id = ?",
                (validation_id,),
            ).fetchone()
            return dict(row) if row else None

    def create_validation_review_resolution(
        self,
        resolution_id: str,
        validation_id: str,
        case_id: str,
        event_id: str,
        actor: str,
        reason: str,
        _commit: bool = True,
    ) -> tuple[dict[str, Any], bool]:
        """Persist the one allowed analyst continuation for a validation run.

        ``validation_id`` is unique, making retry/double-click behavior
        idempotent. This lower layer repeats the eligibility check so a caller
        cannot turn another kind of review into an approval by bypassing the
        HTTP/state boundary.
        """
        with self._lock:
            validation_row = self.conn.execute(
                """
                SELECT case_id, event_id, result_json FROM validation_runs
                WHERE validation_id = ?
                """,
                (validation_id,),
            ).fetchone()
            if (
                not validation_row
                or validation_row["case_id"] != case_id
                or validation_row["event_id"] != event_id
            ):
                raise ValueError("validation does not match the requested case and event")
            validation = ValidationResult.from_dict(json.loads(validation_row["result_json"]))
            if not can_continue_after_manual_review(validation):
                raise ValueError("validation review is not eligible for manual continuation")
            cur = self.conn.execute(
                """
                INSERT OR IGNORE INTO validation_review_resolutions
                (resolution_id, validation_id, case_id, event_id, decision, actor, reason, created_at_ms)
                VALUES (?, ?, ?, ?, 'continue', ?, ?, ?)
                """,
                (resolution_id, validation_id, case_id, event_id, actor, reason, now_ms()),
            )
            row = self.conn.execute(
                "SELECT * FROM validation_review_resolutions WHERE validation_id = ?",
                (validation_id,),
            ).fetchone()
            if _commit:
                self.conn.commit()
            if not row:  # pragma: no cover - INSERT OR IGNORE must select a row.
                raise RuntimeError("validation review resolution was not persisted")
            return dict(row), cur.rowcount > 0

    def insert_approval(self, approval: dict[str, Any], _commit: bool = True) -> bool:
        with self._lock:
            case = self.conn.execute(
                "SELECT status FROM cases WHERE case_id = ?", (approval["case_id"],)
            ).fetchone()
            validation_id = str(approval.get("validation_id") or "")
            if validation_id:
                validation = self.conn.execute(
                    """
                    SELECT validation_id, case_id, event_id, status FROM validation_runs
                    WHERE validation_id = ?
                    """,
                    (validation_id,),
                ).fetchone()
            else:
                validation = self.conn.execute(
                    """
                    SELECT validation_id, case_id, event_id, status FROM validation_runs
                    WHERE case_id = ? AND event_id = ? ORDER BY created_at_ms DESC LIMIT 1
                    """,
                    (approval["case_id"], approval["event_id"]),
                ).fetchone()
            if not case or case["status"] in {"closed", "false_positive"}:
                return False
            if (
                not validation
                or validation["case_id"] != approval["case_id"]
                or validation["event_id"] != approval["event_id"]
            ):
                return False
            review_resolution_id = str(approval.get("review_resolution_id") or "")
            if validation["status"] == "passed":
                allowed = not review_resolution_id
            elif validation["status"] == "review" and review_resolution_id:
                resolution = self.conn.execute(
                    """
                    SELECT 1 FROM validation_review_resolutions
                    WHERE resolution_id = ?
                      AND validation_id = ?
                      AND case_id = ?
                      AND event_id = ?
                      AND decision = 'continue'
                    """,
                    (
                        review_resolution_id,
                        validation["validation_id"],
                        approval["case_id"],
                        approval["event_id"],
                    ),
                ).fetchone()
                allowed = bool(resolution)
            else:
                allowed = False
            if not allowed:
                return False
            action_json = json.dumps(
                {
                    "action": approval["action"],
                    "rationale": approval["rationale"],
                    "rollback": approval["rollback"],
                    "stage": approval.get("stage", ""),
                    "mode": approval["mode"],
                    "execution_action": approval.get("execution_action") or {},
                },
                ensure_ascii=False,
                sort_keys=True,
            )
            cur = self.conn.execute(
                """
                INSERT OR IGNORE INTO action_approvals
                (approval_id, case_id, event_id, validation_id, review_resolution_id,
                 action_json, status, requested_by,
                 decided_by, decision_reason, execution_status, required_approvals,
                 created_at_ms, updated_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, '', '', 'not_executed', ?, ?, ?)
                """,
                (
                    approval["approval_id"],
                    approval["case_id"],
                    approval["event_id"],
                    validation["validation_id"],
                    review_resolution_id,
                    action_json,
                    approval["requested_by"],
                    max(1, min(int(approval.get("required_approvals", 1)), 5)),
                    int(approval["created_at_ms"]),
                    int(approval["created_at_ms"]),
                ),
            )
            if _commit:
                self.conn.commit()
            return cur.rowcount > 0

    def decide_approval(
        self, approval_id: str, decision: str, actor: str, reason: str, _commit: bool = True
    ) -> dict[str, Any] | None:
        if decision not in {"approved", "rejected", "cancelled"}:
            raise ValueError(f"unsupported approval decision: {decision}")
        with self._lock:
            updated_at = now_ms()
            approval = self.conn.execute(
                "SELECT status, required_approvals FROM action_approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            if not approval or approval["status"] != "pending":
                return None
            vote = self.conn.execute(
                """
                INSERT OR IGNORE INTO approval_votes
                (approval_id, actor, decision, reason, created_at_ms)
                VALUES (?, ?, ?, ?, ?)
                """,
                (approval_id, actor, decision, reason, updated_at),
            )
            if vote.rowcount == 0:
                result = self.get_approval(approval_id)
                if result is not None:
                    result["vote_recorded"] = False
                return result
            status = "pending"
            if decision in {"rejected", "cancelled"}:
                status = decision
            else:
                approved_count = self.conn.execute(
                    "SELECT COUNT(*) AS count FROM approval_votes WHERE approval_id = ? AND decision = 'approved'",
                    (approval_id,),
                ).fetchone()["count"]
                if int(approved_count) >= int(approval["required_approvals"]):
                    status = "approved"
            if status == "pending":
                self.conn.execute(
                    "UPDATE action_approvals SET updated_at_ms = ? WHERE approval_id = ?",
                    (updated_at, approval_id),
                )
            else:
                self.conn.execute(
                    """
                    UPDATE action_approvals
                    SET status = ?, decided_by = ?, decision_reason = ?, updated_at_ms = ?
                    WHERE approval_id = ? AND status = 'pending'
                    """,
                    (status, actor, reason, updated_at, approval_id),
                )
            if _commit:
                self.conn.commit()
            result = self.get_approval(approval_id)
            if result is not None:
                result["vote_recorded"] = True
            return result

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM action_approvals WHERE approval_id = ?", (approval_id,)).fetchone()
            return self._approval_row(row) if row else None

    def list_approvals(
        self,
        case_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
        review_resolution_id: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            clauses: list[str] = []
            params: list[Any] = []
            if case_id:
                clauses.append("case_id = ?")
                params.append(case_id)
            if status:
                clauses.append("status = ?")
                params.append(status)
            if review_resolution_id:
                clauses.append("review_resolution_id = ?")
                params.append(review_resolution_id)
            sql = "SELECT * FROM action_approvals"
            if clauses:
                sql += " WHERE " + " AND ".join(clauses)
            sql += " ORDER BY created_at_ms DESC LIMIT ?"
            params.append(max(1, min(int(limit), 500)))
            rows = self.conn.execute(sql, params).fetchall()
            if not rows:
                return []
            approval_ids = [str(row["approval_id"]) for row in rows]
            placeholders = ",".join("?" for _ in approval_ids)
            votes_by_approval: dict[str, list[dict[str, Any]]] = {
                approval_id: [] for approval_id in approval_ids
            }
            for vote in self.conn.execute(
                f"""
                SELECT approval_id, actor, decision, reason, created_at_ms
                FROM approval_votes
                WHERE approval_id IN ({placeholders})
                ORDER BY created_at_ms ASC, actor ASC
                """,
                approval_ids,
            ).fetchall():
                vote_item = dict(vote)
                approval_id = str(vote_item.pop("approval_id"))
                votes_by_approval.setdefault(approval_id, []).append(vote_item)
            tasks_by_approval = {
                str(task["approval_id"]): task
                for task in self.conn.execute(
                    f"SELECT * FROM response_tasks WHERE approval_id IN ({placeholders})",
                    approval_ids,
                ).fetchall()
            }
            return [
                self._approval_row(
                    row,
                    votes=votes_by_approval.get(str(row["approval_id"]), []),
                    response_task=tasks_by_approval.get(str(row["approval_id"])),
                    response_task_loaded=True,
                )
                for row in rows
            ]

    def _approval_row(
        self,
        row: sqlite3.Row,
        votes: list[dict[str, Any]] | None = None,
        response_task: sqlite3.Row | None = None,
        response_task_loaded: bool = False,
    ) -> dict[str, Any]:
        payload = dict(row)
        payload["action"] = json.loads(payload.pop("action_json"))
        if votes is None:
            votes = [
                dict(vote)
                for vote in self.conn.execute(
                    """
                    SELECT actor, decision, reason, created_at_ms FROM approval_votes
                    WHERE approval_id = ? ORDER BY created_at_ms ASC, actor ASC
                    """,
                    (payload["approval_id"],),
                ).fetchall()
            ]
        payload["votes"] = votes
        payload["vote_count"] = sum(1 for vote in votes if vote["decision"] == "approved")
        task = response_task
        if not response_task_loaded:
            task = self.conn.execute(
                "SELECT * FROM response_tasks WHERE approval_id = ?",
                (payload["approval_id"],),
            ).fetchone()
        payload["response_task"] = self._response_task_row(task) if task else None
        return payload

    # ---- controlled response automation ---------------------------------

    @staticmethod
    def _response_connector_row(row: sqlite3.Row) -> dict[str, Any]:
        payload = dict(row)
        payload["enabled"] = bool(payload["enabled"])
        return payload

    def save_response_connector(
        self, connector: dict[str, Any], *, actor: str, _commit: bool = True
    ) -> dict[str, Any]:
        with self._lock:
            current = self.conn.execute(
                "SELECT version, created_by, created_at_ms FROM response_connectors WHERE connector_id = ?",
                (connector["connector_id"],),
            ).fetchone()
            timestamp = now_ms()
            version = int(current["version"] if current else 0) + 1
            created_by = str(current["created_by"] if current else actor)
            created_at = int(current["created_at_ms"] if current else timestamp)
            self.conn.execute(
                """
                INSERT INTO response_connectors(
                  connector_id, name, connector_type, endpoint, secret_env,
                  execution_mode, enabled, max_ttl_seconds, timeout_seconds,
                  health_status, last_error, last_test_at_ms, version,
                  created_by, updated_by, created_at_ms, updated_at_ms
                ) VALUES (?, ?, 'generic_webhook', ?, ?, ?, ?, ?, ?, 'untested', '', NULL, ?, ?, ?, ?, ?)
                ON CONFLICT(connector_id) DO UPDATE SET
                  name = excluded.name,
                  endpoint = excluded.endpoint,
                  secret_env = excluded.secret_env,
                  execution_mode = excluded.execution_mode,
                  enabled = excluded.enabled,
                  max_ttl_seconds = excluded.max_ttl_seconds,
                  timeout_seconds = excluded.timeout_seconds,
                  health_status = 'untested',
                  last_error = '',
                  last_test_at_ms = NULL,
                  version = excluded.version,
                  updated_by = excluded.updated_by,
                  updated_at_ms = excluded.updated_at_ms
                """,
                (
                    connector["connector_id"], connector["name"], connector["endpoint"],
                    connector.get("secret_env", ""), connector["execution_mode"],
                    1 if connector.get("enabled") else 0,
                    int(connector["max_ttl_seconds"]), int(connector["timeout_seconds"]),
                    version, created_by, actor, created_at, timestamp,
                ),
            )
            if _commit:
                self.conn.commit()
            return self.get_response_connector(connector["connector_id"]) or {}

    def get_response_connector(self, connector_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM response_connectors WHERE connector_id = ?", (connector_id,)
            ).fetchone()
            return self._response_connector_row(row) if row else None

    def list_response_connectors(self, *, enabled_only: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            where = "WHERE enabled = 1" if enabled_only else ""
            rows = self.conn.execute(
                f"SELECT * FROM response_connectors {where} ORDER BY updated_at_ms DESC, name ASC"
            ).fetchall()
            return [self._response_connector_row(row) for row in rows]

    def update_response_connector_health(
        self, connector_id: str, status: str, error: str = "", *, _commit: bool = True
    ) -> dict[str, Any] | None:
        if status not in {"healthy", "error"}:
            raise ValueError("unsupported connector health status")
        with self._lock:
            timestamp = now_ms()
            self.conn.execute(
                """
                UPDATE response_connectors
                SET health_status = ?, last_error = ?, last_test_at_ms = ?, updated_at_ms = ?
                WHERE connector_id = ?
                """,
                (status, str(error)[:1000], timestamp, timestamp, connector_id),
            )
            if _commit:
                self.conn.commit()
            return self.get_response_connector(connector_id)

    def get_response_policy(self) -> dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM response_policy WHERE singleton = 1"
            ).fetchone()
            payload = dict(row) if row else {
                "enabled": 0,
                "default_ttl_seconds": 1800,
                "max_ttl_seconds": 86400,
                "protected_cidrs_json": "[]",
                "updated_by": "system",
                "updated_at_ms": 0,
            }
            payload["enabled"] = bool(payload["enabled"])
            payload["protected_cidrs"] = json.loads(payload.pop("protected_cidrs_json"))
            return payload

    def save_response_policy(
        self, policy: dict[str, Any], *, actor: str, _commit: bool = True
    ) -> dict[str, Any]:
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO response_policy(
                  singleton, enabled, default_ttl_seconds, max_ttl_seconds,
                  protected_cidrs_json, updated_by, updated_at_ms
                ) VALUES (1, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(singleton) DO UPDATE SET
                  enabled = excluded.enabled,
                  default_ttl_seconds = excluded.default_ttl_seconds,
                  max_ttl_seconds = excluded.max_ttl_seconds,
                  protected_cidrs_json = excluded.protected_cidrs_json,
                  updated_by = excluded.updated_by,
                  updated_at_ms = excluded.updated_at_ms
                """,
                (
                    1 if policy.get("enabled") else 0,
                    int(policy["default_ttl_seconds"]), int(policy["max_ttl_seconds"]),
                    json.dumps(policy["protected_cidrs"], ensure_ascii=False, sort_keys=True),
                    actor, now_ms(),
                ),
            )
            if not policy.get("enabled"):
                self.conn.execute(
                    """
                    UPDATE response_tasks
                    SET status = 'paused', last_error = 'response policy is disabled',
                        claimed_at_ms = NULL, updated_at_ms = ?
                    WHERE status IN ('queued','retry_wait')
                    """,
                    (now_ms(),),
                )
            if _commit:
                self.conn.commit()
            return self.get_response_policy()

    @staticmethod
    def _response_task_row(row: sqlite3.Row) -> dict[str, Any]:
        payload = dict(row)
        payload["action"] = json.loads(payload.pop("action_json"))
        payload["connector_snapshot"] = json.loads(
            payload.pop("connector_snapshot_json") or "{}"
        )
        return payload

    def create_response_task(
        self, task: dict[str, Any], *, _commit: bool = True
    ) -> tuple[dict[str, Any], bool]:
        with self._lock:
            cur = self.conn.execute(
                """
                INSERT OR IGNORE INTO response_tasks(
                  task_id, approval_id, case_id, event_id, action_type, action_json,
                  connector_id, connector_version, connector_snapshot_json,
                  status, idempotency_key, attempts, max_attempts, available_at_ms,
                  claimed_at_ms, remote_rule_id, last_error, verified_at_ms,
                  expires_at_ms, created_by, created_at_ms, updated_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, NULL, '', '', NULL, NULL, ?, ?, ?)
                """,
                (
                    task["task_id"], task["approval_id"], task["case_id"], task["event_id"],
                    task["action_type"],
                    json.dumps(task["action"], ensure_ascii=False, sort_keys=True),
                    task.get("connector_id"), int(task.get("connector_version", 0)),
                    json.dumps(task.get("connector_snapshot") or {}, ensure_ascii=False, sort_keys=True),
                    task["status"], task["idempotency_key"], int(task.get("max_attempts", 5)),
                    int(task.get("available_at_ms", now_ms())), task["created_by"],
                    int(task["created_at_ms"]), int(task["created_at_ms"]),
                ),
            )
            row = self.conn.execute(
                "SELECT * FROM response_tasks WHERE approval_id = ?", (task["approval_id"],)
            ).fetchone()
            if _commit:
                self.conn.commit()
            if not row:
                raise RuntimeError("response task was not persisted")
            return self._response_task_row(row), cur.rowcount > 0

    def get_response_task(self, task_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM response_tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            if not row:
                return None
            payload = self._response_task_row(row)
            payload["attempt_history"] = [
                dict(item)
                for item in self.conn.execute(
                    "SELECT * FROM response_attempts WHERE task_id = ? ORDER BY created_at_ms ASC",
                    (task_id,),
                ).fetchall()
            ]
            return payload

    def list_response_tasks(
        self, *, status: str | None = None, limit: int = 20, offset: int = 0
    ) -> list[dict[str, Any]]:
        with self._lock:
            where = "WHERE status = ?" if status else ""
            params: list[Any] = [status] if status else []
            params.extend([max(1, min(int(limit), 200)), max(0, int(offset))])
            rows = self.conn.execute(
                f"SELECT * FROM response_tasks {where} ORDER BY created_at_ms DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
            return [self._response_task_row(row) for row in rows]

    def count_response_tasks(self, *, status: str | None = None) -> int:
        with self._lock:
            if status:
                row = self.conn.execute(
                    "SELECT COUNT(*) AS count FROM response_tasks WHERE status = ?", (status,)
                ).fetchone()
            else:
                row = self.conn.execute("SELECT COUNT(*) AS count FROM response_tasks").fetchone()
            return int(row["count"])

    def response_task_stats(self) -> dict[str, int]:
        with self._lock:
            stats = {
                str(row["status"]): int(row["count"])
                for row in self.conn.execute(
                    "SELECT status, COUNT(*) AS count FROM response_tasks GROUP BY status"
                ).fetchall()
            }
            stats["total"] = sum(stats.values())
            return stats

    def response_task_preflight(self, task_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                """
                SELECT t.task_id, t.event_id, a.status AS approval_status,
                       c.status AS case_status,
                       (SELECT ar.event_id FROM agent_runs ar
                        WHERE ar.case_id = t.case_id
                        ORDER BY ar.created_at_ms DESC LIMIT 1) AS latest_event_id
                FROM response_tasks t
                JOIN action_approvals a ON a.approval_id = t.approval_id
                JOIN cases c ON c.case_id = t.case_id
                WHERE t.task_id = ?
                """,
                (task_id,),
            ).fetchone()
            if not row:
                return None
            payload = dict(row)
            payload["eligible"] = (
                payload["approval_status"] == "approved"
                and payload["case_status"] not in {"closed", "false_positive"}
                and payload["event_id"] == payload["latest_event_id"]
            )
            return payload

    def queue_response_task(
        self, task_id: str, *, rollback: bool = False
    ) -> dict[str, Any] | None:
        allowed = (
            {"verified", "shadowed", "failed", "rollback_failed"}
            if rollback
            else {"waiting_dispatch", "paused", "retry_wait"}
        )
        target = "rollback_queued" if rollback else "queued"
        with self._lock:
            row = self.conn.execute(
                "SELECT status, remote_rule_id FROM response_tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            if not row or row["status"] not in allowed:
                return None
            if (
                rollback
                and row["status"] == "failed"
                and not str(row["remote_rule_id"] or "")
            ):
                return None
            timestamp = now_ms()
            self.conn.execute(
                """
                UPDATE response_tasks
                SET status = ?, available_at_ms = ?, claimed_at_ms = NULL,
                    last_error = '', updated_at_ms = ?
                WHERE task_id = ?
                """,
                (target, timestamp, timestamp, task_id),
            )
            self.conn.commit()
            return self.get_response_task(task_id)

    def bind_response_task_connector(
        self, task_id: str, connector: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Freeze a connector snapshot onto a task approved before configuration."""
        with self._lock:
            timestamp = now_ms()
            cur = self.conn.execute(
                """
                UPDATE response_tasks
                SET connector_id = ?, connector_version = ?, connector_snapshot_json = ?,
                    status = 'waiting_dispatch', last_error = '', updated_at_ms = ?
                WHERE task_id = ? AND status = 'waiting_configuration'
                  AND connector_snapshot_json = '{}'
                """,
                (
                    connector["connector_id"],
                    int(connector["version"]),
                    json.dumps(connector, ensure_ascii=False, sort_keys=True),
                    timestamp,
                    task_id,
                ),
            )
            self.conn.commit()
            return self.get_response_task(task_id) if cur.rowcount else None

    def resume_paused_response_tasks(self) -> int:
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT task_id, connector_snapshot_json FROM response_tasks
                WHERE status = 'paused' AND connector_snapshot_json != '{}'
                """
            ).fetchall()
            timestamp = now_ms()
            resumed = 0
            for row in rows:
                snapshot = json.loads(row["connector_snapshot_json"] or "{}")
                mode = str(snapshot.get("execution_mode") or "")
                if mode not in {"shadow", "manual", "auto"}:
                    continue
                status = "waiting_dispatch" if mode == "manual" else "queued"
                self.conn.execute(
                    """
                    UPDATE response_tasks
                    SET status = ?, available_at_ms = ?, last_error = '', updated_at_ms = ?
                    WHERE task_id = ? AND status = 'paused'
                    """,
                    (status, timestamp, timestamp, row["task_id"]),
                )
                resumed += 1
            self.conn.commit()
            return resumed

    def claim_response_task(self) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                """
                SELECT task_id, status FROM response_tasks
                WHERE status IN ('queued','retry_wait','rollback_queued','rollback_retry')
                  AND available_at_ms <= ?
                ORDER BY available_at_ms ASC, created_at_ms ASC LIMIT 1
                """,
                (now_ms(),),
            ).fetchone()
            if not row:
                return None
            target = "rollback_running" if str(row["status"]).startswith("rollback") else "running"
            timestamp = now_ms()
            cur = self.conn.execute(
                """
                UPDATE response_tasks
                SET status = ?, attempts = attempts + 1, claimed_at_ms = ?, updated_at_ms = ?
                WHERE task_id = ? AND status = ?
                """,
                (target, timestamp, timestamp, row["task_id"], row["status"]),
            )
            self.conn.commit()
            return self.get_response_task(row["task_id"]) if cur.rowcount else None

    def finish_response_task(
        self,
        task_id: str,
        status: str,
        *,
        expected_status: str,
        remote_rule_id: str = "",
        error: str = "",
        retry_delay_ms: int = 0,
        require_active_case: bool = False,
        _commit: bool = True,
    ) -> dict[str, Any] | None:
        with self._lock:
            verified_at = now_ms() if status in {"verified", "shadowed", "rolled_back"} else None
            expires_at = None
            if status == "verified":
                row = self.conn.execute(
                    "SELECT action_json FROM response_tasks WHERE task_id = ?", (task_id,)
                ).fetchone()
                if row:
                    duration = max(60, int(json.loads(row["action_json"]).get("duration_seconds") or 0))
                    expires_at = int(verified_at or now_ms()) + duration * 1000
            active_case_clause = ""
            if require_active_case:
                active_case_clause = """
                  AND EXISTS (
                    SELECT 1 FROM cases c
                    WHERE c.case_id = response_tasks.case_id
                      AND c.status NOT IN ('closed', 'false_positive')
                  )
                """
            cur = self.conn.execute(
                f"""
                UPDATE response_tasks
                SET status = ?,
                    remote_rule_id = CASE WHEN ? != '' THEN ? ELSE remote_rule_id END,
                    last_error = ?, available_at_ms = ?, claimed_at_ms = NULL,
                    verified_at_ms = COALESCE(?, verified_at_ms),
                    expires_at_ms = COALESCE(?, expires_at_ms), updated_at_ms = ?
                WHERE task_id = ? AND status = ?
                {active_case_clause}
                """,
                (
                    status, remote_rule_id, remote_rule_id, str(error)[:2000],
                    now_ms() + max(0, int(retry_delay_ms)), verified_at, expires_at,
                    now_ms(), task_id, expected_status,
                ),
            )
            if _commit:
                self.conn.commit()
            return self.get_response_task(task_id) if cur.rowcount else None

    def record_response_rule_id(
        self, task_id: str, remote_rule_id: str, *, _commit: bool = True
    ) -> dict[str, Any] | None:
        with self._lock:
            timestamp = now_ms()
            cur = self.conn.execute(
                """
                UPDATE response_tasks
                SET remote_rule_id = ?,
                    status = CASE
                      WHEN EXISTS (
                        SELECT 1 FROM cases c
                        WHERE c.case_id = response_tasks.case_id
                          AND c.status IN ('closed', 'false_positive')
                      ) THEN 'rollback_queued'
                      ELSE status
                    END,
                    available_at_ms = CASE
                      WHEN EXISTS (
                        SELECT 1 FROM cases c
                        WHERE c.case_id = response_tasks.case_id
                          AND c.status IN ('closed', 'false_positive')
                      ) THEN ?
                      ELSE available_at_ms
                    END,
                    claimed_at_ms = CASE
                      WHEN EXISTS (
                        SELECT 1 FROM cases c
                        WHERE c.case_id = response_tasks.case_id
                          AND c.status IN ('closed', 'false_positive')
                      ) THEN NULL
                      ELSE claimed_at_ms
                    END,
                    last_error = CASE
                      WHEN EXISTS (
                        SELECT 1 FROM cases c
                        WHERE c.case_id = response_tasks.case_id
                          AND c.status IN ('closed', 'false_positive')
                      ) THEN 'case became terminal after remote apply'
                      ELSE last_error
                    END,
                    updated_at_ms = ?
                WHERE task_id = ? AND status = 'running'
                """,
                (str(remote_rule_id)[:512], timestamp, timestamp, task_id),
            )
            if _commit:
                self.conn.commit()
            return self.get_response_task(task_id) if cur.rowcount else None

    def insert_response_attempt(
        self, attempt: dict[str, Any], *, _commit: bool = True
    ) -> None:
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO response_attempts(
                  attempt_id, task_id, operation, attempt_no, request_hash,
                  http_status, outcome, response_excerpt, error, created_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt["attempt_id"], attempt["task_id"], attempt["operation"],
                    int(attempt.get("attempt_no", 0)), attempt.get("request_hash", ""),
                    attempt.get("http_status"), attempt["outcome"],
                    str(attempt.get("response_excerpt", ""))[:2000],
                    str(attempt.get("error", ""))[:2000],
                    int(attempt.get("created_at_ms", now_ms())),
                ),
            )
            if _commit:
                self.conn.commit()

    def queue_expired_response_tasks(self) -> int:
        with self._lock:
            timestamp = now_ms()
            cur = self.conn.execute(
                """
                UPDATE response_tasks
                SET status = 'rollback_queued', available_at_ms = ?, updated_at_ms = ?
                WHERE status = 'verified' AND expires_at_ms IS NOT NULL AND expires_at_ms <= ?
                """,
                (timestamp, timestamp, timestamp),
            )
            self.conn.commit()
            return cur.rowcount

    def queue_terminal_case_response_rollbacks(
        self, case_id: str | None = None, *, _commit: bool = True
    ) -> int:
        """Reconcile terminal Cases with response tasks that may have a remote rule."""
        with self._lock:
            timestamp = now_ms()
            case_clause = " AND case_id = ?" if case_id else ""
            params: list[Any] = [timestamp, timestamp]
            if case_id:
                params.append(case_id)
            cur = self.conn.execute(
                f"""
                UPDATE response_tasks
                SET status = 'rollback_queued', available_at_ms = ?, claimed_at_ms = NULL,
                    last_error = 'case became terminal; compensating rollback required',
                    updated_at_ms = ?
                WHERE EXISTS (
                    SELECT 1 FROM cases c
                    WHERE c.case_id = response_tasks.case_id
                      AND c.status IN ('closed', 'false_positive')
                )
                  AND status NOT IN (
                    'shadowed','rollback_queued','rollback_running','rollback_retry',
                    'rolled_back','rollback_failed'
                  )
                  AND (status = 'verified' OR remote_rule_id != '')
                  {case_clause}
                """,
                params,
            )
            if _commit:
                self.conn.commit()
            return cur.rowcount

    def recover_stale_response_tasks(self, stale_before_ms: int) -> int:
        with self._lock:
            timestamp = now_ms()
            cur = self.conn.execute(
                """
                UPDATE response_tasks
                SET status = CASE
                      WHEN status = 'rollback_running' THEN 'rollback_retry'
                      ELSE 'retry_wait'
                    END,
                    available_at_ms = ?, claimed_at_ms = NULL,
                    last_error = 'stale execution lease recovered', updated_at_ms = ?
                WHERE status IN ('running','rollback_running')
                  AND claimed_at_ms IS NOT NULL AND claimed_at_ms < ?
                """,
                (timestamp, timestamp, int(stale_before_ms)),
            )
            self.conn.commit()
            return cur.rowcount

    def transition_case_response_tasks(self, case_id: str, *, _commit: bool = True) -> int:
        with self._lock:
            timestamp = now_ms()
            rollback = self.queue_terminal_case_response_rollbacks(case_id, _commit=False)
            cancelled = self.conn.execute(
                """
                UPDATE response_tasks
                SET status = 'cancelled', last_error = 'case became terminal', updated_at_ms = ?
                WHERE case_id = ? AND status IN (
                  'waiting_configuration','waiting_dispatch','paused','queued','retry_wait'
                )
                  AND remote_rule_id = ''
                """,
                (timestamp, case_id),
            ).rowcount
            if _commit:
                self.conn.commit()
            return cancelled + rollback

    # ---- runtime settings / durable alert inbox ---------------------------

    def set_runtime_setting(
        self,
        key: str,
        value: Any,
        updated_by: str = "system",
        _commit: bool = True,
    ) -> dict[str, Any]:
        normalized_key = str(key).strip()
        if not normalized_key:
            raise ValueError("runtime setting key is required")
        with self._lock:
            updated_at = now_ms()
            self.conn.execute(
                """
                INSERT INTO runtime_settings(key, value_json, updated_by, updated_at_ms)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                  value_json = excluded.value_json,
                  updated_by = excluded.updated_by,
                  updated_at_ms = excluded.updated_at_ms
                """,
                (
                    normalized_key,
                    json.dumps(value, ensure_ascii=False, sort_keys=True),
                    str(updated_by or "system"),
                    updated_at,
                ),
            )
            if _commit:
                self.conn.commit()
            return {
                "key": normalized_key,
                "value": value,
                "updated_by": str(updated_by or "system"),
                "updated_at_ms": updated_at,
            }

    def get_runtime_setting(self, key: str, default: Any = None) -> Any:
        with self._lock:
            row = self.conn.execute(
                "SELECT value_json FROM runtime_settings WHERE key = ?", (str(key),)
            ).fetchone()
            return json.loads(row["value_json"]) if row else default

    def list_runtime_settings(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT key, value_json, updated_by, updated_at_ms FROM runtime_settings ORDER BY key"
            ).fetchall()
            return [
                {
                    "key": row["key"],
                    "value": json.loads(row["value_json"]),
                    "updated_by": row["updated_by"],
                    "updated_at_ms": row["updated_at_ms"],
                }
                for row in rows
            ]

    @staticmethod
    def _durable_alert_payload(alert: RawAlert | dict[str, Any]) -> dict[str, Any]:
        if isinstance(alert, RawAlert):
            return {
                "source": alert.source,
                "product": alert.product,
                "event_type": alert.event_type,
                "severity": alert.severity,
                "timestamp": alert.timestamp,
                "payload": alert.payload,
                "alert_id": alert.alert_id,
                "trusted_sample": bool(alert.trusted_sample),
                "operational_test": bool(alert.operational_test),
            }
        return dict(alert)

    @staticmethod
    def _alert_identity_json(payload: dict[str, Any]) -> str:
        """Render the immutable source-event identity stored under ``alert_id``.

        ``trusted_sample`` and ``operational_test`` are deliberately excluded:
        they control trusted server-side processing, while the source evidence
        determines whether a retry is the same alert occurrence. Collector
        receipt timestamps are also excluded: they describe a delivery attempt,
        not the immutable security event. A Syslog retry otherwise changes
        ``received_at`` and is incorrectly rejected as an alert-id collision
        even when its raw evidence is equal.
        """
        evidence_payload = payload.get("payload", {})

        def scrub_transport_receipts(value: Any) -> Any:
            if isinstance(value, list):
                return [scrub_transport_receipts(item) for item in value]
            if not isinstance(value, dict):
                return value
            cleaned: dict[str, Any] = {}
            for key, item in value.items():
                if key == "syslog_received_at":
                    continue
                if (
                    key in {"_syslog_envelope", "syslog_envelope", "syslog_route"}
                    and isinstance(item, dict)
                ):
                    cleaned[key] = {
                        nested_key: scrub_transport_receipts(nested_value)
                        for nested_key, nested_value in item.items()
                        if nested_key != "received_at"
                    }
                    continue
                cleaned[key] = scrub_transport_receipts(item)
            return cleaned

        return json.dumps(
            {
                "source": str(payload.get("source") or "unknown"),
                "product": str(payload.get("product") or "unknown").lower(),
                "event_type": str(payload.get("event_type") or "unknown"),
                "severity": str(payload.get("severity") or "medium").lower(),
                "timestamp": str(payload.get("timestamp") or ""),
                "payload": scrub_transport_receipts(evidence_payload),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    def _assert_alert_identity_consistent_locked(
        self,
        alert_id: str,
        identity_json: str,
    ) -> None:
        """Fail closed when an idempotency key points at different evidence."""
        inbox = self.conn.execute(
            "SELECT raw_alert_json FROM durable_alert_inbox WHERE alert_id = ?",
            (alert_id,),
        ).fetchone()
        if inbox:
            prior_payload = json.loads(inbox["raw_alert_json"])
            if self._alert_identity_json(prior_payload) != identity_json:
                raise AlertIdentityConflict(alert_id)

        raw = self.conn.execute(
            """
            SELECT source, product, event_type, severity, timestamp, payload_json
            FROM raw_alerts WHERE alert_id = ?
            """,
            (alert_id,),
        ).fetchone()
        if raw:
            prior_payload = {
                "source": raw["source"],
                "product": raw["product"],
                "event_type": raw["event_type"],
                "severity": raw["severity"],
                "timestamp": raw["timestamp"],
                "payload": json.loads(raw["payload_json"]),
            }
            if self._alert_identity_json(prior_payload) != identity_json:
                raise AlertIdentityConflict(alert_id)

    def enqueue_alert(
        self,
        alert: RawAlert | dict[str, Any],
        max_attempts: int = 5,
        _commit: bool = True,
    ) -> bool:
        payload = self._durable_alert_payload(alert)
        alert_id = str(payload.get("alert_id") or "").strip()
        if not alert_id:
            raise ValueError("alert_id is required for durable enqueue")
        with self._lock:
            self._assert_alert_identity_consistent_locked(
                alert_id,
                self._alert_identity_json(payload),
            )
            created = now_ms()
            priority = self._alert_priority(payload.get("severity"))
            cur = self.conn.execute(
                """
                INSERT OR IGNORE INTO durable_alert_inbox
                (alert_id, raw_alert_json, source, product, priority, status, attempts, max_attempts,
                 available_at_ms, claimed_at_ms, completed_at_ms, last_error, created_at_ms, updated_at_ms)
                VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, ?, NULL, NULL, '', ?, ?)
                """,
                (
                    alert_id,
                    json.dumps(payload, ensure_ascii=False, sort_keys=True),
                    str(payload.get("source") or "unknown"),
                    str(payload.get("product") or "unknown").lower(),
                    priority,
                    max(1, int(max_attempts)),
                    created,
                    created,
                    created,
                ),
            )
            if _commit:
                self.conn.commit()
            return cur.rowcount > 0

    def enqueue_alert_bounded(
        self,
        alert: RawAlert | dict[str, Any],
        *,
        max_attempts: int = 5,
        capacity: int,
        capacity_bytes: int | None = None,
    ) -> str:
        """Atomically enforce durable-inbox capacity and idempotency.

        Returns ``inserted``, ``recovered``, ``duplicate`` or ``full``. A
        completed inbox row is only a valid duplicate while its persisted
        analysis result still exists. This lets a resubmission repair databases
        where an operator cleared fact tables but an older inbox row survived.

        Keeping the count, consistency check and insert under the repository
        transaction prevents concurrent submissions from racing the recovery.
        """
        payload = self._durable_alert_payload(alert)
        alert_id = str(payload.get("alert_id") or "").strip()
        if not alert_id:
            raise ValueError("alert_id is required for durable enqueue")
        with self.transaction():
            self._assert_alert_identity_consistent_locked(
                alert_id,
                self._alert_identity_json(payload),
            )
            existing = self.conn.execute(
                "SELECT status FROM durable_alert_inbox WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
            recover_completed = bool(
                existing
                and existing["status"] == "completed"
                and not self._completed_alert_result_exists(alert_id)
            )
            if existing and not recover_completed:
                return "duplicate"
            capacity_state = self.conn.execute(
                "SELECT unfinished_count, unfinished_bytes FROM inbox_capacity_state "
                "WHERE singleton = 1"
            ).fetchone()
            backlog = int(capacity_state["unfinished_count"] if capacity_state else 0)
            backlog_bytes = int(capacity_state["unfinished_bytes"] if capacity_state else 0)
            incoming_bytes = len(
                json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
            )
            bytes_full = (
                capacity_bytes is not None
                and backlog_bytes + incoming_bytes > max(1, int(capacity_bytes))
            )
            if backlog >= max(1, int(capacity)) or bytes_full:
                return "full"
            if recover_completed:
                available = now_ms()
                self.conn.execute(
                    """
                    UPDATE durable_alert_inbox
                    SET status = 'pending', attempts = 0, max_attempts = ?,
                        available_at_ms = ?, claimed_at_ms = NULL,
                        completed_at_ms = NULL, last_error = '', updated_at_ms = ?
                    WHERE alert_id = ? AND status = 'completed'
                    """,
                    (max(1, int(max_attempts)), available, available, alert_id),
                )
                return "recovered"
            inserted = self.enqueue_alert(
                alert,
                max_attempts=max_attempts,
                _commit=False,
            )
            return "inserted" if inserted else "duplicate"

    @staticmethod
    def _alert_priority(severity: object) -> int:
        return {
            "critical": 0,
            "high": 1,
            "medium": 2,
        }.get(str(severity or "medium").lower(), 3)

    def _completed_alert_result_exists(self, alert_id: str) -> bool:
        return bool(
            self.conn.execute(
                """
                SELECT 1
                FROM raw_alerts r
                JOIN normalized_events ne ON ne.alert_id = r.alert_id
                JOIN case_alert_links l
                  ON l.alert_id = ne.alert_id AND l.event_id = ne.event_id
                JOIN cases c ON c.case_id = l.case_id
                JOIN agent_runs ar
                  ON ar.case_id = l.case_id AND ar.event_id = ne.event_id
                WHERE r.alert_id = ?
                LIMIT 1
                """,
                (alert_id,),
            ).fetchone()
        )

    def claim_inbox_alert(
        self,
        alert_id: str | None = None,
        *,
        preferred_product: str | None = None,
    ) -> dict[str, Any] | None:
        """Atomically claim one due inbox item for a worker."""
        with self.transaction():
            now = now_ms()
            if alert_id:
                row = self.conn.execute(
                    """
                    SELECT * FROM durable_alert_inbox
                    WHERE alert_id = ? AND status IN ('pending','retry') AND available_at_ms <= ?
                    """,
                    (alert_id, now),
                ).fetchone()
            else:
                preferred = str(preferred_product or "").lower()
                row = self.conn.execute(
                    """
                    SELECT * FROM durable_alert_inbox
                    WHERE status IN ('pending','retry') AND available_at_ms <= ?
                    ORDER BY
                      CASE WHEN created_at_ms <= ? THEN 0 ELSE priority END ASC,
                      CASE WHEN product = ? THEN 0 ELSE 1 END ASC,
                      available_at_ms ASC,
                      created_at_ms ASC
                    LIMIT 1
                    """,
                    (now, now - 300_000, preferred),
                ).fetchone()
            if not row:
                return None
            cur = self.conn.execute(
                """
                UPDATE durable_alert_inbox
                SET status = 'processing', attempts = attempts + 1,
                    claimed_at_ms = ?, updated_at_ms = ?
                WHERE alert_id = ? AND status IN ('pending','retry')
                """,
                (now, now, row["alert_id"]),
            )
            if cur.rowcount != 1:
                return None
            claimed = self.conn.execute(
                "SELECT * FROM durable_alert_inbox WHERE alert_id = ?", (row["alert_id"],)
            ).fetchone()
            return self._inbox_row(claimed)

    def renew_inbox_claim(self, alert_id: str, _commit: bool = True) -> bool:
        """Extend a processing lease while a worker is actively analyzing."""
        with self._lock:
            renewed_at = now_ms()
            cur = self.conn.execute(
                """
                UPDATE durable_alert_inbox
                SET claimed_at_ms = ?, updated_at_ms = ?
                WHERE alert_id = ? AND status = 'processing'
                """,
                (renewed_at, renewed_at, alert_id),
            )
            if _commit:
                self.conn.commit()
            return cur.rowcount == 1

    def dead_letter_inbox_alert(
        self,
        alert_id: str,
        error: str,
        _commit: bool = True,
    ) -> bool:
        """Move a permanent failure directly to the durable DLQ."""
        with self._lock:
            failed_at = now_ms()
            cur = self.conn.execute(
                """
                UPDATE durable_alert_inbox
                SET status = 'dead_letter', available_at_ms = ?, claimed_at_ms = NULL,
                    last_error = ?, updated_at_ms = ?
                WHERE alert_id = ? AND status = 'processing'
                """,
                (failed_at, str(error)[:2000], failed_at, alert_id),
            )
            if _commit:
                self.conn.commit()
            return cur.rowcount == 1

    def complete_inbox_alert(self, alert_id: str, _commit: bool = True) -> bool:
        with self._lock:
            completed = now_ms()
            cur = self.conn.execute(
                """
                UPDATE durable_alert_inbox
                SET status = 'completed', completed_at_ms = ?, last_error = '', updated_at_ms = ?
                WHERE alert_id = ? AND status = 'processing'
                """,
                (completed, completed, alert_id),
            )
            if _commit:
                self.conn.commit()
            return cur.rowcount == 1

    def fail_inbox_alert(
        self,
        alert_id: str,
        error: str,
        retry_delay_ms: int = 1000,
        _commit: bool = True,
    ) -> str | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT attempts, max_attempts FROM durable_alert_inbox WHERE alert_id = ? AND status = 'processing'",
                (alert_id,),
            ).fetchone()
            if not row:
                return None
            failed_at = now_ms()
            status = "dead_letter" if int(row["attempts"]) >= int(row["max_attempts"]) else "retry"
            available_at = failed_at if status == "dead_letter" else failed_at + max(0, int(retry_delay_ms))
            self.conn.execute(
                """
                UPDATE durable_alert_inbox
                SET status = ?, available_at_ms = ?, claimed_at_ms = NULL,
                    last_error = ?, updated_at_ms = ? WHERE alert_id = ?
                """,
                (status, available_at, str(error)[:2000], failed_at, alert_id),
            )
            if _commit:
                self.conn.commit()
            return status

    def defer_inbox_alert(
        self,
        alert_id: str,
        *,
        retry_delay_ms: int,
        reason: str = "remote_llm_unavailable",
        _commit: bool = True,
    ) -> bool:
        """Return a remote-model failure to the Inbox without consuming retry budget.

        ``claim_inbox_alert`` increments ``attempts`` before an executor calls
        the model. A remote outage is not an alert-processing defect, so that
        claim must not turn into a terminal dead letter merely because the
        endpoint was unavailable for an extended period.
        """
        with self._lock:
            deferred_at = now_ms()
            normalized_reason = str(reason or "remote_llm_unavailable").strip()[:512]
            cur = self.conn.execute(
                """
                UPDATE durable_alert_inbox
                SET status = 'deferred',
                    attempts = CASE WHEN attempts > 0 THEN attempts - 1 ELSE 0 END,
                    available_at_ms = ?,
                    claimed_at_ms = NULL,
                    last_error = ?,
                    updated_at_ms = ?
                WHERE alert_id = ? AND status = 'processing'
                """,
                (
                    deferred_at + max(0, int(retry_delay_ms)),
                    f"{_LLM_DEFERRED_ERROR_PREFIX}{normalized_reason}",
                    deferred_at,
                    alert_id,
                ),
            )
            if _commit:
                self.conn.commit()
            return cur.rowcount == 1

    def release_llm_deferred_alerts(
        self,
        *,
        limit: int = 100,
        force: bool = True,
        _commit: bool = True,
    ) -> dict[str, int]:
        """Make recoverable remote-LLM work eligible for dispatch.

        This includes legacy rows that reached ``dead_letter`` before remote
        deferrals stopped consuming the durable attempt budget. Generic dead
        letters are intentionally excluded. Scheduled recovery only touches due
        ``deferred`` rows. Legacy dead letters require an explicit analyst replay
        after the model service has been repaired, preventing a stale 4xx
        credential failure from being reissued on every maintenance interval.
        """
        batch_size = max(1, min(int(limit), 500))
        with self.transaction():
            released_at = now_ms()
            rows = self.conn.execute(
                """
                SELECT alert_id, status
                FROM durable_alert_inbox
                WHERE (
                    (status = 'deferred' AND (last_error LIKE ? OR last_error LIKE ?))
                    OR (
                      status = 'dead_letter'
                      AND (
                        last_error LIKE ? OR last_error LIKE ?
                        OR last_error LIKE ? OR last_error LIKE ?
                      )
                    )
                )
                  AND (? = 1 OR (status = 'deferred' AND available_at_ms <= ?))
                ORDER BY CASE status WHEN 'dead_letter' THEN 0 ELSE 1 END,
                         available_at_ms ASC, created_at_ms ASC
                LIMIT ?
                """,
                (
                    f"{_LLM_DEFERRED_ERROR_PREFIX}%",
                    f"%{_LEGACY_LLM_DEFERRED_ERROR_FRAGMENT}%",
                    f"{_LLM_DEFERRED_ERROR_PREFIX}%",
                    f"%{_LEGACY_LLM_DEFERRED_ERROR_FRAGMENT}%",
                    f"%{_TERMINAL_LLM_ERROR_FRAGMENTS[0]}%",
                    f"%{_TERMINAL_LLM_ERROR_FRAGMENTS[1]}%",
                    1 if force else 0,
                    released_at,
                    batch_size,
                ),
            ).fetchall()
            deferred_released = 0
            dead_letter_recovered = 0
            for row in rows:
                status = str(row["status"])
                self.conn.execute(
                    """
                    UPDATE durable_alert_inbox
                    SET status = 'retry', attempts = 0, available_at_ms = ?,
                        claimed_at_ms = NULL,
                        last_error = ?, updated_at_ms = ?
                    WHERE alert_id = ? AND status = ?
                    """,
                    (
                        released_at,
                        f"{_LLM_DEFERRED_ERROR_PREFIX}recovery_dispatch",
                        released_at,
                        row["alert_id"],
                        status,
                    ),
                )
                if status == "dead_letter":
                    dead_letter_recovered += 1
                else:
                    deferred_released += 1
            return {
                "released": len(rows),
                # Keep the historical field for callers that already display it.
                "retry_released": deferred_released,
                "deferred_released": deferred_released,
                "dead_letter_recovered": dead_letter_recovered,
            }

    def recover_stale_inbox(self, stale_before_ms: int, _commit: bool = True) -> int:
        with self._lock:
            recovered_at = now_ms()
            cur = self.conn.execute(
                """
                UPDATE durable_alert_inbox
                SET status = CASE WHEN attempts >= max_attempts THEN 'dead_letter' ELSE 'retry' END,
                    available_at_ms = ?, claimed_at_ms = NULL,
                    last_error = CASE WHEN last_error = '' THEN 'worker_claim_expired' ELSE last_error END,
                    updated_at_ms = ?
                WHERE status = 'processing' AND claimed_at_ms <= ?
                """,
                (recovered_at, recovered_at, int(stale_before_ms)),
            )
            if _commit:
                self.conn.commit()
            return cur.rowcount

    def list_inbox_alerts(
        self,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        with self._lock:
            if status:
                rows = self.conn.execute(
                    "SELECT * FROM durable_alert_inbox WHERE status = ? "
                    "ORDER BY created_at_ms DESC LIMIT ? OFFSET ?",
                    (
                        status,
                        max(1, min(int(limit), 500)),
                        max(0, int(offset)),
                    ),
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM durable_alert_inbox ORDER BY created_at_ms DESC "
                    "LIMIT ? OFFSET ?",
                    (max(1, min(int(limit), 500)), max(0, int(offset))),
                ).fetchall()
            return [self._inbox_row(row) for row in rows]

    def count_inbox_alerts(self, status: str | None = None) -> int:
        with self._lock:
            if status:
                row = self.conn.execute(
                    "SELECT COUNT(*) AS count FROM durable_alert_inbox WHERE status = ?",
                    (status,),
                ).fetchone()
            else:
                row = self.conn.execute(
                    "SELECT COUNT(*) AS count FROM durable_alert_inbox"
                ).fetchone()
            return int(row["count"] if row else 0)

    def inbox_capacity_stats(self) -> dict[str, int]:
        """Return constant-time backlog usage plus oldest waiting age."""
        with self._lock:
            state = self.conn.execute(
                "SELECT unfinished_count, unfinished_bytes FROM inbox_capacity_state "
                "WHERE singleton = 1"
            ).fetchone()
            oldest = self.conn.execute(
                """
                SELECT MIN(created_at_ms) AS created_at_ms
                FROM durable_alert_inbox
                WHERE status IN ('pending','retry','deferred','processing')
                """
            ).fetchone()
            oldest_created = int((oldest["created_at_ms"] if oldest else 0) or 0)
            return {
                "unfinished_count": int(state["unfinished_count"] if state else 0),
                "unfinished_bytes": int(state["unfinished_bytes"] if state else 0),
                "oldest_age_ms": max(0, now_ms() - oldest_created) if oldest_created else 0,
            }

    def get_inbox_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM durable_alert_inbox WHERE alert_id = ?", (alert_id,)
            ).fetchone()
            return self._inbox_row(row) if row else None

    def inbox_stats(self) -> dict[str, int]:
        with self._lock:
            counts = {
                row["status"]: int(row["count"])
                for row in self.conn.execute(
                    "SELECT status, COUNT(*) AS count FROM durable_alert_inbox GROUP BY status"
                ).fetchall()
            }
            return {
                status: counts.get(status, 0)
                for status in ("pending", "retry", "deferred", "processing", "completed", "dead_letter")
            }

    def llm_deferred_inbox_stats(self) -> dict[str, int]:
        """Return the recoverable remote-LLM portion of the durable Inbox."""
        with self._lock:
            counts = {
                str(row["status"]): int(row["count"])
                for row in self.conn.execute(
                    """
                    SELECT status, COUNT(*) AS count
                    FROM durable_alert_inbox
                    WHERE status IN ('deferred', 'dead_letter')
                      AND (
                        last_error LIKE ? OR last_error LIKE ?
                        OR last_error LIKE ? OR last_error LIKE ?
                      )
                    GROUP BY status
                    """,
                    (
                        f"{_LLM_DEFERRED_ERROR_PREFIX}%",
                        f"%{_LEGACY_LLM_DEFERRED_ERROR_FRAGMENT}%",
                        f"%{_TERMINAL_LLM_ERROR_FRAGMENTS[0]}%",
                        f"%{_TERMINAL_LLM_ERROR_FRAGMENTS[1]}%",
                    ),
                ).fetchall()
            }
            deferred = counts.get("deferred", 0)
            dead_letter = counts.get("dead_letter", 0)
            return {
                "deferred": deferred,
                # Backwards-compatible zero while clients migrate to the
                # explicit durable deferral state.
                "retry": 0,
                "dead_letter": dead_letter,
                "total": deferred + dead_letter,
            }

    def purge_completed_inbox(self, before_ms: int, _commit: bool = True) -> int:
        """Remove old completed queue envelopes; persisted raw alerts are untouched."""
        with self._lock:
            cur = self.conn.execute(
                """
                DELETE FROM durable_alert_inbox
                WHERE status = 'completed' AND completed_at_ms IS NOT NULL AND completed_at_ms < ?
                """,
                (int(before_ms),),
            )
            if _commit:
                self.conn.commit()
            return cur.rowcount

    def purge_retained_history(
        self,
        *,
        data_before_ms: int | None = None,
        audit_before_ms: int | None = None,
        memory_before_ms: int | None = None,
        limit: int = 200,
    ) -> dict[str, int]:
        """Purge bounded, terminal history while preserving live governance data.

        Operational data is removed only for terminal Cases. Governance memories
        and match records retain their stable identifiers/sanitized summaries,
        but never keep raw alert payloads alive past the data window. Audit,
        memory-association and operational retention therefore remain independent.
        """
        counts = {
            "cases": 0,
            "raw_alerts": 0,
            "normalized_events": 0,
            "agent_runs": 0,
            "response_agent_sessions": 0,
            "case_response_artifacts": 0,
            "validations": 0,
            "validation_review_resolutions": 0,
            "approvals": 0,
            "response_tasks": 0,
            "response_attempts": 0,
            "memory_matches": 0,
            "audit_events": 0,
            "memory_events": 0,
            "memory_entries": 0,
            "memory_entries_expired": 0,
        }
        batch_limit = max(1, min(int(limit), 1000))
        with self.transaction():
            if audit_before_ms is not None:
                cur = self.conn.execute(
                    """
                    DELETE FROM audit_log WHERE audit_id IN (
                      SELECT a.audit_id FROM audit_log a
                      WHERE a.created_at_ms < ?
                        AND NOT EXISTS (
                          SELECT 1 FROM cases c
                          WHERE c.case_id IN (a.case_id, a.trace_id)
                            AND c.status NOT IN ('closed', 'false_positive')
                        )
                        AND NOT EXISTS (
                          SELECT 1 FROM memory_entries m
                          WHERE m.memory_id IN (a.memory_id, a.trace_id)
                            AND m.status IN ('active', 'pending_approval', 'quarantined')
                        )
                      ORDER BY a.created_at_ms ASC LIMIT ?
                    )
                    """,
                    (int(audit_before_ms), batch_limit),
                )
                counts["audit_events"] += cur.rowcount

            if memory_before_ms is not None:
                cur = self.conn.execute(
                    """
                    DELETE FROM memory_matches WHERE match_id IN (
                      SELECT match_id FROM memory_matches
                      WHERE created_at_ms < ? ORDER BY created_at_ms ASC LIMIT ?
                    )
                    """,
                    (int(memory_before_ms), batch_limit),
                )
                counts["memory_matches"] += cur.rowcount
                cur = self.conn.execute(
                    """
                    DELETE FROM memory_events WHERE event_id IN (
                      SELECT e.event_id FROM memory_events e
                      WHERE e.created_at_ms < ?
                        AND (
                          NOT EXISTS (
                            SELECT 1 FROM memory_entries m WHERE m.memory_id = e.memory_id
                          )
                          OR EXISTS (
                            SELECT 1 FROM memory_entries m
                            WHERE m.memory_id = e.memory_id
                              AND m.status IN ('expired', 'revoked')
                          )
                        )
                      ORDER BY e.created_at_ms ASC LIMIT ?
                    )
                    """,
                    (int(memory_before_ms), batch_limit),
                )
                counts["memory_events"] += cur.rowcount
                cur = self.conn.execute(
                    """
                    DELETE FROM memory_entries WHERE memory_id IN (
                      SELECT m.memory_id FROM memory_entries m
                      WHERE COALESCE(NULLIF(m.updated_at_ms, 0), m.created_at_ms) < ?
                        AND (
                          m.status IN ('expired', 'revoked')
                          OR (
                            m.status = 'pending_approval'
                            AND NOT EXISTS (
                              SELECT 1 FROM cases c
                              WHERE c.case_id = m.source_case_id
                                AND c.status NOT IN ('closed', 'false_positive')
                            )
                          )
                        )
                      ORDER BY COALESCE(NULLIF(m.updated_at_ms, 0), m.created_at_ms) ASC
                      LIMIT ?
                    )
                    """,
                    (int(memory_before_ms), batch_limit),
                )
                counts["memory_entries"] += cur.rowcount

            if data_before_ms is None:
                return counts

            candidates = self.conn.execute(
                """
                SELECT c.case_id FROM cases c
                WHERE c.status IN ('closed', 'false_positive')
                  AND COALESCE(c.closed_at_ms, c.updated_at_ms) < ?
                  AND NOT EXISTS (
                    SELECT 1 FROM response_tasks t
                    WHERE t.case_id = c.case_id
                      AND t.status NOT IN ('shadowed','failed','cancelled','rolled_back')
                  )
                ORDER BY COALESCE(c.closed_at_ms, c.updated_at_ms) ASC
                LIMIT ?
                """,
                (int(data_before_ms), batch_limit),
            ).fetchall()

            for row in candidates:
                case_id = str(row["case_id"])
                retained_at_ms = now_ms()
                expiring_memories = self.conn.execute(
                    """
                    SELECT memory_id, layer FROM memory_entries
                    WHERE source_case_id = ?
                      AND (
                        (layer = 'case_short_term' AND status = 'active')
                        OR status = 'pending_approval'
                      )
                    """,
                    (case_id,),
                ).fetchall()
                for memory in expiring_memories:
                    memory_id = str(memory["memory_id"])
                    cur = self.conn.execute(
                        """
                        UPDATE memory_entries
                        SET status = 'expired', trust_level = 'low', updated_at_ms = ?
                        WHERE memory_id = ?
                          AND (status = 'pending_approval' OR status = 'active')
                        """,
                        (retained_at_ms, memory_id),
                    )
                    if not cur.rowcount:
                        continue
                    counts["memory_entries_expired"] += cur.rowcount
                    digest = hashlib.sha256(
                        f"{memory_id}\0data-retention".encode("utf-8")
                    ).hexdigest()[:24]
                    self.conn.execute(
                        """
                        INSERT OR IGNORE INTO memory_events
                        (event_id, memory_id, layer, event_type, actor, detail_json, created_at_ms)
                        VALUES (?, ?, ?, 'expired', 'retention-maintenance', ?, ?)
                        """,
                        (
                            f"mev_{digest}",
                            memory_id,
                            str(memory["layer"]),
                            json.dumps(
                                {
                                    "reason": "operational_data_retention",
                                    "case_id": case_id,
                                },
                                ensure_ascii=False,
                                sort_keys=True,
                            ),
                            retained_at_ms,
                        ),
                    )
                links = self.conn.execute(
                    "SELECT alert_id, event_id FROM case_alert_links WHERE case_id = ?",
                    (case_id,),
                ).fetchall()
                alert_ids = {str(link["alert_id"]) for link in links}
                event_ids = {str(link["event_id"]) for link in links}

                cur = self.conn.execute(
                    "DELETE FROM response_attempts WHERE task_id IN "
                    "(SELECT task_id FROM response_tasks WHERE case_id = ?)",
                    (case_id,),
                )
                counts["response_attempts"] += cur.rowcount
                cur = self.conn.execute(
                    "DELETE FROM response_tasks WHERE case_id = ?", (case_id,)
                )
                counts["response_tasks"] += cur.rowcount
                self.conn.execute(
                    "DELETE FROM approval_votes WHERE approval_id IN "
                    "(SELECT approval_id FROM action_approvals WHERE case_id = ?)",
                    (case_id,),
                )
                cur = self.conn.execute(
                    "DELETE FROM action_approvals WHERE case_id = ?",
                    (case_id,),
                )
                counts["approvals"] += cur.rowcount
                cur = self.conn.execute(
                    "DELETE FROM validation_review_resolutions WHERE case_id = ?",
                    (case_id,),
                )
                counts["validation_review_resolutions"] += cur.rowcount
                cur = self.conn.execute(
                    "DELETE FROM validation_runs WHERE case_id = ?",
                    (case_id,),
                )
                counts["validations"] += cur.rowcount
                cur = self.conn.execute(
                    "DELETE FROM agent_runs WHERE case_id = ?",
                    (case_id,),
                )
                counts["agent_runs"] += cur.rowcount
                cur = self.conn.execute(
                    "DELETE FROM response_agent_sessions WHERE case_id = ?",
                    (case_id,),
                )
                counts["response_agent_sessions"] += cur.rowcount
                cur = self.conn.execute(
                    "DELETE FROM case_response_artifacts WHERE case_id = ?",
                    (case_id,),
                )
                counts["case_response_artifacts"] += cur.rowcount
                self.conn.execute(
                    "DELETE FROM alert_dispositions WHERE case_id = ?",
                    (case_id,),
                )
                self.conn.execute(
                    "DELETE FROM case_alert_links WHERE case_id = ?",
                    (case_id,),
                )
                cur = self.conn.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
                counts["cases"] += cur.rowcount

                for event_id in event_ids:
                    cur = self.conn.execute(
                        """
                        DELETE FROM normalized_events
                        WHERE event_id = ?
                          AND NOT EXISTS (
                            SELECT 1 FROM case_alert_links WHERE event_id = ?
                          )
                        """,
                        (event_id, event_id),
                    )
                    counts["normalized_events"] += cur.rowcount
                for alert_id in alert_ids:
                    self.conn.execute(
                        """
                        DELETE FROM durable_alert_inbox
                        WHERE alert_id = ? AND status IN ('completed', 'dead_letter')
                        """,
                        (alert_id,),
                    )
                    cur = self.conn.execute(
                        """
                        DELETE FROM raw_alerts
                        WHERE alert_id = ?
                          AND NOT EXISTS (
                            SELECT 1 FROM normalized_events WHERE alert_id = ?
                          )
                          AND NOT EXISTS (
                            SELECT 1 FROM case_alert_links WHERE alert_id = ?
                          )
                        """,
                        (alert_id, alert_id, alert_id),
                    )
                    counts["raw_alerts"] += cur.rowcount
        return counts

    @staticmethod
    def _inbox_row(row: sqlite3.Row) -> dict[str, Any]:
        payload = dict(row)
        payload["raw_alert"] = json.loads(payload.pop("raw_alert_json"))
        error = str(payload.get("last_error") or "")
        payload["analysis_deferred"] = (
            str(payload.get("status") or "") == "deferred"
            or error.startswith(_LLM_DEFERRED_ERROR_PREFIX)
            or _LEGACY_LLM_DEFERRED_ERROR_FRAGMENT in error
        )
        return payload

    def get_normalized_event(self, event_id: str) -> NormalizedEvent | None:
        """Load the immutable event persisted for an alert retry."""
        with self._lock:
            row = self.conn.execute(
                """
                SELECT event_id, alert_id, source, product, event_type, severity, timestamp,
                       entities_json, evidence_json, sensitivity_tags_json
                FROM normalized_events WHERE event_id = ?
                """,
                (event_id,),
            ).fetchone()
            if not row:
                return None
            return NormalizedEvent(
                event_id=row["event_id"],
                raw_ref=row["alert_id"],
                source=row["source"],
                product=row["product"],
                event_type=row["event_type"],
                severity=row["severity"],
                timestamp=row["timestamp"],
                entities=json.loads(row["entities_json"]),
                evidence=json.loads(row["evidence_json"]),
                sensitivity_tags=json.loads(row["sensitivity_tags_json"]),
            )

    def get_agent_result_for_event(self, event_id: str) -> dict[str, Any] | None:
        """Return the completed analysis for one immutable event, if any."""
        with self._lock:
            row = self.conn.execute(
                "SELECT result_json FROM agent_runs WHERE event_id = ? ORDER BY created_at_ms DESC LIMIT 1",
                (event_id,),
            ).fetchone()
            return json.loads(row["result_json"]) if row else None

    def query_correlated_alerts(
        self,
        event: NormalizedEvent,
        window_ms: int = 15 * 60 * 1000,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Return desensitized cross-product events sharing stable entities."""
        stable_fields = ("host", "user", "src_ip", "dst_ip", "app", "process")
        current = {
            field: self._entity_value(event.entities.get(field))
            for field in stable_fields
            if event.entities.get(field) not in (None, "")
        }
        if not current:
            return []
        event_at = self.timestamp_ms(event.timestamp)
        bounded_window = max(1, int(window_ms))
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT ne.event_id, ne.alert_id, ne.product, ne.event_type, ne.severity,
                       ne.timestamp, ne.entities_json, ne.evidence_json,
                       l.case_id
                FROM normalized_events ne
                LEFT JOIN case_alert_links l ON l.event_id = ne.event_id
                WHERE ne.event_id != ?
                  AND ne.product != ?
                  AND ne.event_at_ms BETWEEN ? AND ?
                ORDER BY ABS(ne.event_at_ms - ?) ASC, ne.event_id ASC LIMIT 2000
                """,
                (
                    event.event_id,
                    event.product,
                    event_at - bounded_window,
                    event_at + bounded_window,
                    event_at,
                ),
            ).fetchall()
        matches: list[dict[str, Any]] = []
        current_network = {current.get("src_ip"), current.get("dst_ip")} - {None, ""}
        for row in rows:
            delta = abs(event_at - self.timestamp_ms(str(row["timestamp"])))
            if delta > bounded_window:
                continue
            entities = json.loads(row["entities_json"])
            matched: list[dict[str, str]] = []
            for field in ("host", "user", "app", "process"):
                value = self._entity_value(entities.get(field))
                if value and value == current.get(field):
                    matched.append({"field": field, "value": value})
            other_network = {
                self._entity_value(entities.get("src_ip")),
                self._entity_value(entities.get("dst_ip")),
            } - {None, ""}
            for value in sorted(current_network & other_network):
                matched.append({"field": "network_entity", "value": value})
            if not matched:
                continue
            evidence = json.loads(row["evidence_json"])
            matches.append(
                {
                    "event_id": row["event_id"],
                    "alert_id": row["alert_id"],
                    "case_id": row["case_id"] or "",
                    "product": row["product"],
                    "event_type": row["event_type"],
                    "severity": row["severity"],
                    "timestamp": row["timestamp"],
                    "time_delta_ms": delta,
                    "matched_entities": matched[:8],
                    "evidence_refs": [
                        {"ref": item.get("ref"), "type": item.get("type"), "source": item.get("source")}
                        for item in evidence[:8]
                        if isinstance(item, dict) and item.get("ref")
                    ],
                }
            )
        matches.sort(key=lambda item: (item["time_delta_ms"], item["timestamp"], item["event_id"]))
        return matches[: max(1, min(int(limit), 100))]

    @staticmethod
    def _response_agent_canonical_field(value: Any) -> str:
        source = re.sub(
            r"([a-z0-9])([A-Z])",
            r"\1_\2",
            str(value or "").strip(),
        )
        rendered = "".join(
            character.lower() if character.isalnum() else "_"
            for character in source
        )
        while "__" in rendered:
            rendered = rendered.replace("__", "_")
        return rendered.strip("_")

    @classmethod
    def _response_agent_collect_values(
        cls,
        value: Any,
        *,
        max_nodes: int = 10_000,
        _decode_syslog_envelopes: bool = True,
        _raw_payload: bool = False,
    ) -> dict[str, set[str]]:
        """Extract correlation values without traversing attacker-controlled bodies."""
        result = {field: set() for field in _RESPONSE_AGENT_CORRELATION_FIELDS}
        if _raw_payload:
            allowed_paths = _RESPONSE_AGENT_RAW_CORRELATION_PATHS
            allowed_prefixes = _RESPONSE_AGENT_RAW_CORRELATION_PREFIXES
        else:
            allowed_paths = {
                (alias,): field
                for alias, field in _RESPONSE_AGENT_CORRELATION_ALIASES.items()
            }
            allowed_prefixes: set[tuple[str, ...]] = set()
        stack: list[tuple[Any, tuple[str, ...]]] = [(value, ())]
        visited = 0
        while stack and visited < max(1, int(max_nodes)):
            item, path = stack.pop()
            visited += 1
            if not isinstance(item, dict):
                continue
            for key, nested in reversed(list(item.items())[:2_000]):
                canonical = cls._response_agent_canonical_field(key)
                nested_path = (*path, canonical)
                field = allowed_paths.get(nested_path)
                if field and not isinstance(nested, (dict, list)):
                    rendered = cls._entity_value(nested)
                    if field in {"src_ip", "dst_ip"} and rendered:
                        try:
                            rendered = str(ipaddress.ip_address(rendered))
                        except ValueError:
                            rendered = ""
                    if (
                        rendered
                        and rendered != "[redacted]"
                        and 2 <= len(rendered) <= 256
                        and len(result[field]) < 128
                    ):
                        result[field].add(rendered)
                if nested_path in allowed_prefixes and isinstance(nested, dict):
                    stack.append((nested, nested_path))
        if _decode_syslog_envelopes and isinstance(value, dict):
            records = cls._response_agent_syslog_records(value)
            decoded_budget = max(1, int(max_nodes) // max(1, len(records)))
            for descriptor, decoded in records:
                if (
                    descriptor["syslog_message_integrity"] == "mismatch"
                    or not isinstance(decoded, dict)
                ):
                    continue
                cls._merge_response_agent_values(
                    result,
                    cls._response_agent_collect_values(
                        decoded,
                        max_nodes=decoded_budget,
                        _decode_syslog_envelopes=False,
                        _raw_payload=True,
                    ),
                )
        return result

    @staticmethod
    def _merge_response_agent_values(
        target: dict[str, set[str]], source: dict[str, set[str]]
    ) -> None:
        for field in _RESPONSE_AGENT_CORRELATION_FIELDS:
            target.setdefault(field, set()).update(
                list(source.get(field) or set())[:128]
            )
            if len(target[field]) > 128:
                target[field] = set(sorted(target[field])[:128])

    @staticmethod
    def _response_agent_json_type(value: Any) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, (int, float)):
            return "number"
        if isinstance(value, str):
            return "string"
        if isinstance(value, list):
            return "array"
        if isinstance(value, dict):
            return "object"
        return "unknown"

    @classmethod
    def _response_agent_json_catalog(
        cls,
        value: Any,
        *,
        max_entries: int = 120,
        max_depth: int = 3,
        include_sizes: bool = True,
    ) -> list[dict[str, Any]]:
        """Build a value-free JSON Pointer catalog for targeted raw-log reads."""
        entries: list[dict[str, Any]] = []
        stack: list[tuple[str, Any, int]] = [("", value, 0)]
        while stack and len(entries) < max(1, int(max_entries)):
            pointer, item, depth = stack.pop()
            if pointer:
                byte_size = None
                if include_sizes and (
                    depth <= 1 or not isinstance(item, (dict, list))
                ):
                    byte_size = len(
                        json.dumps(
                            item,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    )
                entries.append(
                    {
                        "json_pointer": pointer,
                        "type": cls._response_agent_json_type(item),
                        "bytes": byte_size,
                        "items": (
                            len(item) if isinstance(item, (dict, list)) else None
                        ),
                    }
                )
            if depth >= max_depth:
                continue
            children: list[tuple[str, Any]] = []
            if isinstance(item, dict):
                for key in sorted(item, key=str)[:200]:
                    escaped = str(key).replace("~", "~0").replace("/", "~1")
                    child_pointer = f"{pointer}/{escaped}" if pointer else f"/{escaped}"
                    children.append((child_pointer, item[key]))
            elif isinstance(item, list):
                for index, nested in enumerate(item[:50]):
                    child_pointer = f"{pointer}/{index}" if pointer else f"/{index}"
                    children.append((child_pointer, nested))
            stack.extend(
                (child_pointer, nested, depth + 1)
                for child_pointer, nested in reversed(children)
            )
        return entries

    def _response_agent_scope_locked(self, case_id: str) -> dict[str, Any] | None:
        case_row = self.conn.execute(
            """
            SELECT case_id, product, created_at_ms, updated_at_ms, last_alert_at_ms
            FROM cases WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()
        if not case_row:
            return None
        rows = self.conn.execute(
            """
            SELECT l.alert_id, l.event_id, l.created_at_ms AS linked_at_ms,
                   ne.event_at_ms, ne.entities_json,
                   ra.payload_json, ra.created_at_ms AS raw_created_at_ms
            FROM case_alert_links l
            LEFT JOIN normalized_events ne ON ne.event_id = l.event_id
            LEFT JOIN raw_alerts ra ON ra.alert_id = l.alert_id
            WHERE l.case_id = ?
            ORDER BY l.created_at_ms ASC, l.alert_id ASC, l.event_id ASC
            """,
            (case_id,),
        ).fetchall()
        values = {field: set() for field in _RESPONSE_AGENT_CORRELATION_FIELDS}
        event_times: list[int] = []
        created_times: list[int] = []
        linked_alert_ids: set[str] = set()
        event_ids: set[str] = set()
        for row in rows:
            linked_alert_ids.add(str(row["alert_id"]))
            event_ids.add(str(row["event_id"]))
            event_at_ms = int(row["event_at_ms"] or 0)
            if event_at_ms > 0:
                event_times.append(event_at_ms)
            raw_created_at_ms = int(row["raw_created_at_ms"] or row["linked_at_ms"] or 0)
            if raw_created_at_ms > 0:
                created_times.append(raw_created_at_ms)
            if row["entities_json"]:
                self._merge_response_agent_values(
                    values,
                    self._response_agent_collect_values(
                        json.loads(row["entities_json"]),
                        max_nodes=2_000,
                    ),
                )
            if row["payload_json"]:
                self._merge_response_agent_values(
                    values,
                    self._response_agent_collect_values(
                        json.loads(row["payload_json"]),
                        _raw_payload=True,
                    ),
                )
        fallback = int(
            case_row["last_alert_at_ms"]
            or case_row["updated_at_ms"]
            or case_row["created_at_ms"]
            or now_ms()
        )
        return {
            "case_id": str(case_row["case_id"]),
            "product": str(case_row["product"]),
            "linked_alert_ids": linked_alert_ids,
            "event_ids": event_ids,
            "values": values,
            "event_min_ms": min(event_times) if event_times else fallback,
            "event_max_ms": max(event_times) if event_times else fallback,
            "created_min_ms": min(created_times) if created_times else fallback,
            "created_max_ms": max(created_times) if created_times else fallback,
        }

    @classmethod
    def _response_agent_match_candidate(
        cls,
        scope: dict[str, Any],
        row: dict[str, Any],
    ) -> tuple[list[dict[str, str]], int]:
        candidate_values = {
            field: set() for field in _RESPONSE_AGENT_CORRELATION_FIELDS
        }
        if row.get("entities_json"):
            cls._merge_response_agent_values(
                candidate_values,
                cls._response_agent_collect_values(
                    json.loads(row["entities_json"]),
                    max_nodes=2_000,
                ),
            )
        if row.get("payload_json"):
            cls._merge_response_agent_values(
                candidate_values,
                cls._response_agent_collect_values(
                    json.loads(row["payload_json"]),
                    _raw_payload=True,
                ),
            )

        matched: list[dict[str, str]] = []
        anchor_values = scope["values"]
        for field in (
            "src_ip",
            "dst_ip",
            "trace_id",
            "request_id",
            "host",
            "user",
            "app",
            "process",
            "rule",
            "url",
        ):
            shared = set(anchor_values.get(field) or set()) & set(
                candidate_values.get(field) or set()
            )
            for value in sorted(shared)[:4]:
                matched.append({"field": field, "value": value})
        score = sum(
            _RESPONSE_AGENT_CORRELATION_WEIGHTS.get(item["field"], 1)
            for item in matched
        )
        return matched[:16], score

    @staticmethod
    def _response_agent_raw_hash(row: dict[str, Any]) -> str:
        encoded = json.dumps(
            {
                "alert_id": row.get("alert_id"),
                "source": row.get("source"),
                "product": row.get("product"),
                "event_type": row.get("event_type"),
                "severity": row.get("severity"),
                "timestamp": row.get("timestamp"),
                "payload": json.loads(row.get("payload_json") or "{}"),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _response_agent_path_value(
        payload: Any,
        paths: tuple[tuple[str, tuple[str, ...]], ...],
    ) -> tuple[bool, str, Any]:
        for pointer, keys in paths:
            current = payload
            found = True
            for key in keys:
                if not isinstance(current, dict) or key not in current:
                    found = False
                    break
                current = current[key]
            if found:
                return True, pointer, current
        return False, "", None

    @staticmethod
    def _response_agent_capture_state(found: bool, value: Any) -> str:
        if not found:
            return "not_observed"
        if value is None:
            return "captured_null"
        if value == [] or value == {}:
            return "captured_empty"
        if isinstance(value, str):
            rendered = value.strip()
            if not rendered:
                return "captured_empty"
            if len(rendered) <= 64_000 and rendered[:1] in {'"', "{", "[", "n"}:
                try:
                    decoded = json.loads(rendered)
                except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
                    decoded = value
                if decoded is None:
                    return "captured_null"
                if decoded == "" or decoded == [] or decoded == {}:
                    return "captured_empty"
        return "captured_nonempty"

    @classmethod
    def _response_agent_request_payload_diagnostic(
        cls,
        payload: Any,
        diagnostics: list[dict[str, Any]],
    ) -> dict[str, Any]:
        by_field = {
            str(item.get("field") or ""): item
            for item in diagnostics
            if isinstance(item, dict)
        }
        body = by_field.get("http_request_body") or {}
        parameters = by_field.get("http_request_parameters") or {}
        body_state = str(body.get("state") or "not_observed")
        parameter_state = str(parameters.get("state") or "not_observed")

        _method_found, _method_pointer, method_value = (
            cls._response_agent_path_value(
                payload,
                (
                    (
                        "/original_log/event/request_message/method",
                        ("original_log", "event", "request_message", "method"),
                    ),
                    (
                        "/original_log/http/request/method",
                        ("original_log", "http", "request", "method"),
                    ),
                    (
                        "/original_log/http/method",
                        ("original_log", "http", "method"),
                    ),
                    (
                        "/event/request_message/method",
                        ("event", "request_message", "method"),
                    ),
                    ("/http/request/method", ("http", "request", "method")),
                    ("/http/method", ("http", "method")),
                    ("/request/method", ("request", "method")),
                    ("/request_message/method", ("request_message", "method")),
                    ("/method", ("method",)),
                    ("/http_method", ("http_method",)),
                ),
            )
        )
        method = str(method_value or "").strip().upper()
        url_found, _url_pointer, url_value = cls._response_agent_path_value(
            payload,
            (
                (
                    "/original_log/event/request_message/url",
                    ("original_log", "event", "request_message", "url"),
                ),
                (
                    "/original_log/http/request/url",
                    ("original_log", "http", "request", "url"),
                ),
                (
                    "/original_log/http/request/uri",
                    ("original_log", "http", "request", "uri"),
                ),
                (
                    "/original_log/http/uri",
                    ("original_log", "http", "uri"),
                ),
                (
                    "/original_log/url/original",
                    ("original_log", "url", "original"),
                ),
                (
                    "/event/request_message/url",
                    ("event", "request_message", "url"),
                ),
                ("/http/request/url", ("http", "request", "url")),
                ("/http/request/uri", ("http", "request", "uri")),
                ("/http/uri", ("http", "uri")),
                ("/request/url", ("request", "url")),
                ("/request/uri", ("request", "uri")),
                ("/url/original", ("url", "original")),
                ("/request_message/url", ("request_message", "url")),
                ("/url", ("url",)),
                ("/uri", ("uri",)),
            ),
        )
        rendered_url = str(url_value or "").strip()
        url_observed = bool(url_found and rendered_url)
        try:
            query_present = bool(urlsplit(rendered_url).query) if url_observed else False
        except ValueError:
            query_present = "?" in rendered_url

        _headers_found, _headers_pointer, headers_value = (
            cls._response_agent_path_value(
                payload,
                (
                    (
                        "/original_log/event/request_message/header",
                        ("original_log", "event", "request_message", "header"),
                    ),
                    (
                        "/original_log/event/request_message/headers",
                        ("original_log", "event", "request_message", "headers"),
                    ),
                    (
                        "/original_log/http/request/headers",
                        ("original_log", "http", "request", "headers"),
                    ),
                    (
                        "/event/request_message/header",
                        ("event", "request_message", "header"),
                    ),
                    (
                        "/event/request_message/headers",
                        ("event", "request_message", "headers"),
                    ),
                    ("/http/request/headers", ("http", "request", "headers")),
                    ("/request/headers", ("request", "headers")),
                    ("/request_headers", ("request_headers",)),
                    ("/headers", ("headers",)),
                ),
            )
        )
        normalized_headers = {
            str(key).strip().casefold().replace("_", "-"): value
            for key, value in (
                headers_value.items() if isinstance(headers_value, dict) else ()
            )
        }
        content_length: int | None = None
        content_length_invalid = False
        content_length_present = "content-length" in normalized_headers
        raw_content_length = normalized_headers.get("content-length")
        rendered_content_length = (
            str(raw_content_length).strip()
            if raw_content_length is not None
            and not isinstance(raw_content_length, bool)
            else ""
        )
        if (
            content_length_present
            and rendered_content_length.isdigit()
            and len(rendered_content_length) <= 20
        ):
            content_length = int(rendered_content_length)
            if content_length > 9_223_372_036_854_775_807:
                content_length = None
                content_length_invalid = True
        elif content_length_present:
            content_length_invalid = True
        if (
            not content_length_present
            and body.get("metadata_only")
            and body.get("declared_bytes") is not None
        ):
            try:
                content_length = int(body["declared_bytes"])
            except (TypeError, ValueError, OverflowError):
                content_length = None
                content_length_invalid = True
            content_length_present = True
        transfer_encoding = str(
            normalized_headers.get("transfer-encoding") or ""
        ).strip()

        body_nonempty = body_state == "captured_nonempty"
        parameters_nonempty = parameter_state == "captured_nonempty"
        declared_body = bool(transfer_encoding) or (
            content_length is not None and content_length > 0
        )

        if content_length_invalid:
            state = "captured_incomplete"
            reason = "invalid_content_length"
        elif declared_body and not body_nonempty:
            state = "captured_incomplete"
            reason = "declared_request_body_missing"
        elif content_length == 0 and body_nonempty:
            state = "captured_incomplete"
            reason = "content_length_body_conflict"
        elif body_nonempty or parameters_nonempty:
            state = "captured_nonempty"
            reason = "request_content_present"
        elif query_present:
            state = "captured_nonempty"
            reason = "query_string_present"
        elif content_length == 0 and not transfer_encoding:
            state = "captured_empty"
            reason = "content_length_zero"
        elif method in {"GET", "HEAD"} and url_observed:
            state = "captured_empty"
            reason = "method_without_body_or_query"
        elif method in {"GET", "HEAD"}:
            state = "captured_incomplete"
            reason = "request_target_not_observed"
        elif (
            body_state == "captured_empty"
            and parameter_state == "captured_empty"
        ):
            state = "captured_empty"
            reason = "captured_empty_fields"
        elif (
            body_state == "not_observed"
            and parameter_state == "not_observed"
        ):
            state = "not_observed"
            reason = "request_payload_not_observed"
        else:
            state = "captured_incomplete"
            reason = "request_payload_fields_empty_or_null"

        item: dict[str, Any] = {
            "field": "http_request_payload",
            "state": state,
            "json_pointer": "",
            "bytes": int(body.get("bytes") or 0)
            + int(parameters.get("bytes") or 0),
            "method": method,
            "url_observed": url_observed,
            "query_present": query_present,
            "reason": reason,
        }
        if content_length is not None:
            item["content_length"] = content_length
        if content_length_present:
            item["content_length_state"] = (
                "invalid" if content_length_invalid else "captured"
            )
        return item

    @staticmethod
    def _response_agent_http_status(value: Any) -> str:
        if isinstance(value, bool):
            return ""
        if isinstance(value, int):
            status = value
        elif isinstance(value, float) and value.is_integer():
            status = int(value)
        elif isinstance(value, str):
            matched = re.fullmatch(
                r"\s*([1-5]\d{2})(?:\s+[^\r\n]{1,128})?\s*",
                value,
            )
            if not matched:
                return ""
            status = int(matched.group(1))
        else:
            return ""
        return str(status) if 100 <= status <= 599 else ""

    @classmethod
    def _response_agent_has_http_context(cls, payload: Any) -> bool:
        found, _pointer, _value = cls._response_agent_path_value(
            payload,
            (
                ("/original_log/http", ("original_log", "http")),
                (
                    "/original_log/event/request_message",
                    ("original_log", "event", "request_message"),
                ),
                (
                    "/original_log/event/response_message",
                    ("original_log", "event", "response_message"),
                ),
                ("/http", ("http",)),
                ("/request_message", ("request_message",)),
                ("/response_message", ("response_message",)),
                ("/http_method", ("http_method",)),
            ),
        )
        if found:
            return True
        if isinstance(payload, dict):
            top_level = {
                cls._response_agent_canonical_field(key): value
                for key, value in payload.items()
            }
            method = str(top_level.get("method") or "").strip().upper()
            if method in _RESPONSE_AGENT_HTTP_METHODS and set(top_level).intersection(
                {
                    "headers",
                    "request_body",
                    "request_parameters",
                    "uri",
                    "url",
                }
            ):
                return True
        request = payload.get("request") if isinstance(payload, dict) else None
        if not isinstance(request, dict):
            return False
        for key, value in request.items():
            field = cls._response_agent_canonical_field(key)
            if field == "method":
                if str(value or "").strip().upper() in _RESPONSE_AGENT_HTTP_METHODS:
                    return True
                continue
            if field in {
                "body",
                "headers",
                "parameter",
                "parameters",
                "query",
                "uri",
                "url",
            }:
                return True
        return False

    @classmethod
    def _response_agent_http_body_metadata(
        cls,
        value: Any,
    ) -> tuple[bool, int | None]:
        if not isinstance(value, dict) or not value:
            return False, None
        metadata_fields = {
            "bytes",
            "content_length",
            "hash",
            "length",
            "sha256",
            "size",
            "truncated",
        }
        canonical_values = {
            cls._response_agent_canonical_field(key): item
            for key, item in value.items()
        }
        fields = set(canonical_values)
        if not fields or not fields.issubset(metadata_fields):
            return False, None
        declared_bytes: int | None = None
        for name in ("bytes", "size", "length", "content_length"):
            raw = canonical_values.get(name)
            if isinstance(raw, bool):
                continue
            try:
                candidate = int(raw)
            except (TypeError, ValueError, OverflowError):
                continue
            if candidate >= 0:
                declared_bytes = candidate
                break
        return True, declared_bytes

    @classmethod
    def _response_agent_http_status_candidate(
        cls,
        payload: Any,
        paths: tuple[tuple[str, tuple[str, ...]], ...],
    ) -> tuple[bool, str, Any, str]:
        fallback: tuple[bool, str, Any] = (False, "", None)
        has_http_context = cls._response_agent_has_http_context(payload)
        for pointer, keys in paths:
            found, _matched_pointer, value = cls._response_agent_path_value(
                payload,
                ((pointer, keys),),
            )
            if not found:
                continue
            if (
                pointer
                in {
                    "/status",
                    "/status_code",
                    "/response_code",
                    "/response_status",
                }
                and not has_http_context
            ):
                continue
            observed_status = cls._response_agent_http_status(value)
            if observed_status:
                return True, pointer, value, observed_status
            if not fallback[0]:
                fallback = (True, pointer, value)
        return (*fallback, "")

    @classmethod
    def _response_agent_capture_diagnostics(
        cls,
        payload: Any,
    ) -> list[dict[str, Any]]:
        fields = (
            (
                "http_request_body",
                (
                    (
                        "/original_log/event/request_message/body",
                        ("original_log", "event", "request_message", "body"),
                    ),
                    (
                        "/original_log/http/request/body/content",
                        ("original_log", "http", "request", "body", "content"),
                    ),
                    (
                        "/original_log/http/request/body",
                        ("original_log", "http", "request", "body"),
                    ),
                    (
                        "/event/request_message/body",
                        ("event", "request_message", "body"),
                    ),
                    (
                        "/http/request/body/content",
                        ("http", "request", "body", "content"),
                    ),
                    ("/http/request/body", ("http", "request", "body")),
                    ("/request/body", ("request", "body")),
                    ("/request_message/body", ("request_message", "body")),
                    ("/request_body", ("request_body",)),
                    ("/payload/request_body", ("payload", "request_body")),
                ),
            ),
            (
                "http_request_parameters",
                (
                    (
                        "/original_log/event/request_message/parameter",
                        ("original_log", "event", "request_message", "parameter"),
                    ),
                    (
                        "/original_log/http/request/parameters",
                        ("original_log", "http", "request", "parameters"),
                    ),
                    (
                        "/original_log/http/request/query",
                        ("original_log", "http", "request", "query"),
                    ),
                    (
                        "/original_log/url/query",
                        ("original_log", "url", "query"),
                    ),
                    (
                        "/event/request_message/parameter",
                        ("event", "request_message", "parameter"),
                    ),
                    (
                        "/request_message/parameter",
                        ("request_message", "parameter"),
                    ),
                    (
                        "/http/request/parameters",
                        ("http", "request", "parameters"),
                    ),
                    ("/http/request/query", ("http", "request", "query")),
                    ("/request/parameters", ("request", "parameters")),
                    ("/request/query", ("request", "query")),
                    ("/url/query", ("url", "query")),
                    ("/request_parameters", ("request_parameters",)),
                    ("/query", ("query",)),
                ),
            ),
            (
                "http_request_headers",
                (
                    (
                        "/original_log/event/request_message/header",
                        ("original_log", "event", "request_message", "header"),
                    ),
                    (
                        "/original_log/event/request_message/headers",
                        ("original_log", "event", "request_message", "headers"),
                    ),
                    (
                        "/original_log/http/request/headers",
                        ("original_log", "http", "request", "headers"),
                    ),
                    (
                        "/event/request_message/header",
                        ("event", "request_message", "header"),
                    ),
                    (
                        "/event/request_message/headers",
                        ("event", "request_message", "headers"),
                    ),
                    ("/http/request/headers", ("http", "request", "headers")),
                    ("/request/headers", ("request", "headers")),
                    ("/request_headers", ("request_headers",)),
                    ("/headers", ("headers",)),
                ),
            ),
            (
                "http_response_status",
                (
                    (
                        "/original_log/event/response_message/status_code",
                        (
                            "original_log",
                            "event",
                            "response_message",
                            "status_code",
                        ),
                    ),
                    (
                        "/event/response_message/status_code",
                        ("event", "response_message", "status_code"),
                    ),
                    (
                        "/original_log/http/response/status_code",
                        ("original_log", "http", "response", "status_code"),
                    ),
                    (
                        "/original_log/http/status",
                        ("original_log", "http", "status"),
                    ),
                    (
                        "/original_log/response/status_code",
                        ("original_log", "response", "status_code"),
                    ),
                    (
                        "/response_message/status_code",
                        ("response_message", "status_code"),
                    ),
                    (
                        "/http/response/status_code",
                        ("http", "response", "status_code"),
                    ),
                    ("/http/status", ("http", "status")),
                    ("/response/status_code", ("response", "status_code")),
                    ("/response_status", ("response_status",)),
                    ("/response_code", ("response_code",)),
                    ("/status_code", ("status_code",)),
                    ("/status", ("status",)),
                ),
            ),
            (
                "http_response_body",
                (
                    (
                        "/original_log/event/response_message/body",
                        ("original_log", "event", "response_message", "body"),
                    ),
                    (
                        "/original_log/http/response/body/content",
                        ("original_log", "http", "response", "body", "content"),
                    ),
                    (
                        "/original_log/http/response/body",
                        ("original_log", "http", "response", "body"),
                    ),
                    (
                        "/event/response_message/body",
                        ("event", "response_message", "body"),
                    ),
                    (
                        "/http/response/body/content",
                        ("http", "response", "body", "content"),
                    ),
                    ("/http/response/body", ("http", "response", "body")),
                    ("/response/body", ("response", "body")),
                    ("/response_message/body", ("response_message", "body")),
                    ("/response_body", ("response_body",)),
                ),
            ),
        )
        diagnostics: list[dict[str, Any]] = []
        for field, paths in fields:
            observed_status = ""
            body_metadata_only = False
            declared_body_bytes: int | None = None
            if field == "http_response_status":
                (
                    found,
                    pointer,
                    value,
                    observed_status,
                ) = cls._response_agent_http_status_candidate(payload, paths)
            else:
                found, pointer, value = cls._response_agent_path_value(payload, paths)
                if field in {"http_request_body", "http_response_body"} and found:
                    (
                        body_metadata_only,
                        declared_body_bytes,
                    ) = cls._response_agent_http_body_metadata(value)
            rendered = (
                json.dumps(
                    value,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                if found
                else ""
            )
            item: dict[str, Any] = {
                "field": field,
                "state": cls._response_agent_capture_state(found, value),
                "json_pointer": pointer,
                "bytes": len(rendered.encode("utf-8")) if found else 0,
            }
            if body_metadata_only:
                item["state"] = (
                    "captured_empty"
                    if declared_body_bytes == 0
                    else "captured_incomplete"
                )
                item["metadata_only"] = True
                item["bytes"] = 0
                if declared_body_bytes is not None:
                    item["declared_bytes"] = declared_body_bytes
            if (
                field == "http_response_status"
                and item["state"] == "captured_nonempty"
            ):
                if observed_status:
                    item["observed_value"] = observed_status
                else:
                    item["state"] = "captured_invalid"
            diagnostics.append(item)
        diagnostics.append(
            cls._response_agent_request_payload_diagnostic(
                payload,
                diagnostics,
            )
        )
        return diagnostics

    @staticmethod
    def _response_agent_decode_syslog_message(
        raw_message: str,
    ) -> tuple[dict[str, Any] | None, str]:
        encoded = raw_message.encode("utf-8")
        if len(encoded) > 10_000_000:
            return None, "too_large"
        text = raw_message.strip()
        if not text:
            return None, "empty"
        try:
            decoded = loads_bounded_json(text)
        except (TypeError, ValueError, RecursionError):
            decoded = None
        if isinstance(decoded, dict):
            return decoded, "decoded_json"
        start = text.find("{")
        end = text.rfind("}")
        if 0 <= start < end:
            try:
                decoded = loads_bounded_json(text[start : end + 1])
            except (TypeError, ValueError, RecursionError):
                decoded = None
            if isinstance(decoded, dict):
                return decoded, "decoded_embedded_json"
        return None, "not_decodable_as_object"

    @classmethod
    def _response_agent_syslog_records(
        cls,
        payload: Any,
    ) -> list[tuple[dict[str, Any], dict[str, Any] | None]]:
        records: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
        seen: set[tuple[str, str, str]] = set()
        for pointer, keys in _RESPONSE_AGENT_SYSLOG_ENVELOPE_PATHS:
            found, _matched_pointer, envelope = cls._response_agent_path_value(
                payload,
                ((pointer, keys),),
            )
            if not found or not isinstance(envelope, dict):
                continue
            raw_message = envelope.get("raw_message")
            if not isinstance(raw_message, str):
                continue
            encoded = raw_message.encode("utf-8")
            computed_hash = hashlib.sha256(encoded).hexdigest()
            wire_hash = (
                str(envelope.get("raw_message_sha256") or "").strip().casefold()
            )
            text_hash = (
                str(envelope.get("raw_message_text_sha256") or "")
                .strip()
                .casefold()
            )
            # New envelopes authenticate the persisted text separately from the
            # original wire bytes. Legacy envelopes used one digest for both and
            # remain verifiable whenever their raw bytes were valid UTF-8.
            recorded_hash = text_hash or wire_hash
            try:
                recorded_wire_bytes = int(envelope.get("raw_message_bytes") or 0)
            except (TypeError, ValueError, OverflowError):
                recorded_wire_bytes = 0
            legacy_lossy = bool(
                not text_hash
                and wire_hash
                and wire_hash != computed_hash
                and "\ufffd" in raw_message
                and recorded_wire_bytes > 0
                and recorded_wire_bytes != len(encoded)
            )
            if recorded_hash and recorded_hash == computed_hash:
                integrity = "verified"
                integrity_reason = (
                    "persisted_text_hash_verified"
                    if text_hash
                    else "legacy_wire_hash_matches_utf8_text"
                )
            elif legacy_lossy:
                integrity = "unverified"
                integrity_reason = "legacy_lossy_utf8"
            elif recorded_hash:
                integrity = "mismatch"
                integrity_reason = (
                    "persisted_text_hash_mismatch"
                    if text_hash
                    else "legacy_wire_hash_mismatch"
                )
            else:
                integrity = "unverified"
                integrity_reason = "hash_not_recorded"
            identity = (computed_hash, recorded_hash, wire_hash)
            if identity in seen:
                continue
            seen.add(identity)
            decoded, decode_status = cls._response_agent_decode_syslog_message(
                raw_message
            )
            try:
                destination_port = int(envelope.get("destination_port") or 0)
            except (TypeError, ValueError, OverflowError):
                destination_port = 0
            records.append(
                (
                    {
                        "syslog_message_present": True,
                        "syslog_message_pointer": f"{pointer}/raw_message",
                        "syslog_message_bytes": len(encoded),
                        "syslog_message_sha256": computed_hash,
                        "syslog_recorded_sha256": recorded_hash,
                        "syslog_message_integrity": integrity,
                        "syslog_message_integrity_reason": integrity_reason,
                        "syslog_message_decode_status": decode_status,
                        "syslog_protocol": str(envelope.get("protocol") or ""),
                        "syslog_destination_port": destination_port,
                    },
                    decoded,
                )
            )
        return records

    @classmethod
    def _response_agent_syslog_record(
        cls,
        payload: Any,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        records = cls._response_agent_syslog_records(payload)
        if records:
            integrity_rank = {"mismatch": 0, "unverified": 1, "verified": 2}
            return max(
                records,
                key=lambda record: (
                    integrity_rank.get(
                        str(record[0].get("syslog_message_integrity") or ""),
                        -1,
                    ),
                    isinstance(record[1], dict),
                ),
            )
        return (
            {
                "syslog_message_present": False,
                "syslog_message_pointer": "",
                "syslog_message_bytes": 0,
                "syslog_message_sha256": "",
                "syslog_recorded_sha256": "",
                "syslog_message_integrity": "not_observed",
                "syslog_message_integrity_reason": "not_observed",
                "syslog_message_decode_status": "not_observed",
                "syslog_protocol": "",
                "syslog_destination_port": 0,
            },
            None,
        )

    @classmethod
    def _response_agent_syslog_descriptor(
        cls,
        payload: Any,
    ) -> dict[str, Any]:
        descriptor, _decoded = cls._response_agent_syslog_record(payload)
        return descriptor

    @classmethod
    def _response_agent_mapped_projection(cls, payload: Any) -> Any:
        if not isinstance(payload, dict):
            return payload
        original_log = payload.get("original_log")
        adapted = isinstance(payload.get("adapter"), dict)
        projection: dict[str, Any] = {}
        for key, value in payload.items():
            if str(key).casefold() in SERVER_OWNED_ALERT_PAYLOAD_FIELDS:
                continue
            if (
                adapted
                and isinstance(original_log, dict)
                and key in original_log
                and value == original_log[key]
            ):
                # Non-RASP adapters retain a top-level copy of the vendor log.
                # It is raw evidence, not proof that a profile mapped the field.
                continue
            projection[key] = value
        mapped_entities = payload.get("mapped_entities")
        if isinstance(mapped_entities, dict):
            for key, value in mapped_entities.items():
                projection.setdefault(str(key), value)
        return projection

    @staticmethod
    def _response_agent_diagnostics_by_field(
        diagnostics: list[dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        return {
            str(item.get("field") or ""): item
            for item in diagnostics
            if isinstance(item, dict)
        }

    @staticmethod
    def _response_agent_original_pointer(pointer: Any) -> str:
        rendered = str(pointer or "")
        return f"/original_log{rendered}" if rendered else ""

    @classmethod
    def _response_agent_capture_layers(
        cls,
        payload: Any,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, str]]]:
        descriptor, raw_payload = cls._response_agent_syslog_record(payload)
        mapped_payload = cls._response_agent_mapped_projection(payload)
        original_payload = (
            payload.get("original_log") if isinstance(payload, dict) else None
        )
        mapped_by_field = cls._response_agent_diagnostics_by_field(
            cls._response_agent_capture_diagnostics(mapped_payload)
        )
        original_by_field = cls._response_agent_diagnostics_by_field(
            cls._response_agent_capture_diagnostics(original_payload)
            if isinstance(original_payload, dict)
            else []
        )
        syslog_by_field = cls._response_agent_diagnostics_by_field(
            cls._response_agent_capture_diagnostics(raw_payload)
            if isinstance(raw_payload, dict)
            else []
        )
        effective: list[dict[str, Any]] = []
        mapping_gaps: list[dict[str, str]] = []
        original_available = isinstance(original_payload, dict)
        syslog_available = isinstance(raw_payload, dict)
        syslog_integrity = str(
            descriptor.get("syslog_message_integrity") or "not_observed"
        )
        syslog_usable = syslog_available and syslog_integrity in {
            "verified",
            "unverified",
        }
        default_item = {
            "state": "not_observed",
            "json_pointer": "",
            "bytes": 0,
        }
        for field, mapped_item in mapped_by_field.items():
            mapped = {"field": field, **default_item, **mapped_item}
            original = {
                "field": field,
                **default_item,
                **original_by_field.get(field, {}),
            }
            syslog = {
                "field": field,
                **default_item,
                **syslog_by_field.get(field, {}),
            }
            mapped_state = str(mapped.get("state") or "not_observed")
            original_state = str(original.get("state") or "not_observed")
            syslog_state = str(syslog.get("state") or "not_observed")
            candidates = [
                {
                    "item": mapped,
                    "provenance": "mapped_projection",
                    "confidence": "projection",
                    "authority": 0,
                }
            ]
            if original_available:
                candidates.append(
                    {
                        "item": original,
                        "provenance": "stored_original_log",
                        "confidence": "stored",
                        "authority": 2,
                    }
                )
            if syslog_usable:
                candidates.append(
                    {
                        "item": syslog,
                        "provenance": "syslog_raw_message",
                        "confidence": syslog_integrity,
                        "authority": 3 if syslog_integrity == "verified" else 1,
                    }
                )
            selected_source = max(
                candidates,
                key=lambda candidate: (
                    str(candidate["item"].get("state") or "not_observed")
                    != "not_observed",
                    int(candidate["authority"]),
                ),
            )
            selected = selected_source["item"]
            provenance = str(selected_source["provenance"])
            mapped_observed = str(mapped.get("observed_value") or "")
            original_observed = str(original.get("observed_value") or "")
            syslog_observed = str(syslog.get("observed_value") or "")

            raw_candidates: list[dict[str, Any]] = []
            if original_available:
                raw_candidates.append(
                    {"item": original, "authority": 2, "source": "original_log"}
                )
            if syslog_usable:
                raw_candidates.append(
                    {
                        "item": syslog,
                        "authority": 3 if syslog_integrity == "verified" else 1,
                        "source": "syslog",
                    }
                )
            raw_reference = (
                max(
                    raw_candidates,
                    key=lambda candidate: (
                        str(
                            candidate["item"].get("state")
                            or "not_observed"
                        )
                        != "not_observed",
                        int(candidate["authority"]),
                    ),
                )
                if raw_candidates
                else None
            )
            raw_item = raw_reference["item"] if raw_reference else default_item
            raw_state = str(raw_item.get("state") or "not_observed")
            raw_observed = str(raw_item.get("observed_value") or "")
            if syslog_integrity == "mismatch" and syslog_state != "not_observed":
                consistency = "syslog_integrity_mismatch"
            elif not raw_candidates:
                consistency = "raw_not_available"
            elif raw_state == "not_observed" and mapped_state != "not_observed":
                consistency = "mapped_projection_only"
            elif mapped_state == "not_observed" and raw_state != "not_observed":
                consistency = "raw_evidence_only"
            elif mapped_state != raw_state:
                consistency = "state_mismatch"
            elif (
                mapped_observed
                and raw_observed
                and mapped_observed != raw_observed
            ):
                consistency = "value_mismatch"
            else:
                consistency = "consistent"

            merged = dict(selected)
            if provenance == "stored_original_log":
                merged["json_pointer"] = cls._response_agent_original_pointer(
                    selected.get("json_pointer")
                )
            merged.update(
                {
                    "provenance": provenance,
                    "provenance_confidence": str(
                        selected_source["confidence"]
                    ),
                    "mapped_state": mapped_state,
                    "original_log_state": original_state,
                    "syslog_state": syslog_state,
                    "syslog_integrity": syslog_integrity,
                    "syslog_usable": syslog_usable,
                    "mapping_consistency": consistency,
                    "mapped_json_pointer": str(
                        mapped.get("json_pointer") or ""
                    ),
                    "original_log_json_pointer": (
                        cls._response_agent_original_pointer(
                            original.get("json_pointer")
                        )
                    ),
                    "syslog_json_pointer": str(
                        syslog.get("json_pointer") or ""
                    ),
                }
            )
            if mapped_observed:
                merged["mapped_observed_value"] = mapped_observed
            if original_observed:
                merged["original_log_observed_value"] = original_observed
            if syslog_observed:
                merged["syslog_observed_value"] = syslog_observed
            effective.append(merged)

            integrity_conflict = (
                syslog_integrity == "mismatch"
                and syslog_state != "not_observed"
            )
            critical_state_conflict = (
                raw_state in {"captured_incomplete", "captured_invalid"}
                and raw_state != mapped_state
                and mapped_state
                in {"not_observed", "captured_null", "captured_empty"}
            )
            value_conflict = (
                raw_state == mapped_state == "captured_nonempty"
                and raw_observed
                and mapped_observed
                and raw_observed != mapped_observed
            )
            raw_mapping_state_conflict = (
                raw_state != "not_observed"
                and raw_state != mapped_state
            )
            if (
                integrity_conflict
                or critical_state_conflict
                or value_conflict
                or raw_mapping_state_conflict
            ):
                if integrity_conflict:
                    reason = "syslog_integrity_mismatch"
                elif value_conflict:
                    reason = "field_value_differs_from_raw_evidence"
                elif critical_state_conflict:
                    reason = "raw_capture_conflicts_with_mapped_projection"
                elif (
                    raw_state == "captured_nonempty"
                    and mapped_state == "not_observed"
                ):
                    reason = "field_available_in_raw_evidence_not_mapped"
                else:
                    reason = "raw_capture_state_differs_from_mapped_projection"
                mapping_gaps.append(
                    {
                        "field": field,
                        "mapped_state": mapped_state,
                        "original_log_state": original_state,
                        "syslog_state": syslog_state,
                        "syslog_integrity": syslog_integrity,
                        "reason": reason,
                    }
                )
        return descriptor, effective, mapping_gaps

    @staticmethod
    def _response_agent_investigation_facts(payload: Any) -> dict[str, Any]:
        """Project bounded attack facts without exposing request bodies or headers."""
        if not isinstance(payload, dict):
            return {}

        original_log = payload.get("original_log")
        original_event = (
            original_log.get("event")
            if isinstance(original_log, dict)
            and isinstance(original_log.get("event"), dict)
            else {}
        )
        request = (
            original_event.get("request_message")
            if isinstance(original_event.get("request_message"), dict)
            else {}
        )
        original_items = (
            original_log.get("items")
            if isinstance(original_log, dict)
            and isinstance(original_log.get("items"), list)
            else []
        )
        projected_context = payload.get("rasp_items_context")
        projected_items = (
            projected_context.get("items")
            if isinstance(projected_context, dict)
            and isinstance(projected_context.get("items"), list)
            else []
        )

        def bounded(value: Any, limit: int = 512) -> Any:
            if isinstance(value, bool):
                return value
            if isinstance(value, (int, float)):
                return value
            if isinstance(value, str):
                return value[:limit]
            return None

        allowed_hook_fields = {
            "absolute_path": "path",
            "absolutepath": "path",
            "class": "class",
            "class_name": "class",
            "classname": "class",
            "file": "file",
            "file_name": "file",
            "filename": "file",
            "hit_evidence": "attack_evidence",
            "hitevidence": "attack_evidence",
            "lib": "library",
            "library": "library",
            "method": "method",
            "name": "name",
            "path": "path",
            "process": "process",
            "process_name": "process",
            "processname": "process",
            "suffix": "suffix",
            "url": "url",
        }

        def project_hook(value: Any) -> dict[str, Any]:
            if not isinstance(value, dict):
                return {}
            projected: dict[str, Any] = {}
            for key, candidate in value.items():
                canonical = str(key or "").strip().casefold().replace("-", "_")
                output_key = allowed_hook_fields.get(canonical)
                rendered = bounded(candidate)
                if output_key and rendered is not None and output_key not in projected:
                    projected[output_key] = rendered
            return projected

        detections: list[dict[str, Any]] = []
        for index, raw_item in enumerate(original_items[:8]):
            if not isinstance(raw_item, dict):
                continue
            projected_item = (
                projected_items[index]
                if index < len(projected_items)
                and isinstance(projected_items[index], dict)
                else {}
            )
            detection: dict[str, Any] = {}
            candidates = {
                "sequence": (raw_item.get("sequence"), index + 1),
                "trigger_time": (raw_item.get("trigger_time"),),
                "rule": (raw_item.get("rule_id"), projected_item.get("rule_id")),
                "rule_name": (
                    raw_item.get("rule_name"),
                    projected_item.get("rule_name"),
                ),
                "attack_type": (raw_item.get("attack_type"),),
                "attack_level": (raw_item.get("attack_level"),),
                "action": (
                    raw_item.get("intercept_state"),
                    raw_item.get("action"),
                    projected_item.get("action"),
                ),
                "dangerous_sink": (
                    projected_item.get("sink"),
                    raw_item.get("sink"),
                ),
            }
            for name, values in candidates.items():
                for candidate in values:
                    rendered = bounded(candidate)
                    if rendered not in {None, ""}:
                        detection[name] = rendered
                        break
            hook_evidence = project_hook(raw_item.get("hook_data"))
            if hook_evidence:
                detection["hook_evidence"] = hook_evidence
            if detection:
                detections.append(detection)

        facts: dict[str, Any] = {}
        primary_detection = detections[0] if detections else {}
        sources = {
            "event_time": (payload.get("event_time"), original_event.get("attack_time")),
            "source_ip": (
                payload.get("src_ip"),
                original_event.get("attack_source"),
                original_event.get("attacker_ip"),
            ),
            "host": (payload.get("host"), original_event.get("server_hostname")),
            "application": (payload.get("app"), original_event.get("app_name")),
            "request_id": (payload.get("request_id"), original_event.get("request_id")),
            "method": (payload.get("method"), request.get("method")),
            "url": (payload.get("url"), request.get("url")),
            "rule": (
                payload.get("rule"),
                primary_detection.get("rule"),
                original_event.get("attack_rule_code"),
            ),
            "rule_name": (primary_detection.get("rule_name"),),
            "action": (
                payload.get("action"),
                primary_detection.get("action"),
                original_event.get("intercept_state"),
            ),
            "attack_type": (primary_detection.get("attack_type"),),
            "attack_level": (primary_detection.get("attack_level"),),
            "dangerous_sink": (
                payload.get("sink"),
                primary_detection.get("dangerous_sink"),
            ),
            "web_root": (original_event.get("web_path"),),
        }
        for name, candidates in sources.items():
            for candidate in candidates:
                value = bounded(candidate)
                if value not in {None, ""}:
                    facts[name] = value
                    break

        hook_evidence = (
            primary_detection.get("hook_evidence")
            if isinstance(primary_detection.get("hook_evidence"), dict)
            else project_hook(payload.get("hook_data"))
        )
        if hook_evidence:
            facts["hook_evidence"] = hook_evidence
        if detections:
            facts["detections"] = detections

        return facts

    @staticmethod
    def _response_agent_forensic_domains(
        product: str,
        catalog: list[dict[str, Any]],
        investigation_facts: dict[str, Any] | None = None,
    ) -> list[str]:
        product_name = str(product or "").casefold()
        pointers = " ".join(
            str(item.get("json_pointer") or "").casefold()
            for item in catalog
        )
        domains: set[str] = set()
        facts = investigation_facts or {}
        fact_hooks = []
        if isinstance(facts.get("hook_evidence"), dict):
            fact_hooks.append(facts["hook_evidence"])
        fact_hooks.extend(
            item.get("hook_evidence")
            for item in facts.get("detections") or []
            if isinstance(item, dict) and isinstance(item.get("hook_evidence"), dict)
        )
        if product_name in {"waf", "rasp"} or any(
            token in pointers
            for token in ("request_message", "request_body", "/http", "/url")
        ):
            domains.add("web_request")
        if product_name == "rasp" or any(
            token in pointers
            for token in ("/host", "/server", "/runtime", "/stacktrace", "/sink")
        ):
            domains.add("server_runtime")
        if product_name in {"edr", "hips", "sysmon", "auditd"} or any(
            token in pointers
            for token in ("/process", "/parent", "/command_line", "/module")
        ):
            domains.add("endpoint_process")
        if any(
            any(key in hook for key in ("process", "class", "method"))
            for hook in fact_hooks
        ) and product_name in {"edr", "hips", "sysmon", "auditd"}:
            domains.add("endpoint_process")
        if product_name in {"edr", "hips", "fim"} or any(
            token in pointers
            for token in (
                "/hook_data/path",
                "/hook_data/absolute_path",
                "/file_path",
                "/file_name",
                "/filename",
                "/file/",
                "/hash",
                "/webroot",
            )
        ):
            domains.add("file_integrity")
        if any(
            any(key in hook for key in ("path", "file"))
            for hook in fact_hooks
        ):
            domains.add("file_integrity")
        if product_name in {"waf", "ndr", "siem", "firewall", "ids", "ips"} or any(
            token in pointers
            for token in ("/dst_ip", "/network", "/connection", "/flow")
        ):
            domains.add("network_perimeter")
        if product_name in {"siem", "iam", "idp"} or any(
            token in pointers
            for token in ("/user", "/account", "/login", "/authentication")
        ):
            domains.add("identity_authentication")
        if any(
            token in pointers
            for token in ("/service", "/cron", "/scheduled", "/autorun", "/startup")
        ):
            domains.add("persistence")
        if product_name in {"cloud", "k8s", "kubernetes", "container"} or any(
            token in pointers
            for token in ("/container", "/pod", "/namespace", "/cloud")
        ):
            domains.add("cloud_container")
        return sorted(domains)

    @classmethod
    def _response_agent_raw_manifest(
        cls,
        row: dict[str, Any],
        *,
        relation: str,
        matched: list[dict[str, str]] | None = None,
        correlation_score: int = 0,
        time_delta_ms: int = 0,
        include_catalog: bool = True,
    ) -> dict[str, Any]:
        payload = json.loads(row.get("payload_json") or "{}")
        original_log = payload.get("original_log") if isinstance(payload, dict) else None
        catalog = cls._response_agent_json_catalog(
            payload,
            max_entries=120 if include_catalog else 80,
            include_sizes=include_catalog,
        )
        (
            syslog_descriptor,
            capture_diagnostics,
            capture_mapping_gaps,
        ) = cls._response_agent_capture_layers(payload)
        investigation_facts = cls._response_agent_investigation_facts(payload)
        return {
            "alert_id": str(row.get("alert_id") or ""),
            "event_id": str(row.get("event_id") or ""),
            "source": str(row.get("source") or ""),
            "product": str(row.get("product") or ""),
            "event_type": str(row.get("event_type") or ""),
            "severity": str(row.get("severity") or ""),
            "timestamp": str(row.get("timestamp") or ""),
            "created_at_ms": int(row.get("created_at_ms") or 0),
            "relation": relation,
            "matched_entities": list(matched or []),
            "correlation_score": int(correlation_score),
            "time_delta_ms": int(time_delta_ms),
            "raw_bytes": len(
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ),
            "original_log_present": original_log is not None,
            "original_log_bytes": (
                len(
                    json.dumps(
                        original_log,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                )
                if original_log is not None
                else 0
            ),
            "source_hash": cls._response_agent_raw_hash(row),
            **syslog_descriptor,
            "capture_diagnostics": capture_diagnostics,
            "capture_mapping_gaps": capture_mapping_gaps,
            "investigation_facts": investigation_facts,
            "forensic_domains": cls._response_agent_forensic_domains(
                str(row.get("product") or ""),
                catalog,
                investigation_facts,
            ),
            "field_catalog": catalog if include_catalog else [],
        }

    def query_response_agent_case_raw_alerts(
        self,
        case_id: str,
        *,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any] | None:
        """List complete raw-alert manifests linked to a controller-owned Case."""
        page_limit = max(1, min(int(limit), 50))
        page_offset = max(0, int(offset))
        with self._lock:
            if not self.conn.execute(
                "SELECT 1 FROM cases WHERE case_id = ?", (case_id,)
            ).fetchone():
                return None
            total = int(
                self.conn.execute(
                    "SELECT COUNT(DISTINCT alert_id) AS count "
                    "FROM case_alert_links WHERE case_id = ?",
                    (case_id,),
                ).fetchone()["count"]
            )
            rows = self.conn.execute(
                """
                SELECT l.alert_id, l.event_id, l.linked_at_ms,
                       ra.source, ra.product, ra.event_type, ra.severity,
                       ra.timestamp, ra.payload_json, ra.created_at_ms
                FROM (
                    SELECT alert_id, MIN(event_id) AS event_id,
                           MAX(created_at_ms) AS linked_at_ms
                    FROM case_alert_links
                    WHERE case_id = ?
                    GROUP BY alert_id
                ) l
                JOIN raw_alerts ra ON ra.alert_id = l.alert_id
                ORDER BY l.linked_at_ms DESC, l.alert_id ASC
                LIMIT ? OFFSET ?
                """,
                (case_id, page_limit, page_offset),
            ).fetchall()
            items = [
                {
                    **self._response_agent_raw_manifest(
                        dict(row), relation="linked_to_case"
                    ),
                    "linked_at_ms": int(row["linked_at_ms"] or 0),
                }
                for row in rows
            ]
            next_offset = page_offset + len(items)
            return {
                "items": items,
                "total": total,
                "limit": page_limit,
                "offset": page_offset,
                "next_offset": next_offset if next_offset < total else None,
                "query_mode": "controller_scoped_raw_manifest",
            }

    def _response_agent_candidate_json_locked(
        self,
        alert_id: str,
        event_id: str | None,
    ) -> dict[str, Any] | None:
        row = self.conn.execute(
            """
            SELECT ra.payload_json,
                   (
                       SELECT ne.entities_json
                       FROM normalized_events ne
                       WHERE ne.event_id = ?
                   ) AS entities_json
            FROM raw_alerts ra
            WHERE ra.alert_id = ?
            """,
            (event_id, alert_id),
        ).fetchone()
        return dict(row) if row else None

    def query_response_agent_related_alerts(
        self,
        case_id: str,
        *,
        products: list[str] | None = None,
        window_ms: int = 24 * 60 * 60 * 1_000,
        scan_limit: int = 2_000,
        scan_max_bytes: int = 64_000_000,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any] | None:
        """Search bounded raw/normalized telemetry using Case-derived indicators."""
        bounded_window = max(60_000, min(int(window_ms), 7 * 24 * 60 * 60 * 1_000))
        bounded_scan = max(100, min(int(scan_limit), 10_000))
        bounded_scan_bytes = max(
            1_000_000, min(int(scan_max_bytes), 512_000_000)
        )
        page_limit = max(1, min(int(limit), 100))
        page_offset = max(0, int(offset))
        selected_products = []
        for product in products or []:
            rendered = str(product or "").strip().lower()
            if (
                rendered
                and len(rendered) <= 32
                and all(character.isalnum() or character in "._-" for character in rendered)
                and rendered not in selected_products
            ):
                selected_products.append(rendered)
            if len(selected_products) >= 12:
                break
        with self._lock:
            scope = self._response_agent_scope_locked(case_id)
            if not scope:
                return None
            product_clause = ""
            parameters: list[Any] = [
                scope["event_min_ms"] - bounded_window,
                scope["event_max_ms"] + bounded_window,
                scope["created_min_ms"] - bounded_window,
                scope["created_max_ms"] + bounded_window,
            ]
            if selected_products:
                placeholders = ",".join("?" for _ in selected_products)
                product_clause = f" AND LOWER(ra.product) IN ({placeholders})"
                parameters.extend(selected_products)
            # Fetch one sentinel row so callers can distinguish a complete scan
            # from one bounded by the SQL candidate-row limit.
            parameters.append(bounded_scan + 1)
            candidate_rows = self.conn.execute(
                f"""
                SELECT ra.alert_id, ra.source, ra.product, ra.event_type,
                       ra.severity, ra.timestamp, ra.created_at_ms,
                       LENGTH(CAST(ra.payload_json AS BLOB)) AS payload_bytes,
                       ne.event_id, ne.event_at_ms
                FROM raw_alerts ra
                LEFT JOIN normalized_events ne ON ne.event_id = (
                    SELECT ne_latest.event_id
                    FROM normalized_events ne_latest
                    WHERE ne_latest.alert_id = ra.alert_id
                    ORDER BY ne_latest.created_at_ms DESC, ne_latest.event_id ASC
                    LIMIT 1
                )
                WHERE (
                    COALESCE(NULLIF(ne.event_at_ms, 0), ra.created_at_ms)
                      BETWEEN ? AND ?
                    OR ra.created_at_ms BETWEEN ? AND ?
                )
                {product_clause}
                ORDER BY COALESCE(NULLIF(ne.event_at_ms, 0), ra.created_at_ms) ASC,
                         ra.created_at_ms ASC, ra.alert_id ASC
                LIMIT ?
                """,
                parameters,
            )
            matches: list[dict[str, Any]] = []
            seen_alerts: set[str] = set()
            scanned_alerts: set[str] = set()
            scanned_bytes = 0
            row_limit_hit = False
            byte_limit_hit = False
            try:
                for candidate_index, sql_row in enumerate(candidate_rows):
                    if candidate_index >= bounded_scan:
                        row_limit_hit = True
                        break
                    if byte_limit_hit:
                        # Continue over payload-free metadata only so the SQL
                        # row-limit sentinel remains independently observable.
                        continue
                    row = dict(sql_row)
                    alert_id = str(row["alert_id"])
                    if (
                        alert_id in seen_alerts
                        or alert_id in scope["linked_alert_ids"]
                    ):
                        continue
                    if alert_id not in scanned_alerts:
                        payload_bytes = int(row.get("payload_bytes") or 0)
                        if scanned_bytes + payload_bytes > bounded_scan_bytes:
                            byte_limit_hit = True
                            continue
                    candidate_json = self._response_agent_candidate_json_locked(
                        alert_id,
                        str(row["event_id"]) if row.get("event_id") else None,
                    )
                    if candidate_json is None:
                        continue
                    row.update(candidate_json)
                    if alert_id not in scanned_alerts:
                        scanned_alerts.add(alert_id)
                        scanned_bytes += int(row.get("payload_bytes") or 0)
                    matched, score = self._response_agent_match_candidate(scope, row)
                    if score < _RESPONSE_AGENT_MIN_CORRELATION_SCORE:
                        continue
                    seen_alerts.add(alert_id)
                    event_at_ms = int(
                        row.get("event_at_ms") or row["created_at_ms"] or 0
                    )
                    time_delta_ms = min(
                        abs(event_at_ms - int(scope["event_min_ms"])),
                        abs(event_at_ms - int(scope["event_max_ms"])),
                    )
                    matches.append(
                        self._response_agent_raw_manifest(
                            row,
                            relation="case_indicator_correlation",
                            matched=matched,
                            correlation_score=score,
                            time_delta_ms=time_delta_ms,
                            include_catalog=False,
                        )
                    )
            finally:
                candidate_rows.close()
            scan_truncation_reasons = []
            if row_limit_hit:
                scan_truncation_reasons.append("row_limit")
            if byte_limit_hit:
                scan_truncation_reasons.append("byte_limit")
            matches.sort(
                key=lambda item: (
                    -int(item["correlation_score"]),
                    int(item["time_delta_ms"]),
                    str(item["timestamp"]),
                    str(item["alert_id"]),
                )
            )
            page = matches[page_offset : page_offset + page_limit]
            next_offset = page_offset + len(page)
            return {
                "items": page,
                "total": len(matches),
                "limit": page_limit,
                "offset": page_offset,
                "next_offset": next_offset if next_offset < len(matches) else None,
                "query_mode": "case_indicator_correlation",
                "products": selected_products,
                "window_ms": bounded_window,
                "scan_limit": bounded_scan,
                "scan_max_bytes": bounded_scan_bytes,
                "scanned": len(scanned_alerts),
                "scanned_bytes": scanned_bytes,
                "scan_truncated": bool(scan_truncation_reasons),
                "scan_truncation_reasons": scan_truncation_reasons,
                "minimum_correlation_score": _RESPONSE_AGENT_MIN_CORRELATION_SCORE,
                "anchor_fields": [
                    field for field, values in scope["values"].items() if values
                ],
            }

    def get_response_agent_raw_alert(
        self,
        case_id: str,
        alert_id: str,
        *,
        window_ms: int = 24 * 60 * 60 * 1_000,
    ) -> dict[str, Any] | None:
        """Return raw evidence only when linked or correlated to the controller Case."""
        bounded_window = max(60_000, min(int(window_ms), 7 * 24 * 60 * 60 * 1_000))
        with self._lock:
            scope = self._response_agent_scope_locked(case_id)
            if not scope:
                return None
            sql_row = self.conn.execute(
                """
                SELECT ra.alert_id, ra.source, ra.product, ra.event_type,
                       ra.severity, ra.timestamp, ra.payload_json, ra.created_at_ms,
                       ne.event_id, ne.entities_json, ne.evidence_hash, ne.event_at_ms
                FROM raw_alerts ra
                LEFT JOIN normalized_events ne ON ne.event_id = (
                    SELECT ne_latest.event_id
                    FROM normalized_events ne_latest
                    WHERE ne_latest.alert_id = ra.alert_id
                    ORDER BY ne_latest.created_at_ms DESC, ne_latest.event_id ASC
                    LIMIT 1
                )
                WHERE ra.alert_id = ?
                LIMIT 1
                """,
                (alert_id,),
            ).fetchone()
            if not sql_row:
                return None
            row = dict(sql_row)
            linked = str(alert_id) in scope["linked_alert_ids"]
            matched: list[dict[str, str]] = []
            score = 0
            if not linked:
                event_at_ms = int(row.get("event_at_ms") or row["created_at_ms"] or 0)
                within_event_window = (
                    int(scope["event_min_ms"]) - bounded_window
                    <= event_at_ms
                    <= int(scope["event_max_ms"]) + bounded_window
                )
                within_ingest_window = (
                    int(scope["created_min_ms"]) - bounded_window
                    <= int(row["created_at_ms"])
                    <= int(scope["created_max_ms"]) + bounded_window
                )
                if not (within_event_window or within_ingest_window):
                    return None
                matched, score = self._response_agent_match_candidate(scope, row)
                if score < _RESPONSE_AGENT_MIN_CORRELATION_SCORE:
                    return None
            manifest = self._response_agent_raw_manifest(
                row,
                relation=(
                    "linked_to_case" if linked else "case_indicator_correlation"
                ),
                matched=matched,
                correlation_score=score,
            )
            return {
                **manifest,
                "payload": json.loads(row["payload_json"]),
                "normalized_evidence_hash": str(row.get("evidence_hash") or ""),
            }

    @staticmethod
    def _entity_value(value: Any) -> str:
        return str(value).strip().lower()[:256] if value not in (None, "") else ""

    def link_case_alert(
        self,
        case_id: str,
        alert_id: str,
        event_id: str,
        _commit: bool = True,
        alert_at_ms: int | None = None,
    ) -> None:
        with self._lock:
            linked_at = now_ms()
            self.conn.execute(
                """
                INSERT OR IGNORE INTO case_alert_links
                (case_id, alert_id, event_id, created_at_ms)
                VALUES (?, ?, ?, ?)
                """,
                (case_id, alert_id, event_id, linked_at),
            )
            self.conn.execute(
                "UPDATE cases SET last_alert_at_ms = MAX(last_alert_at_ms, ?), updated_at_ms = ? WHERE case_id = ?",
                (alert_at_ms or linked_at, linked_at, case_id),
            )
            if _commit:
                self.conn.commit()

    def resolve_case_id(
        self,
        correlation_key: str,
        event_id: str,
        event_timestamp: str,
        window_ms: int = 60 * 60 * 1000,
    ) -> tuple[str, str]:
        """Resolve an event to an open Case without reviving terminal history.

        The first event keeps the familiar Demo case identifier. A terminal Case
        or an alert outside the correlation window gets a deterministic suffix,
        so retries remain idempotent and old analyst dispositions stay immutable.
        """
        event_at = self.timestamp_ms(event_timestamp)
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT case_id, status, last_alert_at_ms FROM cases
                WHERE correlation_key = ?
                ORDER BY last_alert_at_ms DESC, updated_at_ms DESC LIMIT 1
                """,
                (correlation_key,),
            ).fetchall()
            if not rows:
                return correlation_key[:96], "new_correlation"
            latest = rows[0]
            terminal = latest["status"] in {"closed", "false_positive"}
            in_window = abs(event_at - int(latest["last_alert_at_ms"] or 0)) <= max(1, int(window_ms))
            if not terminal and in_window:
                return str(latest["case_id"]), "correlated_existing"
            digest = hashlib.sha256(event_id.encode("utf-8")).hexdigest()[:10]
            suffix = f"__{digest}"
            case_id = f"{correlation_key[:96 - len(suffix)]}{suffix}"
            return case_id, "terminal_rollover" if terminal else "time_window_rollover"

    @staticmethod
    def timestamp_ms(value: str) -> int:
        try:
            normalized = str(value).strip().replace("Z", "+00:00")
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return int(parsed.timestamp() * 1000)
        except (TypeError, ValueError, OverflowError):
            return now_ms()

    def update_case_status(self, case_id: str, status: str, _commit: bool = True) -> dict[str, Any] | None:
        with self._lock:
            updated_at = now_ms()
            terminal = status in {"closed", "false_positive"}
            cur = self.conn.execute(
                """
                UPDATE cases
                SET status = ?, updated_at_ms = ?, closed_at_ms = ?
                WHERE case_id = ?
                """,
                (status, updated_at, updated_at if terminal else None, case_id),
            )
            if cur.rowcount == 0:
                return None
            if terminal:
                self.cancel_pending_approvals(
                    case_id,
                    actor="case-lifecycle",
                    reason=f"Case transitioned to terminal status: {status}",
                    _commit=False,
                )
                self.cancel_case_response_agents(
                    case_id,
                    reason=f"Case transitioned to terminal status: {status}",
                    _commit=False,
                )
                self.transition_case_response_tasks(case_id, _commit=False)
                self._archive_case_memory_locked(case_id, updated_at)
                self._expire_unapproved_long_term_memory_locked(case_id, status, updated_at)
            if _commit:
                self.conn.commit()
            row = self.conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            return dict(row) if row else None

    def cancel_pending_approvals(
        self,
        case_id: str,
        actor: str,
        reason: str,
        _commit: bool = True,
        except_event_id: str | None = None,
    ) -> int:
        with self._lock:
            clauses = ["case_id = ?", "status = 'pending'"]
            params: list[Any] = [case_id]
            if except_event_id:
                clauses.append("event_id != ?")
                params.append(except_event_id)
            updated_at = now_ms()
            cur = self.conn.execute(
                f"""
                UPDATE action_approvals
                SET status = 'cancelled', decided_by = ?, decision_reason = ?, updated_at_ms = ?
                WHERE {' AND '.join(clauses)}
                """,
                (actor, reason, updated_at, *params),
            )
            if _commit:
                self.conn.commit()
            return cur.rowcount

    def _archive_case_memory_locked(self, case_id: str, archived_at_ms: int) -> int:
        rows = self.conn.execute(
            """
            SELECT memory_id FROM memory_entries
            WHERE layer = 'case_short_term' AND namespace = ? AND status = 'active'
            """,
            (f"case/{case_id}",),
        ).fetchall()
        for row in rows:
            memory_id = str(row["memory_id"])
            self.conn.execute(
                "UPDATE memory_entries SET status = 'expired', trust_level = 'low', updated_at_ms = ? WHERE memory_id = ?",
                (archived_at_ms, memory_id),
            )
            digest = hashlib.sha256(f"{memory_id}\0{archived_at_ms}".encode("utf-8")).hexdigest()[:24]
            self.conn.execute(
                """
                INSERT OR IGNORE INTO memory_events
                (event_id, memory_id, layer, event_type, actor, detail_json, created_at_ms)
                VALUES (?, ?, 'case_short_term', 'expired', 'case-lifecycle', ?, ?)
                """,
                (
                    f"mev_{digest}",
                    memory_id,
                    json.dumps({"reason": "case_closed_archive", "case_id": case_id}, ensure_ascii=False),
                    archived_at_ms,
                ),
            )
        return len(rows)

    def _expire_unapproved_long_term_memory_locked(
        self, case_id: str, case_status: str, expired_at_ms: int
    ) -> int:
        """Retire unapproved long-term candidates when their source Case ends.

        A pending candidate is only an observation awaiting governance review.  It
        must not remain actionable after its source Case has been closed or
        classified as a business false positive.  Approved long-term memories
        deliberately remain active: their lifecycle is independent once all
        promotion gates have been satisfied.
        """
        rows = self.conn.execute(
            """
            SELECT memory_id FROM memory_entries
            WHERE source_case_id = ?
              AND layer = 'product_long_term'
              AND status = 'pending_approval'
            """,
            (case_id,),
        ).fetchall()
        for row in rows:
            memory_id = str(row["memory_id"])
            self.conn.execute(
                """
                UPDATE memory_entries
                SET status = 'expired', trust_level = 'low', updated_at_ms = ?
                WHERE memory_id = ? AND status = 'pending_approval'
                """,
                (expired_at_ms, memory_id),
            )
            digest = hashlib.sha256(
                f"{memory_id}\0{case_id}\0{expired_at_ms}\0case-terminal".encode("utf-8")
            ).hexdigest()[:24]
            self.conn.execute(
                """
                INSERT OR IGNORE INTO memory_events
                (event_id, memory_id, layer, event_type, actor, detail_json, created_at_ms)
                VALUES (?, ?, 'product_long_term', 'expired', 'case-lifecycle', ?, ?)
                """,
                (
                    f"mev_{digest}",
                    memory_id,
                    json.dumps(
                        {
                            "reason": "source_case_terminal_before_promotion",
                            "case_id": case_id,
                            "case_status": case_status,
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    expired_at_ms,
                ),
            )
        return len(rows)

    def set_alert_disposition(
        self,
        alert_id: str,
        disposition: str,
        actor: str,
        reason: str = "",
        _commit: bool = True,
    ) -> dict[str, Any] | None:
        """Record an alert-level decision without changing its aggregate Case.

        The caller may close a Case as false positive only when
        ``case_can_close_as_false_positive`` is true. This prevents one alert in a
        multi-alert Case from overwriting the disposition of every other alert.
        """
        if disposition not in {"open", "closed", "false_positive"}:
            raise ValueError(f"unsupported alert disposition: {disposition}")
        with self._lock:
            link = self.conn.execute(
                "SELECT case_id FROM case_alert_links WHERE alert_id = ? ORDER BY created_at_ms DESC LIMIT 1",
                (alert_id,),
            ).fetchone()
            if not link:
                return None
            case_id = str(link["case_id"])
            updated = now_ms()
            self.conn.execute(
                """
                INSERT INTO alert_dispositions
                (alert_id, case_id, disposition, actor, reason, created_at_ms, updated_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(alert_id) DO UPDATE SET
                  case_id = excluded.case_id,
                  disposition = excluded.disposition,
                  actor = excluded.actor,
                  reason = excluded.reason,
                  updated_at_ms = excluded.updated_at_ms
                """,
                (alert_id, case_id, disposition, actor, reason, updated, updated),
            )
            aggregate = self.conn.execute(
                """
                SELECT COUNT(DISTINCT l.alert_id) AS total,
                       COUNT(DISTINCT CASE
                         WHEN d.disposition = 'false_positive' THEN l.alert_id
                       END) AS false_positives
                FROM case_alert_links l
                LEFT JOIN alert_dispositions d
                  ON d.alert_id = l.alert_id AND d.case_id = l.case_id
                WHERE l.case_id = ?
                """,
                (case_id,),
            ).fetchone()
            if _commit:
                self.conn.commit()
            total = int(aggregate["total"] or 0)
            false_positives = int(aggregate["false_positives"] or 0)
            return {
                "alert_id": alert_id,
                "case_id": case_id,
                "disposition": disposition,
                "case_alert_count": total,
                "case_false_positive_count": false_positives,
                "case_can_close_as_false_positive": total > 0 and false_positives == total,
                "updated_at_ms": updated,
            }

    def set_alert_dispositions(
        self,
        case_id: str,
        alert_ids: list[str],
        disposition: str,
        actor: str,
        reason: str = "",
        _commit: bool = True,
    ) -> dict[str, Any]:
        """Apply one reviewed decision to an explicitly resolved alert cluster."""
        if disposition not in {"open", "closed", "false_positive"}:
            raise ValueError(f"unsupported alert disposition: {disposition}")
        unique_ids = list(dict.fromkeys(str(item) for item in alert_ids if item))
        if not unique_ids:
            raise ValueError("alert cluster is empty")
        with self._lock:
            placeholders = ",".join("?" for _ in unique_ids)
            linked_rows = self.conn.execute(
                f"""
                SELECT alert_id FROM case_alert_links
                WHERE case_id = ? AND alert_id IN ({placeholders})
                """,
                (case_id, *unique_ids),
            ).fetchall()
            linked_ids = {str(row["alert_id"]) for row in linked_rows}
            if linked_ids != set(unique_ids):
                raise ValueError("alert cluster contains alerts outside the Case")
            updated = now_ms()
            self.conn.executemany(
                """
                INSERT INTO alert_dispositions
                (alert_id, case_id, disposition, actor, reason, created_at_ms, updated_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(alert_id) DO UPDATE SET
                  case_id = excluded.case_id,
                  disposition = excluded.disposition,
                  actor = excluded.actor,
                  reason = excluded.reason,
                  updated_at_ms = excluded.updated_at_ms
                """,
                [
                    (alert_id, case_id, disposition, actor, reason, updated, updated)
                    for alert_id in unique_ids
                ],
            )
            aggregate = self.conn.execute(
                """
                SELECT COUNT(DISTINCT l.alert_id) AS total,
                       COUNT(DISTINCT CASE
                         WHEN d.disposition = 'false_positive' THEN l.alert_id
                       END) AS false_positives
                FROM case_alert_links l
                LEFT JOIN alert_dispositions d
                  ON d.alert_id = l.alert_id AND d.case_id = l.case_id
                WHERE l.case_id = ?
                """,
                (case_id,),
            ).fetchone()
            if _commit:
                self.conn.commit()
            total = int(aggregate["total"] or 0)
            false_positives = int(aggregate["false_positives"] or 0)
            return {
                "case_id": case_id,
                "alert_ids": unique_ids,
                "updated_count": len(unique_ids),
                "disposition": disposition,
                "case_alert_count": total,
                "case_false_positive_count": false_positives,
                "case_can_close_as_false_positive": total > 0 and false_positives == total,
                "updated_at_ms": updated,
            }

    def get_alert_disposition(self, alert_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM alert_dispositions WHERE alert_id = ?", (alert_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_alert_disposition_summary(self, alert_id: str) -> dict[str, Any] | None:
        """Return the stable response shape for an existing alert disposition."""
        with self._lock:
            row = self.conn.execute(
                """
                SELECT alert_id, case_id, disposition, updated_at_ms
                FROM alert_dispositions
                WHERE alert_id = ?
                """,
                (alert_id,),
            ).fetchone()
            if not row:
                return None
            aggregate = self.conn.execute(
                """
                SELECT COUNT(DISTINCT l.alert_id) AS total,
                       COUNT(DISTINCT CASE
                         WHEN d.disposition = 'false_positive' THEN l.alert_id
                       END) AS false_positives
                FROM case_alert_links l
                LEFT JOIN alert_dispositions d
                  ON d.alert_id = l.alert_id AND d.case_id = l.case_id
                WHERE l.case_id = ?
                """,
                (row["case_id"],),
            ).fetchone()
            total = int(aggregate["total"] or 0)
            false_positives = int(aggregate["false_positives"] or 0)
            return {
                "alert_id": str(row["alert_id"]),
                "case_id": str(row["case_id"]),
                "disposition": str(row["disposition"]),
                "case_alert_count": total,
                "case_false_positive_count": false_positives,
                "case_can_close_as_false_positive": total > 0 and false_positives == total,
                "updated_at_ms": int(row["updated_at_ms"]),
            }

    # ---- mapping profiles -------------------------------------------------

    def save_mapping_profile(self, profile: dict[str, Any], _commit: bool = True) -> None:
        with self._lock:
            now = now_ms()
            existing = self.conn.execute(
                "SELECT created_at_ms FROM mapping_profiles WHERE profile_id = ?", (profile["profile_id"],)
            ).fetchone()
            created = existing["created_at_ms"] if existing else profile.get("created_at_ms", now)
            self.conn.execute(
                """
                INSERT OR REPLACE INTO mapping_profiles
                (profile_id, name, version, description, enabled, profile_json, created_at_ms, updated_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile["profile_id"],
                    profile["name"],
                    profile["version"],
                    profile.get("description", ""),
                    1 if profile.get("enabled", True) else 0,
                    profile["profile_json"],
                    created,
                    now,
                ),
            )
            if _commit:
                self.conn.commit()

    def delete_mapping_profile(self, profile_id: str, _commit: bool = True) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM mapping_profiles WHERE profile_id = ?", (profile_id,))
            if _commit:
                self.conn.commit()

    def list_mapping_profiles(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT profile_id, name, version, description, enabled, profile_json, created_at_ms, updated_at_ms
                FROM mapping_profiles ORDER BY updated_at_ms DESC
                """
            ).fetchall()
            return [self._mapping_profile_row(row) for row in rows]

    def get_mapping_profile(self, profile_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                """
                SELECT profile_id, name, version, description, enabled, profile_json, created_at_ms, updated_at_ms
                FROM mapping_profiles WHERE profile_id = ?
                """,
                (profile_id,),
            ).fetchone()
            return self._mapping_profile_row(row) if row else None

    def _mapping_profile_row(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["enabled"] = bool(item["enabled"])
        item["profile"] = json.loads(item.pop("profile_json"))
        return item

    # ---- multi-layer memory repository (see docs/MEMORY.md, architecture §8) ----

    _MEMORY_COLUMNS = (
        "memory_id, layer, namespace, retrieval_key, content, source_case_id, scope, "
        "trust_level, status, sensitivity_ok, approved_by, expires_at_ms, created_at_ms, updated_at_ms"
    )

    def save_memory(self, record: dict[str, Any], _commit: bool = True) -> None:
        with self._lock:
            ts = now_ms()
            self.conn.execute(
                """
                INSERT OR REPLACE INTO memory_entries
                (memory_id, layer, namespace, retrieval_key, content, source_case_id, scope,
                 trust_level, status, sensitivity_ok, approved_by, expires_at_ms, created_at_ms, updated_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["memory_id"],
                    record.get("layer", "product_long_term"),
                    record["namespace"],
                    record.get("retrieval_key", ""),
                    record["content"],
                    record.get("source_case_id", ""),
                    record.get("scope", ""),
                    record.get("trust_level", "low"),
                    record.get("status", "active"),
                    1 if record.get("sensitivity_ok", True) else 0,
                    record.get("approved_by"),
                    record.get("expires_at_ms"),
                    ts,
                    ts,
                ),
            )
            if _commit:
                self.conn.commit()

    def update_memory(self, memory_id: str, _commit: bool = True, **fields: Any) -> bool:
        with self._lock:
            if not fields:
                return False
            allowed = {
                "layer", "namespace", "retrieval_key", "content", "source_case_id", "scope",
                "trust_level", "status", "sensitivity_ok", "approved_by", "expires_at_ms",
            }
            sets: list[str] = []
            vals: list[Any] = []
            for key, value in fields.items():
                if key in allowed:
                    if key == "sensitivity_ok":
                        value = 1 if value else 0
                    sets.append(f"{key} = ?")
                    vals.append(value)
            if not sets:
                return False
            sets.append("updated_at_ms = ?")
            vals.append(now_ms())
            vals.append(memory_id)
            cur = self.conn.execute(
                f"UPDATE memory_entries SET {', '.join(sets)} WHERE memory_id = ?", vals
            )
            if _commit:
                self.conn.commit()
            return cur.rowcount > 0

    def get_memory(self, memory_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                f"SELECT {self._MEMORY_COLUMNS} FROM memory_entries WHERE memory_id = ?", (memory_id,)
            ).fetchone()
            return dict(row) if row else None

    def query_case_memory(
        self,
        source_case_id: str,
        *,
        layer: str | None = None,
        statuses: tuple[str, ...] = (),
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Load memory owned by one Case without a broad namespace scan."""
        with self._lock:
            clauses = ["source_case_id = ?"]
            params: list[Any] = [source_case_id]
            if layer:
                clauses.append("layer = ?")
                params.append(layer)
            if statuses:
                placeholders = ",".join("?" for _ in statuses)
                clauses.append(f"status IN ({placeholders})")
                params.extend(statuses)
            rows = self.conn.execute(
                f"""
                SELECT {self._MEMORY_COLUMNS} FROM memory_entries
                WHERE {' AND '.join(clauses)}
                ORDER BY updated_at_ms DESC, memory_id ASC
                LIMIT ?
                """,
                (*params, max(1, min(int(limit), 500))),
            ).fetchall()
            return [dict(row) for row in rows]

    def query_memory(
        self,
        layer: str | None = None,
        namespace: str | None = None,
        status: str | None = None,
        retrieval_key: str | None = None,
        query: str | None = None,
        limit: int = 50,
        offset: int = 0,
        include_expired: bool = False,
    ) -> list[dict[str, Any]]:
        with self._lock:
            clauses: list[str] = []
            params: list[Any] = []
            if layer:
                clauses.append("layer = ?")
                params.append(layer)
            if namespace:
                clauses.append("namespace = ?")
                params.append(namespace)
            if retrieval_key:
                clauses.append("retrieval_key = ?")
                params.append(retrieval_key)
            if status:
                clauses.append("status = ?")
                params.append(status)
            elif not include_expired:
                # live memories only: active or pending approval
                clauses.append("status IN ('active', 'pending_approval')")
            if query:
                escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                pattern = f"%{escaped}%"
                clauses.append(
                    "(memory_id LIKE ? ESCAPE '\\' OR namespace LIKE ? ESCAPE '\\' "
                    "OR retrieval_key LIKE ? ESCAPE '\\' OR source_case_id LIKE ? ESCAPE '\\' "
                    "OR scope LIKE ? ESCAPE '\\' OR content LIKE ? ESCAPE '\\')"
                )
                params.extend([pattern] * 6)
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            rows = self.conn.execute(
                f"SELECT {self._MEMORY_COLUMNS} FROM memory_entries {where} "
                "ORDER BY created_at_ms DESC, memory_id ASC LIMIT ? OFFSET ?",
                (*params, limit, max(0, int(offset))),
            ).fetchall()
            return [dict(row) for row in rows]

    def count_memory(
        self,
        layer: str | None = None,
        namespace: str | None = None,
        status: str | None = None,
        retrieval_key: str | None = None,
        query: str | None = None,
        include_expired: bool = False,
    ) -> int:
        with self._lock:
            clauses: list[str] = []
            params: list[Any] = []
            if layer:
                clauses.append("layer = ?")
                params.append(layer)
            if namespace:
                clauses.append("namespace = ?")
                params.append(namespace)
            if retrieval_key:
                clauses.append("retrieval_key = ?")
                params.append(retrieval_key)
            if status:
                clauses.append("status = ?")
                params.append(status)
            elif not include_expired:
                clauses.append("status IN ('active', 'pending_approval')")
            if query:
                escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                pattern = f"%{escaped}%"
                clauses.append(
                    "(memory_id LIKE ? ESCAPE '\\' OR namespace LIKE ? ESCAPE '\\' "
                    "OR retrieval_key LIKE ? ESCAPE '\\' OR source_case_id LIKE ? ESCAPE '\\' "
                    "OR scope LIKE ? ESCAPE '\\' OR content LIKE ? ESCAPE '\\')"
                )
                params.extend([pattern] * 6)
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            row = self.conn.execute(
                f"SELECT COUNT(*) AS count FROM memory_entries {where}", params
            ).fetchone()
            return int(row["count"])

    def query_matchable_product_memory(
        self,
        product: str,
        now_ms_value: int,
        limit: int = 500,
        lookup_keys: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return the broad governed candidate pool before matcher hard filters."""
        with self._lock:
            exact_keys = sorted(
                {
                    str(key).strip().lower()
                    for key in lookup_keys or []
                    if str(key).strip()
                }
            )[:32]
            if exact_keys:
                placeholders = ",".join("?" for _ in exact_keys)
                priority = f"CASE WHEN lower(retrieval_key) IN ({placeholders}) THEN 0 ELSE 1 END, "
            else:
                priority = ""
            rows = self.conn.execute(
                f"""
                SELECT {self._MEMORY_COLUMNS} FROM memory_entries
                WHERE layer = 'product_long_term'
                  AND namespace = ?
                  AND status = 'active'
                  AND trust_level IN ('medium', 'high')
                  AND sensitivity_ok = 1
                  AND COALESCE(approved_by, '') != ''
                  AND (expires_at_ms IS NULL OR expires_at_ms > ?)
                ORDER BY {priority}updated_at_ms DESC, memory_id ASC
                LIMIT ?
                """,
                (
                    f"product/{product.lower()}",
                    now_ms_value,
                    *exact_keys,
                    max(1, min(int(limit), 500)),
                ),
            ).fetchall()
            return [dict(row) for row in rows]

    def insert_memory_matches(
        self,
        event_id: str,
        alert_id: str,
        case_id: str,
        analysis_run_id: str,
        matcher_version: str,
        final_effect: str,
        candidates: list[dict[str, Any]],
        selected_memory_id: str | None = None,
        attack_signal_veto: bool = False,
        attack_signal_reasons: list[str] | None = None,
        config_snapshot: dict[str, Any] | None = None,
        _commit: bool = True,
    ) -> None:
        with self._lock:
            created = now_ms()
            for candidate in candidates:
                memory_id = str(candidate["memory_id"])
                rank = int(candidate.get("rank") or 0)
                selected = rank == 1 if selected_memory_id is None else memory_id == selected_memory_id
                candidate_final_effect = final_effect if selected else "none"
                digest = hashlib.sha256(f"{analysis_run_id}\0{memory_id}".encode("utf-8")).hexdigest()[:24]
                self.conn.execute(
                    """
                    INSERT INTO memory_matches
                    (match_id, event_id, alert_id, case_id, analysis_run_id, memory_id,
                     matcher_version, rank, structured_score, semantic_score, retrieval_score,
                     overall_score, decision, final_effect, matched_features_json,
                     score_breakdown_json, match_level, title_eligible, comparison_json,
                     apply_threshold, policy_effect, selected_candidate, attack_signal_veto,
                     attack_signal_reasons_json, config_snapshot_json, created_at_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(analysis_run_id, memory_id) DO UPDATE SET
                      matcher_version = excluded.matcher_version,
                      rank = excluded.rank,
                      structured_score = excluded.structured_score,
                      semantic_score = excluded.semantic_score,
                      retrieval_score = excluded.retrieval_score,
                      overall_score = excluded.overall_score,
                      decision = excluded.decision,
                      final_effect = excluded.final_effect,
                      matched_features_json = excluded.matched_features_json,
                      score_breakdown_json = excluded.score_breakdown_json,
                      match_level = excluded.match_level,
                      title_eligible = excluded.title_eligible,
                      comparison_json = excluded.comparison_json,
                      apply_threshold = excluded.apply_threshold,
                      policy_effect = excluded.policy_effect,
                      selected_candidate = excluded.selected_candidate,
                      attack_signal_veto = excluded.attack_signal_veto,
                      attack_signal_reasons_json = excluded.attack_signal_reasons_json,
                      config_snapshot_json = excluded.config_snapshot_json,
                      created_at_ms = excluded.created_at_ms
                    """,
                    (
                        f"mm_{digest}", event_id, alert_id, case_id, analysis_run_id, memory_id,
                        matcher_version, rank,
                        float(candidate.get("structured_score") or 0),
                        float(candidate.get("semantic_score") or 0),
                        float(candidate.get("retrieval_score") or 0),
                        float(candidate.get("overall_score") or 0),
                        str(candidate.get("decision") or "ignored"), candidate_final_effect,
                        json.dumps(candidate.get("matched_features") or [], ensure_ascii=False, sort_keys=True),
                        json.dumps(candidate.get("score_breakdown") or {}, ensure_ascii=False, sort_keys=True),
                        str(candidate.get("match_level") or "weak"),
                        1 if candidate.get("title_eligible") else 0,
                        json.dumps(candidate.get("comparison") or {}, ensure_ascii=False, sort_keys=True),
                        float(candidate.get("apply_threshold") or 1.0),
                        str(candidate.get("policy_effect") or "review_only"),
                        1 if selected else 0,
                        1 if attack_signal_veto else 0,
                        json.dumps(attack_signal_reasons or [], ensure_ascii=False, sort_keys=True),
                        json.dumps(config_snapshot or {}, ensure_ascii=False, sort_keys=True),
                        created,
                    ),
                )
            if _commit:
                self.conn.commit()

    def list_memory_matches(
        self,
        memory_id: str | None = None,
        event_id: str | None = None,
        case_id: str | None = None,
        decision: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        with self._lock:
            clauses: list[str] = []
            params: list[Any] = []
            for column, value in (
                ("memory_id", memory_id),
                ("event_id", event_id),
                ("case_id", case_id),
                ("decision", decision),
            ):
                if value:
                    clauses.append(f"{column} = ?")
                    params.append(value)
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            rows = self.conn.execute(
                f"""
                SELECT match_id, event_id, alert_id, case_id, analysis_run_id, memory_id,
                       matcher_version, rank, structured_score, semantic_score, retrieval_score,
                       overall_score, decision, final_effect, matched_features_json,
                       score_breakdown_json, match_level, title_eligible, comparison_json,
                       apply_threshold, policy_effect, selected_candidate, attack_signal_veto,
                       attack_signal_reasons_json, config_snapshot_json, created_at_ms
                FROM memory_matches {where}
                ORDER BY created_at_ms DESC, overall_score DESC, match_id ASC
                LIMIT ? OFFSET ?
                """,
                (*params, max(1, min(int(limit), 500)), max(0, int(offset))),
            ).fetchall()
            output: list[dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                item["matched_features"] = json.loads(item.pop("matched_features_json"))
                item["score_breakdown"] = json.loads(item.pop("score_breakdown_json"))
                item["comparison"] = json.loads(item.pop("comparison_json"))
                item["attack_signal_reasons"] = json.loads(item.pop("attack_signal_reasons_json"))
                item["config_snapshot"] = json.loads(item.pop("config_snapshot_json"))
                item["title_eligible"] = bool(item["title_eligible"])
                item["selected_candidate"] = bool(item["selected_candidate"])
                item["attack_signal_veto"] = bool(item["attack_signal_veto"])
                output.append(item)
            return output

    def count_memory_matches(
        self,
        memory_id: str | None = None,
        event_id: str | None = None,
        case_id: str | None = None,
        decision: str | None = None,
    ) -> int:
        with self._lock:
            clauses: list[str] = []
            params: list[Any] = []
            for column, value in (
                ("memory_id", memory_id),
                ("event_id", event_id),
                ("case_id", case_id),
                ("decision", decision),
            ):
                if value:
                    clauses.append(f"{column} = ?")
                    params.append(value)
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            row = self.conn.execute(
                f"SELECT COUNT(*) AS count FROM memory_matches {where}", params
            ).fetchone()
            return int(row["count"])

    def memory_governance_summary(self, now_ms_value: int, review_before_ms: int) -> dict[str, Any]:
        """Aggregate governance counts without loading memory content into application memory."""
        with self._lock:
            by_status = {
                row["status"]: row["count"]
                for row in self.conn.execute(
                    "SELECT status, COUNT(*) AS count FROM memory_entries GROUP BY status"
                ).fetchall()
            }
            by_layer = {
                row["layer"]: row["count"]
                for row in self.conn.execute(
                    "SELECT layer, COUNT(*) AS count FROM memory_entries GROUP BY layer"
                ).fetchall()
            }
            by_trust = {
                row["trust_level"]: row["count"]
                for row in self.conn.execute(
                    "SELECT trust_level, COUNT(*) AS count FROM memory_entries GROUP BY trust_level"
                ).fetchall()
            }
            expiring_soon = self.conn.execute(
                """
                SELECT COUNT(*) AS count FROM memory_entries
                WHERE status = 'active' AND expires_at_ms IS NOT NULL
                  AND expires_at_ms > ? AND expires_at_ms <= ?
                """,
                (now_ms_value, now_ms_value + 30 * 24 * 3600 * 1000),
            ).fetchone()["count"]
            overdue_review = self.conn.execute(
                """
                SELECT COUNT(*) AS count FROM memory_entries
                WHERE layer = 'product_long_term' AND status = 'active' AND updated_at_ms <= ?
                """,
                (review_before_ms,),
            ).fetchone()["count"]
            total_events = self.conn.execute("SELECT COUNT(*) AS count FROM memory_events").fetchone()["count"]
            total_matches = self.conn.execute("SELECT COUNT(*) AS count FROM memory_matches").fetchone()["count"]
            applied_matches = self.conn.execute(
                "SELECT COUNT(*) AS count FROM memory_matches WHERE decision IN ('downgraded_to_benign', 'classification_reinforced')"
            ).fetchone()["count"]
            return {
                "total": sum(by_status.values()),
                "by_status": by_status,
                "by_layer": by_layer,
                "by_trust": by_trust,
                "expiring_soon": expiring_soon,
                "overdue_review": overdue_review,
                "total_events": total_events,
                "total_matches": total_matches,
                "applied_matches": applied_matches,
                "generated_at_ms": now_ms_value,
            }

    def memory_due_for_expiry(self, now_ms_value: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                f"""
                SELECT {self._MEMORY_COLUMNS} FROM memory_entries
                WHERE status = 'active' AND expires_at_ms IS NOT NULL AND expires_at_ms <= ?
                ORDER BY expires_at_ms ASC
                """,
                (now_ms_value,),
            ).fetchall()
            return [dict(row) for row in rows]

    def memory_due_for_review(self, layer: str, before_ms: int, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                f"""
                SELECT {self._MEMORY_COLUMNS} FROM memory_entries
                WHERE layer = ? AND status = 'active' AND created_at_ms <= ?
                ORDER BY created_at_ms ASC LIMIT ?
                """,
                (layer, before_ms, limit),
            ).fetchall()
            return [dict(row) for row in rows]

    def insert_memory_event(
        self, event_id: str, memory_id: str, layer: str, event_type: str, actor: str, detail: dict[str, Any],
        _commit: bool = True,
    ) -> None:
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO memory_events
                (event_id, memory_id, layer, event_type, actor, detail_json, created_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (event_id, memory_id, layer, event_type, actor, json.dumps(detail, ensure_ascii=False, sort_keys=True), now_ms()),
            )
            if _commit:
                self.conn.commit()

    def list_memory_events(
        self,
        memory_id: str | None = None,
        event_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        with self._lock:
            clauses: list[str] = []
            params: list[Any] = []
            if memory_id:
                clauses.append("memory_id = ?")
                params.append(memory_id)
            if event_type:
                clauses.append("event_type = ?")
                params.append(event_type)
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            rows = self.conn.execute(
                f"""
                SELECT event_id, memory_id, layer, event_type, actor, detail_json, created_at_ms
                FROM memory_events {where}
                ORDER BY created_at_ms DESC, event_id ASC LIMIT ? OFFSET ?
                """,
                (*params, limit, max(0, int(offset))),
            ).fetchall()
            out = []
            for row in rows:
                item = dict(row)
                item["detail"] = json.loads(item.pop("detail_json"))
                out.append(item)
            return out

    def count_memory_events(
        self, memory_id: str | None = None, event_type: str | None = None
    ) -> int:
        with self._lock:
            clauses: list[str] = []
            params: list[Any] = []
            if memory_id:
                clauses.append("memory_id = ?")
                params.append(memory_id)
            if event_type:
                clauses.append("event_type = ?")
                params.append(event_type)
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            row = self.conn.execute(
                f"SELECT COUNT(*) AS count FROM memory_events {where}", params
            ).fetchone()
            return int(row["count"])

    def load_evidence_refs(
        self,
        case_id: str,
        exclude_event_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Immutable evidence store: read-only, already-desensitized refs from normalized events."""
        with self._lock:
            excluded = str(exclude_event_id or "")
            rows = self.conn.execute(
                """
                SELECT ne.event_id, ne.product, ne.evidence_json, ne.sensitivity_tags_json
                FROM case_alert_links l
                JOIN normalized_events ne ON ne.event_id = l.event_id
                WHERE l.case_id = ?
                  AND (? = '' OR ne.event_id != ?)
                ORDER BY l.created_at_ms ASC
                """,
                (case_id, excluded, excluded),
            ).fetchall()
            refs: list[dict[str, Any]] = []
            for row in rows:
                evidence = json.loads(row["evidence_json"])
                tags = json.loads(row["sensitivity_tags_json"])
                for item in evidence:
                    refs.append(
                        {
                            "ref": item.get("ref"),
                            "source": item.get("source", row["product"]),
                            "type": item.get("type"),
                            "summary": item.get("why_it_matters") or item.get("value"),
                            "sensitivity_tags": tags,
                        }
                    )
            return refs

    def insert_audit(
        self,
        audit_id: str,
        trace_id: str,
        actor: str,
        action: str,
        detail: dict[str, Any],
        _commit: bool = True,
    ) -> None:
        with self._lock:
            case_id = str(detail.get("case_id") or "")
            memory_id = str(detail.get("memory_id") or "")
            if not case_id or not memory_id:
                linked = self.conn.execute(
                    """
                    SELECT case_id, memory_id FROM audit_log
                    WHERE trace_id = ? AND (case_id != '' OR memory_id != '')
                    ORDER BY created_at_ms DESC LIMIT 1
                    """,
                    (trace_id,),
                ).fetchone()
                if linked:
                    case_id = case_id or str(linked["case_id"] or "")
                    memory_id = memory_id or str(linked["memory_id"] or "")
            if not case_id and self.conn.execute(
                "SELECT 1 FROM cases WHERE case_id = ?", (trace_id,)
            ).fetchone():
                case_id = trace_id
            if not memory_id and self.conn.execute(
                "SELECT 1 FROM memory_entries WHERE memory_id = ?", (trace_id,)
            ).fetchone():
                memory_id = trace_id
            self.conn.execute(
                """
                INSERT INTO audit_log
                (audit_id, trace_id, case_id, memory_id, actor, action, detail_json, created_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    trace_id,
                    case_id,
                    memory_id,
                    actor,
                    action,
                    json.dumps(detail, ensure_ascii=False, sort_keys=True),
                    now_ms(),
                ),
            )
            if _commit:
                self.conn.commit()

    def link_audit_trace_to_case(
        self,
        trace_id: str,
        case_id: str,
        _commit: bool = True,
    ) -> int:
        """Attach pre-correlation audit rows to their resolved Case."""
        with self._lock:
            cur = self.conn.execute(
                "UPDATE audit_log SET case_id = ? WHERE trace_id = ? AND case_id = ''",
                (case_id, trace_id),
            )
            if _commit:
                self.conn.commit()
            return cur.rowcount

    def list_cases(
        self,
        limit: int = 50,
        offset: int = 0,
        product: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        active_only: bool = False,
        terminal_only: bool = False,
        created_from_ms: int | None = None,
        created_to_ms: int | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            clauses: list[str] = []
            params: list[Any] = []
            if product:
                clauses.append("c.product = ?")
                params.append(product.lower())
            if severity:
                clauses.append("c.severity = ?")
                params.append(severity.lower())
            if status:
                clauses.append("c.status = ?")
                params.append(status.lower())
            if active_only:
                # Filter before applying the page limit.  Filtering a mixed,
                # limited result set in the browser can incorrectly make the
                # active queue appear empty when recent terminal Cases fill it.
                clauses.append("c.status NOT IN ('closed', 'false_positive')")
            if terminal_only:
                clauses.append("c.status IN ('closed', 'false_positive')")
            if created_from_ms is not None:
                clauses.append("c.created_at_ms >= ?")
                params.append(created_from_ms)
            if created_to_ms is not None:
                clauses.append("c.created_at_ms <= ?")
                params.append(created_to_ms)
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            rows = self.conn.execute(
                f"""
                SELECT
                  c.case_id,
                  c.product,
                  c.status,
                  c.severity,
                  c.classification,
                  c.confidence,
                  c.summary,
                  c.created_at_ms,
                  c.updated_at_ms,
                  COALESCE((
                    SELECT COUNT(DISTINCT l.alert_id)
                    FROM case_alert_links l WHERE l.case_id = c.case_id
                  ), 0) AS alert_count,
                  (
                    SELECT l.alert_id FROM case_alert_links l
                    WHERE l.case_id = c.case_id
                    ORDER BY l.created_at_ms DESC LIMIT 1
                  ) AS latest_alert_id
                FROM cases c {where}
                ORDER BY c.created_at_ms DESC, c.case_id ASC LIMIT ? OFFSET ?
                """,
                (*params, limit, max(0, int(offset))),
            ).fetchall()
            return [dict(row) for row in rows]

    def count_cases(
        self,
        product: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        active_only: bool = False,
        terminal_only: bool = False,
        created_from_ms: int | None = None,
        created_to_ms: int | None = None,
    ) -> int:
        with self._lock:
            clauses: list[str] = []
            params: list[Any] = []
            if product:
                clauses.append("c.product = ?")
                params.append(product.lower())
            if severity:
                clauses.append("c.severity = ?")
                params.append(severity.lower())
            if status:
                clauses.append("c.status = ?")
                params.append(status.lower())
            if active_only:
                clauses.append("c.status NOT IN ('closed', 'false_positive')")
            if terminal_only:
                clauses.append("c.status IN ('closed', 'false_positive')")
            if created_from_ms is not None:
                clauses.append("c.created_at_ms >= ?")
                params.append(created_from_ms)
            if created_to_ms is not None:
                clauses.append("c.created_at_ms <= ?")
                params.append(created_to_ms)
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            row = self.conn.execute(
                f"SELECT COUNT(*) AS count FROM cases c {where}", params
            ).fetchone()
            return int(row["count"])

    def case_distribution_summary(self) -> dict[str, Any]:
        """Return all-Case dashboard distributions without page-size truncation."""
        with self._lock:
            total_row = self.conn.execute(
                "SELECT COUNT(*) AS count FROM cases"
            ).fetchone()
            product_rows = self.conn.execute(
                """
                SELECT
                  CASE
                    WHEN TRIM(COALESCE(product, '')) = '' THEN 'unknown'
                    ELSE LOWER(TRIM(product))
                  END AS value,
                  COUNT(*) AS count
                FROM cases
                GROUP BY value
                ORDER BY count DESC, value ASC
                """
            ).fetchall()
            classification_rows = self.conn.execute(
                """
                SELECT
                  CASE
                    WHEN TRIM(COALESCE(classification, '')) = '' THEN 'unknown'
                    ELSE LOWER(TRIM(classification))
                  END AS value,
                  COUNT(*) AS count
                FROM cases
                GROUP BY value
                ORDER BY count DESC, value ASC
                """
            ).fetchall()
            return {
                "total": int(total_row["count"]),
                "products": [
                    {"value": str(row["value"]), "count": int(row["count"])}
                    for row in product_rows
                ],
                "classifications": [
                    {"value": str(row["value"]), "count": int(row["count"])}
                    for row in classification_rows
                ],
            }

    def get_case_detail_page(
        self,
        case_id: str,
        section: str,
        *,
        limit: int = 5,
        offset: int = 0,
    ) -> dict[str, Any] | None:
        """Load only the requested Case detail records.

        Dedicated detail pages must not deserialize the complete Case graph. RASP
        payloads and analysis results can be large, so each section is queried and
        paginated independently.
        """
        page_limit = max(1, min(int(limit), 50))
        page_offset = max(0, int(offset))
        with self._lock:
            case_row = self.conn.execute(
                """
                SELECT case_id, product, status, severity, classification,
                       confidence, summary, updated_at_ms
                FROM cases WHERE case_id = ?
                """,
                (case_id,),
            ).fetchone()
            if not case_row:
                return None
            case_summary = dict(case_row)

            if section == "raw-alerts":
                total = int(
                    self.conn.execute(
                        """
                        SELECT COUNT(DISTINCT l.alert_id) AS count
                        FROM case_alert_links l
                        JOIN raw_alerts ra ON ra.alert_id = l.alert_id
                        WHERE l.case_id = ?
                        """,
                        (case_id,),
                    ).fetchone()["count"]
                )
                rows = self.conn.execute(
                    """
                    WITH latest_links AS (
                      SELECT l.*,
                             ROW_NUMBER() OVER (
                               PARTITION BY l.alert_id
                               ORDER BY l.created_at_ms DESC, l.event_id DESC
                             ) AS link_rank
                      FROM case_alert_links l
                      WHERE l.case_id = ?
                    )
                    SELECT l.alert_id, l.event_id, l.created_at_ms AS linked_at_ms,
                           ra.source, ra.product, ra.event_type, ra.severity,
                           ra.timestamp, ra.payload_json, ra.created_at_ms,
                           ad.disposition, ad.actor, ad.reason,
                           ad.updated_at_ms AS disposition_updated_at_ms
                    FROM latest_links l
                    JOIN raw_alerts ra ON ra.alert_id = l.alert_id
                    LEFT JOIN alert_dispositions ad
                      ON ad.case_id = l.case_id AND ad.alert_id = l.alert_id
                    WHERE l.link_rank = 1
                    ORDER BY l.created_at_ms DESC
                    LIMIT ? OFFSET ?
                    """,
                    (case_id, page_limit, page_offset),
                ).fetchall()
                items = []
                for row in rows:
                    disposition = None
                    if row["disposition"]:
                        disposition = {
                            "case_id": case_id,
                            "status": row["disposition"],
                            "actor": row["actor"],
                            "reason": row["reason"],
                            "updated_at_ms": row["disposition_updated_at_ms"],
                        }
                    items.append(
                        {
                            "record_type": "raw_alert",
                            "alert_id": row["alert_id"],
                            "event_id": row["event_id"],
                            "linked_at_ms": row["linked_at_ms"],
                            "disposition": disposition,
                            "data": {
                                "alert_id": row["alert_id"],
                                "source": row["source"],
                                "product": row["product"],
                                "event_type": row["event_type"],
                                "severity": row["severity"],
                                "timestamp": row["timestamp"],
                                "payload": json.loads(row["payload_json"]),
                                "created_at_ms": row["created_at_ms"],
                            },
                        }
                    )
            elif section == "normalized-evidence":
                total = int(
                    self.conn.execute(
                        """
                        SELECT COUNT(*) AS count
                        FROM case_alert_links l
                        JOIN normalized_events ne ON ne.event_id = l.event_id
                        WHERE l.case_id = ?
                        """,
                        (case_id,),
                    ).fetchone()["count"]
                )
                rows = self.conn.execute(
                    """
                    SELECT l.alert_id, l.event_id, l.created_at_ms AS linked_at_ms,
                           ne.source, ne.product, ne.event_type, ne.severity,
                           ne.timestamp, ne.entities_json, ne.evidence_json,
                           ne.sensitivity_tags_json, ne.created_at_ms
                    FROM case_alert_links l
                    JOIN normalized_events ne ON ne.event_id = l.event_id
                    WHERE l.case_id = ?
                    ORDER BY l.created_at_ms DESC
                    LIMIT ? OFFSET ?
                    """,
                    (case_id, page_limit, page_offset),
                ).fetchall()
                items = [
                    {
                        "record_type": "normalized_evidence",
                        "alert_id": row["alert_id"],
                        "event_id": row["event_id"],
                        "linked_at_ms": row["linked_at_ms"],
                        "data": {
                            "event_id": row["event_id"],
                            "source": row["source"],
                            "product": row["product"],
                            "event_type": row["event_type"],
                            "severity": row["severity"],
                            "timestamp": row["timestamp"],
                            "entities": json.loads(row["entities_json"]),
                            "evidence": json.loads(row["evidence_json"]),
                            "sensitivity_tags": json.loads(row["sensitivity_tags_json"]),
                            "created_at_ms": row["created_at_ms"],
                        },
                    }
                    for row in rows
                ]
            elif section == "analysis-runs":
                total = int(
                    self.conn.execute(
                        """
                        SELECT
                          (SELECT COUNT(*) FROM agent_runs WHERE case_id = ?)
                          + (SELECT COUNT(*) FROM validation_runs WHERE case_id = ?)
                          AS count
                        """,
                        (case_id, case_id),
                    ).fetchone()["count"]
                )
                rows = self.conn.execute(
                    """
                    SELECT record_type, record_id, event_id, actor, product,
                           version, status, result_json, created_at_ms
                    FROM (
                      SELECT 'agent_run' AS record_type, run_id AS record_id,
                             event_id, agent AS actor, product,
                             prompt_version AS version, '' AS status,
                             result_json, created_at_ms
                      FROM agent_runs WHERE case_id = ?
                      UNION ALL
                      SELECT 'validation_run' AS record_type,
                             validation_id AS record_id, event_id,
                             validator AS actor, '' AS product,
                             validator_version AS version, status,
                             result_json, created_at_ms
                      FROM validation_runs WHERE case_id = ?
                    )
                    ORDER BY created_at_ms DESC
                    LIMIT ? OFFSET ?
                    """,
                    (case_id, case_id, page_limit, page_offset),
                ).fetchall()
                validation_ids = [
                    str(row["record_id"])
                    for row in rows
                    if row["record_type"] == "validation_run"
                ]
                resolutions: dict[str, dict[str, Any]] = {}
                if validation_ids:
                    placeholders = ",".join("?" for _ in validation_ids)
                    for resolution in self.conn.execute(
                        f"""
                        SELECT validation_id, resolution_id, decision, actor,
                               reason, created_at_ms
                        FROM validation_review_resolutions
                        WHERE validation_id IN ({placeholders})
                        """,
                        validation_ids,
                    ).fetchall():
                        item = dict(resolution)
                        resolutions[str(item.pop("validation_id"))] = item
                items = []
                for row in rows:
                    result = json.loads(row["result_json"])
                    if row["record_type"] == "agent_run":
                        data = {
                            "run_id": row["record_id"],
                            "case_id": case_id,
                            "event_id": row["event_id"],
                            "agent": row["actor"],
                            "product": row["product"],
                            "prompt_version": row["version"],
                            "result": result,
                            "created_at_ms": row["created_at_ms"],
                        }
                    else:
                        data = result
                        resolution = resolutions.get(str(row["record_id"]))
                        if resolution:
                            data["manual_review_resolution"] = resolution
                    items.append({"record_type": row["record_type"], "data": data})
            else:
                raise ValueError("unsupported case detail section")

            return {
                "case": case_summary,
                "section": section,
                "count": total,
                "items": items,
                "pagination": {
                    "limit": page_limit,
                    "offset": page_offset,
                    "page": page_offset // page_limit + 1,
                    "total": total,
                    "total_pages": max(1, (total + page_limit - 1) // page_limit),
                },
            }

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            if not row:
                return None
            runs = self.conn.execute(
                "SELECT * FROM agent_runs WHERE case_id = ? ORDER BY created_at_ms DESC",
                (case_id,),
            ).fetchall()
            result = dict(row)
            parsed_runs = []
            for run in runs:
                item = dict(run)
                item["result"] = json.loads(item.pop("result_json"))
                parsed_runs.append(item)
            result["agent_runs"] = parsed_runs
            validations = self.conn.execute(
                """
                SELECT vr.result_json,
                       rr.resolution_id, rr.decision, rr.actor, rr.reason,
                       rr.created_at_ms AS resolution_created_at_ms
                FROM validation_runs vr
                LEFT JOIN validation_review_resolutions rr ON rr.validation_id = vr.validation_id
                WHERE vr.case_id = ?
                ORDER BY vr.created_at_ms DESC
                """,
                (case_id,),
            ).fetchall()
            parsed_validations = []
            for item in validations:
                validation = json.loads(item["result_json"])
                if item["resolution_id"]:
                    validation["manual_review_resolution"] = {
                        "resolution_id": item["resolution_id"],
                        "decision": item["decision"],
                        "actor": item["actor"],
                        "reason": item["reason"],
                        "created_at_ms": item["resolution_created_at_ms"],
                    }
                parsed_validations.append(validation)
            result["validation_runs"] = parsed_validations
            result["approvals"] = self.list_approvals(case_id=case_id, limit=100)
            result["memory_matches"] = self.list_memory_matches(case_id=case_id, limit=200)
            result["linked_alerts"] = self._linked_alerts_locked(case_id)
            return result

    def get_case_status(self, case_id: str) -> str | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT status FROM cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            return str(row["status"]) if row else None

    def get_case_triage(self, case_id: str) -> dict[str, Any] | None:
        """Load the bounded Case workbench graph without deserializing raw evidence."""
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM cases WHERE case_id = ?", (case_id,)
            ).fetchone()
            if not row:
                return None
            result = dict(row)

            run = self.conn.execute(
                """
                SELECT * FROM agent_runs
                WHERE case_id = ?
                ORDER BY created_at_ms DESC, run_id ASC
                LIMIT 1
                """,
                (case_id,),
            ).fetchone()
            if run:
                latest_run = dict(run)
                latest_run["result"] = json.loads(latest_run.pop("result_json"))
                result["agent_runs"] = [latest_run]
            else:
                result["agent_runs"] = []

            validation = self.conn.execute(
                """
                SELECT vr.result_json,
                       rr.resolution_id, rr.decision, rr.actor, rr.reason,
                       rr.created_at_ms AS resolution_created_at_ms
                FROM validation_runs vr
                LEFT JOIN validation_review_resolutions rr
                  ON rr.validation_id = vr.validation_id
                WHERE vr.case_id = ?
                ORDER BY vr.created_at_ms DESC, vr.validation_id ASC
                LIMIT 1
                """,
                (case_id,),
            ).fetchone()
            if validation:
                latest_validation = json.loads(validation["result_json"])
                if validation["resolution_id"]:
                    latest_validation["manual_review_resolution"] = {
                        "resolution_id": validation["resolution_id"],
                        "decision": validation["decision"],
                        "actor": validation["actor"],
                        "reason": validation["reason"],
                        "created_at_ms": validation["resolution_created_at_ms"],
                    }
                result["validation_runs"] = [latest_validation]
            else:
                result["validation_runs"] = []

            counts = self.conn.execute(
                """
                SELECT
                  (SELECT COUNT(DISTINCT l.alert_id) FROM case_alert_links l
                   JOIN raw_alerts ra ON ra.alert_id = l.alert_id
                   WHERE l.case_id = ?) AS raw_alerts,
                  (SELECT COUNT(*) FROM case_alert_links l
                   JOIN normalized_events ne ON ne.event_id = l.event_id
                   WHERE l.case_id = ?) AS normalized_evidence,
                  (SELECT COUNT(*) FROM agent_runs WHERE case_id = ?)
                    + (SELECT COUNT(*) FROM validation_runs WHERE case_id = ?)
                    AS analysis_runs
                """,
                (case_id, case_id, case_id, case_id),
            ).fetchone()
            result["detail_counts"] = {
                "raw_alerts": int(counts["raw_alerts"]),
                "normalized_evidence": int(counts["normalized_evidence"]),
                "analysis_runs": int(counts["analysis_runs"]),
            }
            result["approvals"] = self.list_approvals(case_id=case_id, limit=100)

            confirmations = self._confirmed_false_positive_memories_locked(case_id)
            links = self.conn.execute(
                """
                SELECT
                  l.case_id, l.alert_id, l.event_id,
                  l.created_at_ms AS linked_at_ms,
                  ra.source AS raw_source, ra.product AS raw_product,
                  ra.event_type AS raw_event_type, ra.severity AS raw_severity,
                  ra.timestamp AS raw_timestamp, ra.created_at_ms AS raw_created_at_ms,
                  CASE WHEN ra.payload_json IS NULL THEN NULL ELSE json_object(
                    'adapter', json_extract(ra.payload_json, '$.adapter'),
                    'rule_id', json_extract(ra.payload_json, '$.rule_id'),
                    'rule_name', json_extract(ra.payload_json, '$.rule_name'),
                    'app', json_extract(ra.payload_json, '$.app'),
                    'host', json_extract(ra.payload_json, '$.host'),
                    'src_host', json_extract(ra.payload_json, '$.src_host'),
                    'src_ip', json_extract(ra.payload_json, '$.src_ip'),
                    'dst_ip', json_extract(ra.payload_json, '$.dst_ip'),
                    'method', json_extract(ra.payload_json, '$.method'),
                    'uri', json_extract(ra.payload_json, '$.uri'),
                    'route', json_extract(ra.payload_json, '$.route'),
                    'headers', json_object(
                      'user-agent', json_extract(ra.payload_json, '$.headers."user-agent"')
                    ),
                    'matched_parameters', json_extract(ra.payload_json, '$.matched_parameters'),
                    'process_name', json_extract(ra.payload_json, '$.process_name'),
                    'parent_process', json_extract(ra.payload_json, '$.parent_process'),
                    'signature_status', json_extract(ra.payload_json, '$.signature_status'),
                    'sni', json_extract(ra.payload_json, '$.sni'),
                    'protocol', json_extract(ra.payload_json, '$.protocol'),
                    'dst_port', json_extract(ra.payload_json, '$.dst_port'),
                    'user', json_extract(ra.payload_json, '$.user'),
                    'mitre_tactic', json_extract(ra.payload_json, '$.mitre_tactic')
                  ) END AS compact_payload_json,
                  ne.source AS normalized_source, ne.product AS normalized_product,
                  ne.event_type AS normalized_event_type,
                  ne.severity AS normalized_severity,
                  ne.timestamp AS normalized_timestamp, ne.entities_json,
                  CASE WHEN json_type(ne.evidence_json) = 'array'
                       THEN json_array_length(ne.evidence_json) ELSE 0 END
                    AS evidence_count,
                  ne.created_at_ms AS normalized_created_at_ms,
                  ad.case_id AS disposition_case_id,
                  ad.disposition AS alert_disposition,
                  ad.actor AS disposition_actor, ad.reason AS disposition_reason,
                  ad.updated_at_ms AS disposition_updated_at_ms
                FROM case_alert_links l
                LEFT JOIN raw_alerts ra ON ra.alert_id = l.alert_id
                LEFT JOIN normalized_events ne ON ne.event_id = l.event_id
                LEFT JOIN alert_dispositions ad
                  ON ad.alert_id = l.alert_id AND ad.case_id = l.case_id
                WHERE l.case_id = ?
                ORDER BY l.created_at_ms DESC, l.alert_id ASC, l.event_id ASC
                """,
                (case_id,),
            ).fetchall()
            linked_alerts: list[dict[str, Any]] = []
            for link in links:
                raw_alert = None
                if link["compact_payload_json"] is not None:
                    raw_alert = {
                        "alert_id": link["alert_id"],
                        "source": link["raw_source"],
                        "product": link["raw_product"],
                        "event_type": link["raw_event_type"],
                        "severity": link["raw_severity"],
                        "timestamp": link["raw_timestamp"],
                        "payload": json.loads(link["compact_payload_json"]),
                        "created_at_ms": link["raw_created_at_ms"],
                    }
                normalized_event = None
                if link["entities_json"] is not None:
                    normalized_event = {
                        "event_id": link["event_id"],
                        "source": link["normalized_source"],
                        "product": link["normalized_product"],
                        "event_type": link["normalized_event_type"],
                        "severity": link["normalized_severity"],
                        "timestamp": link["normalized_timestamp"],
                        "entities": json.loads(link["entities_json"]),
                        "_evidence_count": int(link["evidence_count"] or 0),
                        "created_at_ms": link["normalized_created_at_ms"],
                    }
                disposition = None
                if link["alert_disposition"]:
                    disposition = {
                        "case_id": link["disposition_case_id"],
                        "status": link["alert_disposition"],
                        "actor": link["disposition_actor"],
                        "reason": link["disposition_reason"],
                        "updated_at_ms": link["disposition_updated_at_ms"],
                    }
                    confirmation = confirmations.get(str(link["alert_id"]))
                    if confirmation:
                        disposition["memory_confirmation"] = confirmation
                linked_alerts.append(
                    {
                        "case_id": link["case_id"],
                        "alert_id": link["alert_id"],
                        "event_id": link["event_id"],
                        "linked_at_ms": link["linked_at_ms"],
                        "disposition": disposition,
                        "raw_alert": raw_alert,
                        "normalized_event": normalized_event,
                    }
                )
            result["linked_alerts"] = linked_alerts
            return result

    def get_linked_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT case_id FROM case_alert_links WHERE alert_id = ? ORDER BY created_at_ms DESC LIMIT 1",
                (alert_id,),
            ).fetchone()
            if not row:
                return None
            for item in self._linked_alerts_locked(row["case_id"]):
                if item.get("alert_id") == alert_id:
                    return item
            return None

    def _linked_alerts_locked(self, case_id: str) -> list[dict[str, Any]]:
        """Caller must hold ``self._lock``. See ``get_case``/``get_linked_alert``."""
        rows = self.conn.execute(
            """
            SELECT
              l.case_id,
              l.alert_id,
              l.event_id,
              l.created_at_ms AS linked_at_ms,
              ra.source AS raw_source,
              ra.product AS raw_product,
              ra.event_type AS raw_event_type,
              ra.severity AS raw_severity,
              ra.timestamp AS raw_timestamp,
              ra.payload_json AS raw_payload_json,
              ra.created_at_ms AS raw_created_at_ms,
              ne.source AS normalized_source,
              ne.product AS normalized_product,
              ne.event_type AS normalized_event_type,
              ne.severity AS normalized_severity,
              ne.timestamp AS normalized_timestamp,
              ne.entities_json,
              ne.evidence_json,
              ne.sensitivity_tags_json,
              ne.created_at_ms AS normalized_created_at_ms,
              ad.case_id AS disposition_case_id,
              ad.disposition AS alert_disposition,
              ad.actor AS disposition_actor,
              ad.reason AS disposition_reason,
              ad.updated_at_ms AS disposition_updated_at_ms
            FROM case_alert_links l
            LEFT JOIN raw_alerts ra ON ra.alert_id = l.alert_id
            LEFT JOIN normalized_events ne ON ne.event_id = l.event_id
            LEFT JOIN alert_dispositions ad
              ON ad.alert_id = l.alert_id AND ad.case_id = l.case_id
            WHERE l.case_id = ?
            ORDER BY l.created_at_ms DESC
            """,
            (case_id,),
        ).fetchall()
        linked = []
        confirmations = self._confirmed_false_positive_memories_locked(case_id)
        for row in rows:
            item = dict(row)
            raw_alert = None
            if item.get("raw_payload_json") is not None:
                raw_alert = {
                    "alert_id": item["alert_id"],
                    "source": item["raw_source"],
                    "product": item["raw_product"],
                    "event_type": item["raw_event_type"],
                    "severity": item["raw_severity"],
                    "timestamp": item["raw_timestamp"],
                    "payload": json.loads(item["raw_payload_json"]),
                    "created_at_ms": item["raw_created_at_ms"],
                }
            normalized_event = None
            if item.get("entities_json") is not None:
                normalized_event = {
                    "event_id": item["event_id"],
                    "source": item["normalized_source"],
                    "product": item["normalized_product"],
                    "event_type": item["normalized_event_type"],
                    "severity": item["normalized_severity"],
                    "timestamp": item["normalized_timestamp"],
                    "entities": json.loads(item["entities_json"]),
                    "evidence": json.loads(item["evidence_json"]),
                    "sensitivity_tags": json.loads(item["sensitivity_tags_json"]),
                    "created_at_ms": item["normalized_created_at_ms"],
                }
            disposition = None
            if item.get("alert_disposition"):
                confirmation = (
                    confirmations.get(str(item["alert_id"]))
                    if item["alert_disposition"] == "false_positive"
                    else None
                )
                disposition = {
                    "case_id": item["disposition_case_id"],
                    "status": item["alert_disposition"],
                    "actor": item["disposition_actor"],
                    "reason": item["disposition_reason"],
                    "updated_at_ms": item["disposition_updated_at_ms"],
                }
                if confirmation:
                    disposition["memory_confirmation"] = confirmation
            linked.append(
                {
                    "case_id": item["case_id"],
                    "alert_id": item["alert_id"],
                    "event_id": item["event_id"],
                    "linked_at_ms": item["linked_at_ms"],
                    "disposition": disposition,
                    "raw_alert": raw_alert,
                    "normalized_event": normalized_event,
                }
            )
        return linked

    def _confirmed_false_positive_memories_locked(
        self, case_id: str
    ) -> dict[str, dict[str, Any]]:
        """Load all active human confirmations for a Case in one bounded scan."""
        rows = self.conn.execute(
            """
            SELECT memory_id, content, created_at_ms, updated_at_ms
            FROM memory_entries
            WHERE layer = 'product_long_term'
              AND status = 'active'
              AND source_case_id = ?
            ORDER BY created_at_ms DESC, memory_id ASC
            """,
            (case_id,),
        ).fetchall()
        confirmations: dict[str, dict[str, Any]] = {}
        for row in rows:
            try:
                content = json.loads(row["content"])
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(content, dict):
                continue
            alert_id = str(content.get("alert_id") or "")
            if (
                alert_id
                and alert_id not in confirmations
                and content.get("human_confirmed") is True
                and content.get("confirmation_type") == "business_false_positive"
                and str(content.get("case_id") or "") == case_id
            ):
                confirmations[alert_id] = {
                    "memory_id": row["memory_id"],
                    "created_at_ms": row["created_at_ms"],
                    "updated_at_ms": row["updated_at_ms"],
                }
        return confirmations

    def _confirmed_false_positive_memory_locked(
        self, alert_id: str, case_id: str
    ) -> dict[str, Any] | None:
        """Find the active human-confirmed memory for this exact alert/Case.

        ``alert_dispositions`` is intentionally not treated as proof that the
        memory write completed. Older databases can contain an orphaned or
        reused alert disposition, so the UI needs an independently persisted
        confirmation memory before it reports a successful memory write.
        Caller holds ``self._lock``; JSON parsing is kept in Python so legacy
        non-JSON memory content cannot make the SQL query fail.
        """
        return self._confirmed_false_positive_memories_locked(case_id).get(alert_id)

    def get_confirmed_false_positive_memory(
        self, alert_id: str, case_id: str
    ) -> dict[str, Any] | None:
        """Return the active human confirmation for one alert/Case pair."""
        with self._lock:
            return self._confirmed_false_positive_memory_locked(alert_id, case_id)

    @staticmethod
    def _case_response_artifact_row(
        row: sqlite3.Row,
        refs: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        payload = dict(row)
        payload["content"] = json.loads(payload.pop("content_json"))
        payload["validation"] = json.loads(payload.pop("validation_json"))
        payload["model_metadata"] = json.loads(
            payload.pop("model_metadata_json") or "{}"
        )
        payload["evidence_refs"] = list(refs or [])
        return payload

    @staticmethod
    def _response_agent_session_row(row: sqlite3.Row) -> dict[str, Any]:
        payload = dict(row)
        payload["plan"] = json.loads(payload.pop("plan_json") or "[]")
        payload["budget"] = json.loads(payload.pop("budget_json") or "{}")
        payload["usage"] = json.loads(payload.pop("usage_json") or "{}")
        payload["model_metadata"] = json.loads(
            payload.pop("model_metadata_json") or "{}"
        )
        payload.pop("source_json", None)
        return payload

    @staticmethod
    def _response_agent_step_row(row: sqlite3.Row) -> dict[str, Any]:
        payload = dict(row)
        payload["detail"] = json.loads(payload.pop("detail_json") or "{}")
        payload["evidence_refs"] = json.loads(
            payload.pop("evidence_refs_json") or "[]"
        )
        return payload

    @staticmethod
    def _response_agent_tool_call_row(row: sqlite3.Row) -> dict[str, Any]:
        payload = dict(row)
        payload["arguments"] = json.loads(payload.pop("arguments_json") or "{}")
        payload["result"] = json.loads(payload.pop("result_json") or "{}")
        payload["evidence_refs"] = json.loads(
            payload.pop("evidence_refs_json") or "[]"
        )
        return payload

    @staticmethod
    def _response_agent_report_row(
        row: sqlite3.Row,
        refs: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        payload = dict(row)
        payload["content"] = json.loads(payload.pop("content_json") or "{}")
        payload["validation"] = json.loads(payload.pop("validation_json") or "{}")
        payload["model_metadata"] = json.loads(
            payload.pop("model_metadata_json") or "{}"
        )
        payload["evidence_refs"] = list(refs or [])
        return payload

    def get_case_response_source(self, case_id: str) -> dict[str, Any] | None:
        """Load the bounded, structured facts used by the Case Response Pack.

        Raw alert payloads are intentionally excluded. The response workbench only
        receives normalized entities/evidence and governed workflow state.
        """
        with self._lock:
            case_row = self.conn.execute(
                """
                SELECT case_id, correlation_key, product, status, severity,
                       classification, confidence, summary, created_at_ms,
                       updated_at_ms, last_alert_at_ms, closed_at_ms
                FROM cases WHERE case_id = ?
                """,
                (case_id,),
            ).fetchone()
            if not case_row:
                return None

            event_rows = self.conn.execute(
                """
                SELECT * FROM (
                  SELECT l.alert_id, l.created_at_ms AS linked_at_ms,
                         ne.event_id, ne.source, ne.product, ne.event_type,
                         ne.severity, ne.timestamp, ne.entities_json,
                         ne.evidence_json, ne.sensitivity_tags_json,
                         ne.evidence_hash, ne.event_at_ms, ne.created_at_ms
                  FROM case_alert_links l
                  JOIN normalized_events ne ON ne.event_id = l.event_id
                  WHERE l.case_id = ?
                  ORDER BY ne.event_at_ms DESC, ne.created_at_ms DESC, ne.event_id DESC
                  LIMIT 2000
                )
                ORDER BY event_at_ms ASC, created_at_ms ASC, event_id ASC
                """,
                (case_id,),
            ).fetchall()
            events: list[dict[str, Any]] = []
            for row in event_rows:
                item = dict(row)
                item["entities"] = json.loads(item.pop("entities_json"))
                item["evidence"] = json.loads(item.pop("evidence_json"))
                item["sensitivity_tags"] = json.loads(
                    item.pop("sensitivity_tags_json")
                )
                events.append(item)

            run_rows = self.conn.execute(
                """
                SELECT run_id, case_id, event_id, agent, product,
                       prompt_version, result_json, created_at_ms
                FROM agent_runs WHERE case_id = ?
                ORDER BY created_at_ms DESC, run_id ASC
                LIMIT 100
                """,
                (case_id,),
            ).fetchall()
            agent_runs = []
            for row in run_rows:
                item = dict(row)
                item["result"] = json.loads(item.pop("result_json"))
                agent_runs.append(item)

            validation_rows = self.conn.execute(
                """
                SELECT validation_id, event_id, validator, validator_version,
                       status, result_json, created_at_ms
                FROM validation_runs WHERE case_id = ?
                ORDER BY created_at_ms DESC, validation_id ASC
                LIMIT 100
                """,
                (case_id,),
            ).fetchall()
            validations = []
            for row in validation_rows:
                item = dict(row)
                item["result"] = json.loads(item.pop("result_json"))
                validations.append(item)

            approval_rows = self.conn.execute(
                """
                SELECT * FROM action_approvals WHERE case_id = ?
                ORDER BY created_at_ms DESC, approval_id ASC
                LIMIT 200
                """,
                (case_id,),
            ).fetchall()
            approvals = []
            for row in approval_rows:
                item = dict(row)
                item["action"] = json.loads(item.pop("action_json"))
                approvals.append(item)
            approval_ids = [str(item["approval_id"]) for item in approvals]
            votes: list[dict[str, Any]] = []
            if approval_ids:
                placeholders = ",".join("?" for _ in approval_ids)
                votes = [
                    dict(row)
                    for row in self.conn.execute(
                        f"""
                        SELECT approval_id, actor, decision, reason, created_at_ms
                        FROM approval_votes
                        WHERE approval_id IN ({placeholders})
                        ORDER BY created_at_ms ASC, approval_id ASC, actor ASC
                        """,
                        approval_ids,
                    ).fetchall()
                ]

            task_rows = self.conn.execute(
                """
                SELECT * FROM response_tasks WHERE case_id = ?
                ORDER BY created_at_ms DESC, task_id ASC
                LIMIT 200
                """,
                (case_id,),
            ).fetchall()
            response_tasks = [self._response_task_row(row) for row in task_rows]
            task_ids = [str(item["task_id"]) for item in response_tasks]
            response_attempts: list[dict[str, Any]] = []
            if task_ids:
                placeholders = ",".join("?" for _ in task_ids)
                response_attempts = [
                    dict(row)
                    for row in self.conn.execute(
                        f"""
                        SELECT attempt_id, task_id, operation, attempt_no,
                               http_status, outcome, error, created_at_ms
                        FROM response_attempts
                        WHERE task_id IN ({placeholders})
                        ORDER BY created_at_ms ASC, attempt_id ASC
                        """,
                        task_ids,
                    ).fetchall()
                ]

            audit_actions = (
                "escalate_case_review",
                "confirm_case_attack",
                "close_case",
                "reopen_case",
                "manual_validation_review_continued",
                "analysis_replay_requested",
                "analysis_replay_completed",
            )
            placeholders = ",".join("?" for _ in audit_actions)
            audit_rows = self.conn.execute(
                f"""
                SELECT audit_id, actor, action, detail_json, created_at_ms
                FROM audit_log
                WHERE case_id = ? AND action IN ({placeholders})
                ORDER BY created_at_ms ASC, audit_id ASC
                LIMIT 500
                """,
                (case_id, *audit_actions),
            ).fetchall()
            audit_events = []
            for row in audit_rows:
                item = dict(row)
                item["detail"] = json.loads(item.pop("detail_json"))
                audit_events.append(item)

            return {
                "case": dict(case_row),
                "events": events,
                "agent_runs": agent_runs,
                "validations": validations,
                "approvals": approvals,
                "approval_votes": votes,
                "response_tasks": response_tasks,
                "response_attempts": response_attempts,
                "audit_events": audit_events,
            }

    def get_case_timeline_page(
        self, case_id: str, *, limit: int, offset: int
    ) -> dict[str, Any] | None:
        """Page the reconstructed Case timeline in SQLite with a stable order."""
        timeline_cte = """
            WITH linked_events AS (
              SELECT ne.event_id, ne.product, ne.event_type, ne.severity,
                     ne.timestamp, ne.event_at_ms, ne.created_at_ms,
                     CASE WHEN ne.event_id LIKE '%__replay_%'
                          THEN 1 ELSE 0 END AS is_replay
              FROM case_alert_links l
              JOIN normalized_events ne ON ne.event_id = l.event_id
              WHERE l.case_id = :case_id
            ),
            timeline(
              entry_id, kind, kind_order, source_id, source_event_id,
              occurred_at_ms, recorded_at_ms, time_basis, title, state,
              product, actor
            ) AS (
              SELECT 'event:' || event_id,
                     CASE WHEN is_replay = 1 THEN 'analysis_replay'
                          ELSE 'security_event' END,
                     CASE WHEN is_replay = 1 THEN 15 ELSE 10 END,
                     event_id, event_id,
                     CASE
                       WHEN is_replay = 1 THEN created_at_ms
                       WHEN julianday(timestamp) IS NOT NULL
                         THEN COALESCE(NULLIF(event_at_ms, 0), created_at_ms)
                       ELSE created_at_ms
                     END,
                     created_at_ms,
                     CASE
                       WHEN is_replay = 1 THEN 'system'
                       WHEN julianday(timestamp) IS NOT NULL THEN 'reported'
                       ELSE 'ingest_fallback'
                     END,
                     CASE
                       WHEN is_replay = 1
                         THEN 'Analysis replay created a normalized evidence version'
                       ELSE UPPER(product) || ' ' || event_type
                     END,
                     severity, product, ''
              FROM linked_events

              UNION ALL
              SELECT 'analysis:' || ar.run_id, 'analysis', 20,
                     ar.run_id, ar.event_id,
                     ar.created_at_ms, ar.created_at_ms, 'system',
                     'AI analysis completed', '', ar.product, ar.agent
              FROM agent_runs ar
              WHERE ar.case_id = :case_id

              UNION ALL
              SELECT 'validation:' || vr.validation_id, 'validation', 30,
                     vr.validation_id, vr.event_id,
                     vr.created_at_ms, vr.created_at_ms, 'system',
                     'Validation gate: ' || vr.status, vr.status, '', vr.validator
              FROM validation_runs vr
              WHERE vr.case_id = :case_id

              UNION ALL
              SELECT 'approval-request:' || aa.approval_id, 'approval_request', 40,
                     aa.approval_id, aa.event_id,
                     aa.created_at_ms, aa.created_at_ms, 'system',
                     'Approval requested', 'pending', '', aa.requested_by
              FROM action_approvals aa
              WHERE aa.case_id = :case_id

              UNION ALL
              SELECT 'approval-vote:' || av.approval_id || ':' || av.actor,
                     'approval_vote', 45,
                     av.approval_id, aa.event_id,
                     av.created_at_ms, av.created_at_ms, 'system',
                     'Approval vote: ' || av.decision, av.decision, '', av.actor
              FROM approval_votes av
              JOIN action_approvals aa ON aa.approval_id = av.approval_id
              WHERE aa.case_id = :case_id

              UNION ALL
              SELECT 'approval-decision:' || aa.approval_id,
                     'approval_decision', 50,
                     aa.approval_id, aa.event_id,
                     aa.updated_at_ms, aa.updated_at_ms, 'system',
                     'Approval decision: ' || aa.status, aa.status, '', aa.decided_by
              FROM action_approvals aa
              WHERE aa.case_id = :case_id
                AND aa.status != 'pending'
                AND aa.updated_at_ms >= aa.created_at_ms

              UNION ALL
              SELECT 'response-task:' || rt.task_id, 'response_task', 60,
                     rt.task_id, rt.event_id,
                     rt.created_at_ms, rt.created_at_ms, 'system',
                     'Response task created: ' || rt.action_type, 'created', '', rt.created_by
              FROM response_tasks rt
              WHERE rt.case_id = :case_id

              UNION ALL
              SELECT 'response-attempt:' || ra.attempt_id, 'response_attempt', 65,
                     ra.attempt_id, rt.event_id,
                     ra.created_at_ms, ra.created_at_ms, 'system',
                     'Response ' || ra.operation || ': ' || ra.outcome,
                     ra.outcome, '', ''
              FROM response_attempts ra
              JOIN response_tasks rt ON rt.task_id = ra.task_id
              WHERE rt.case_id = :case_id

              UNION ALL
              SELECT 'response-task-state:' || rt.task_id || ':' || rt.updated_at_ms,
                     'response_task_state', 70,
                     rt.task_id, rt.event_id,
                     rt.updated_at_ms, rt.updated_at_ms, 'system',
                     'Response task state: ' || rt.status, rt.status, '', ''
              FROM response_tasks rt
              WHERE rt.case_id = :case_id
                AND rt.updated_at_ms > rt.created_at_ms

              UNION ALL
              SELECT 'audit:' || al.audit_id, 'governance', 80,
                     al.audit_id, '',
                     al.created_at_ms, al.created_at_ms, 'system',
                     'Governance event: ' || al.action, '', '', al.actor
              FROM audit_log al
              WHERE al.case_id = :case_id
                AND al.action IN (
                  'escalate_case_review', 'confirm_case_attack', 'close_case',
                  'reopen_case', 'manual_validation_review_continued',
                  'analysis_replay_requested', 'analysis_replay_completed',
                  'case_response_pack_generated', 'case_response_pack_reused'
                )
            )
        """
        page_limit = max(1, min(int(limit), 100))
        page_offset = max(0, int(offset))
        params = {
            "case_id": case_id,
            "limit": page_limit,
            "offset": page_offset,
        }
        with self._lock:
            case_row = self.conn.execute(
                """
                SELECT case_id, product, status, severity, classification,
                       summary, updated_at_ms
                FROM cases WHERE case_id = ?
                """,
                (case_id,),
            ).fetchone()
            if not case_row:
                return None
            totals = self.conn.execute(
                timeline_cte
                + """
                  SELECT COUNT(*) AS total,
                         COALESCE(MAX(recorded_at_ms), 0) AS latest_recorded_at_ms
                  FROM timeline
                """,
                params,
            ).fetchone()
            rows = self.conn.execute(
                timeline_cte
                + """
                  , paged AS (
                    SELECT * FROM timeline
                    ORDER BY occurred_at_ms ASC, recorded_at_ms ASC,
                             kind_order ASC, entry_id ASC
                    LIMIT :limit OFFSET :offset
                  )
                  SELECT p.entry_id, p.kind, p.source_id, p.source_event_id,
                         p.occurred_at_ms, p.recorded_at_ms, p.time_basis,
                         p.title, p.state, p.product, p.actor,
                         COALESCE(ne.evidence_json, '[]') AS evidence_json,
                         COALESCE(ne.evidence_hash, '') AS evidence_hash,
                         CASE
                           WHEN p.kind IN ('security_event', 'analysis_replay')
                             THEN COALESCE(ne.entities_json, '{}')
                           WHEN p.kind = 'analysis'
                             THEN COALESCE(ar.result_json, '{}')
                           WHEN p.kind IN ('approval_request', 'approval_decision')
                             THEN COALESCE(aa.action_json, '{}')
                           WHEN p.kind IN ('response_task', 'response_task_state')
                             THEN COALESCE(rt.action_json, '{}')
                           WHEN p.kind = 'governance'
                             THEN COALESCE(al.detail_json, '{}')
                           ELSE '{}'
                         END AS detail_json
                  FROM paged p
                  LEFT JOIN normalized_events ne
                    ON ne.event_id = p.source_event_id
                  LEFT JOIN agent_runs ar
                    ON p.kind = 'analysis' AND ar.run_id = p.source_id
                  LEFT JOIN action_approvals aa
                    ON p.kind IN ('approval_request', 'approval_decision')
                   AND aa.approval_id = p.source_id
                  LEFT JOIN response_tasks rt
                    ON p.kind IN ('response_task', 'response_task_state')
                   AND rt.task_id = p.source_id
                  LEFT JOIN audit_log al
                    ON p.kind = 'governance' AND al.audit_id = p.source_id
                  ORDER BY p.occurred_at_ms ASC, p.recorded_at_ms ASC,
                           p.kind_order ASC, p.entry_id ASC
                """,
                params,
            ).fetchall()
            return {
                "case": dict(case_row),
                "items": [dict(row) for row in rows],
                "total": int(totals["total"] if totals else 0),
                "latest_recorded_at_ms": int(
                    totals["latest_recorded_at_ms"] if totals else 0
                ),
            }

    def insert_case_response_artifact(
        self,
        artifact: dict[str, Any],
        refs: list[dict[str, Any]],
        *,
        _commit: bool = True,
    ) -> tuple[dict[str, Any], bool]:
        """Persist one immutable Response Pack version and its citation manifest."""
        with self._lock:
            existing = self.conn.execute(
                """
                SELECT * FROM case_response_artifacts
                WHERE case_id = ? AND source_snapshot_hash = ? AND content_hash = ?
                """,
                (
                    artifact["case_id"],
                    artifact["source_snapshot_hash"],
                    artifact["content_hash"],
                ),
            ).fetchone()
            if existing:
                artifact_id = str(existing["artifact_id"])
                existing_refs = [
                    dict(row)
                    for row in self.conn.execute(
                        """
                        SELECT claim_scope, ref_type, ref_id, source_event_id, source_hash
                        FROM case_response_artifact_refs WHERE artifact_id = ?
                        ORDER BY claim_scope ASC, ref_type ASC, ref_id ASC, source_event_id ASC
                        """,
                        (artifact_id,),
                    ).fetchall()
                ]
                return self._case_response_artifact_row(existing, existing_refs), False

            version_row = self.conn.execute(
                """
                SELECT COALESCE(MAX(version), 0) + 1 AS next_version
                FROM case_response_artifacts WHERE case_id = ?
                """,
                (artifact["case_id"],),
            ).fetchone()
            version = int(version_row["next_version"])
            self.conn.execute(
                """
                INSERT INTO case_response_artifacts(
                  artifact_id, case_id, artifact_type, version, schema_version,
                  source_snapshot_hash, content_hash, content_json,
                  validation_status, validation_json, generator,
                  model_metadata_json, created_by, created_at_ms
                ) VALUES (?, ?, 'response_pack', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact["artifact_id"],
                    artifact["case_id"],
                    version,
                    artifact["schema_version"],
                    artifact["source_snapshot_hash"],
                    artifact["content_hash"],
                    json.dumps(artifact["content"], ensure_ascii=False, sort_keys=True),
                    artifact["validation_status"],
                    json.dumps(artifact["validation"], ensure_ascii=False, sort_keys=True),
                    artifact["generator"],
                    json.dumps(
                        artifact.get("model_metadata") or {},
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    artifact["created_by"],
                    int(artifact["created_at_ms"]),
                ),
            )
            for ref in refs:
                self.conn.execute(
                    """
                    INSERT OR IGNORE INTO case_response_artifact_refs(
                      artifact_id, claim_scope, ref_type, ref_id,
                      source_event_id, source_hash
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        artifact["artifact_id"],
                        str(ref.get("claim_scope") or "pack")[:128],
                        str(ref.get("ref_type") or "evidence")[:64],
                        str(ref.get("ref_id") or "")[:512],
                        str(ref.get("source_event_id") or "")[:256],
                        str(ref.get("source_hash") or "")[:128],
                    ),
                )
            if _commit:
                self.conn.commit()
            row = self.conn.execute(
                "SELECT * FROM case_response_artifacts WHERE artifact_id = ?",
                (artifact["artifact_id"],),
            ).fetchone()
            saved_refs = [
                dict(row)
                for row in self.conn.execute(
                    """
                    SELECT claim_scope, ref_type, ref_id, source_event_id, source_hash
                    FROM case_response_artifact_refs WHERE artifact_id = ?
                    ORDER BY claim_scope ASC, ref_type ASC, ref_id ASC, source_event_id ASC
                    """,
                    (artifact["artifact_id"],),
                ).fetchall()
            ]
            if not row:  # pragma: no cover - insert above must produce a row.
                raise RuntimeError("Case Response Pack was not persisted")
            return self._case_response_artifact_row(row, saved_refs), True

    def get_latest_case_response_artifact(
        self, case_id: str
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                """
                SELECT * FROM case_response_artifacts
                WHERE case_id = ? AND artifact_type = 'response_pack'
                ORDER BY version DESC LIMIT 1
                """,
                (case_id,),
            ).fetchone()
            if not row:
                return None
            refs = [
                dict(item)
                for item in self.conn.execute(
                    """
                    SELECT claim_scope, ref_type, ref_id, source_event_id, source_hash
                    FROM case_response_artifact_refs WHERE artifact_id = ?
                    ORDER BY claim_scope ASC, ref_type ASC, ref_id ASC, source_event_id ASC
                    """,
                    (row["artifact_id"],),
                ).fetchall()
            ]
            return self._case_response_artifact_row(row, refs)

    def get_case_response_artifact(
        self, artifact_id: str
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM case_response_artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
            if not row:
                return None
            refs = [
                dict(item)
                for item in self.conn.execute(
                    """
                    SELECT claim_scope, ref_type, ref_id, source_event_id, source_hash
                    FROM case_response_artifact_refs WHERE artifact_id = ?
                    ORDER BY claim_scope ASC, ref_type ASC, ref_id ASC, source_event_id ASC
                    """,
                    (artifact_id,),
                ).fetchall()
            ]
            return self._case_response_artifact_row(row, refs)

    def create_response_agent_session(
        self, session: dict[str, Any], *, _commit: bool = True
    ) -> tuple[dict[str, Any], bool]:
        """Create one bounded investigation session, or return the active one."""
        with self._lock:
            active = self.conn.execute(
                """
                SELECT * FROM response_agent_sessions
                WHERE case_id = ? AND status IN (
                  'queued','running','waiting_input','paused','synthesizing','validating'
                )
                ORDER BY created_at_ms DESC LIMIT 1
                """,
                (session["case_id"],),
            ).fetchone()
            if active:
                return self._response_agent_session_row(active), False
            if not self.conn.execute(
                "SELECT 1 FROM cases WHERE case_id = ?", (session["case_id"],)
            ).fetchone():
                raise KeyError("case not found")
            self.conn.execute(
                """
                INSERT INTO response_agent_sessions(
                  session_id, case_id, artifact_id, source_snapshot_hash, goal,
                  source_json, status, plan_json, budget_json, usage_json, model_metadata_json,
                  last_error, created_by, created_at_ms, updated_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, '', ?, ?, ?)
                """,
                (
                    session["session_id"],
                    session["case_id"],
                    session["artifact_id"],
                    session["source_snapshot_hash"],
                    session["goal"],
                    json.dumps(
                        session["source_snapshot"], ensure_ascii=False, sort_keys=True
                    ),
                    json.dumps(session.get("plan") or [], ensure_ascii=False, sort_keys=True),
                    json.dumps(session.get("budget") or {}, ensure_ascii=False, sort_keys=True),
                    json.dumps(session.get("usage") or {}, ensure_ascii=False, sort_keys=True),
                    json.dumps(
                        session.get("model_metadata") or {},
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    session["created_by"],
                    int(session["created_at_ms"]),
                    int(session["created_at_ms"]),
                ),
            )
            if _commit:
                self.conn.commit()
            row = self.conn.execute(
                "SELECT * FROM response_agent_sessions WHERE session_id = ?",
                (session["session_id"],),
            ).fetchone()
            if not row:  # pragma: no cover
                raise RuntimeError("Response Agent session was not persisted")
            return self._response_agent_session_row(row), True

    def recover_response_agent_sessions(self) -> int:
        """Requeue work interrupted after a process restart."""
        with self._lock:
            timestamp = now_ms()
            cur = self.conn.execute(
                """
                UPDATE response_agent_sessions
                SET status = 'queued', claimed_at_ms = NULL, updated_at_ms = ?,
                    last_error = 'worker_restarted'
                WHERE status IN ('running','synthesizing','validating')
                """,
                (timestamp,),
            )
            self.conn.commit()
            return int(cur.rowcount)

    def claim_response_agent_session(self) -> dict[str, Any] | None:
        """Atomically claim the oldest queued session for the single worker."""
        with self._lock:
            row = self.conn.execute(
                """
                SELECT session_id FROM response_agent_sessions
                WHERE status = 'queued'
                ORDER BY created_at_ms ASC, session_id ASC LIMIT 1
                """
            ).fetchone()
            if not row:
                return None
            timestamp = now_ms()
            cur = self.conn.execute(
                """
                UPDATE response_agent_sessions
                SET status = 'running', claimed_at_ms = ?, updated_at_ms = ?,
                    last_error = ''
                WHERE session_id = ? AND status = 'queued'
                """,
                (timestamp, timestamp, row["session_id"]),
            )
            if cur.rowcount != 1:
                self.conn.rollback()
                return None
            self.conn.commit()
            claimed = self.conn.execute(
                "SELECT * FROM response_agent_sessions WHERE session_id = ?",
                (row["session_id"],),
            ).fetchone()
            return self._response_agent_session_row(claimed) if claimed else None

    def update_response_agent_session(
        self,
        session_id: str,
        *,
        expected_statuses: tuple[str, ...] | None = None,
        status: str | None = None,
        plan: list[dict[str, Any]] | None = None,
        usage: dict[str, Any] | None = None,
        model_metadata: dict[str, Any] | None = None,
        report_id: str | None = None,
        last_error: str | None = None,
        completed: bool = False,
        refresh_claimed_at: bool = False,
        _commit: bool = True,
    ) -> dict[str, Any] | None:
        with self._lock:
            timestamp = now_ms()
            assignments = ["updated_at_ms = ?"]
            values: list[Any] = [timestamp]
            if status is not None:
                assignments.append("status = ?")
                values.append(status)
            if plan is not None:
                assignments.append("plan_json = ?")
                values.append(json.dumps(plan, ensure_ascii=False, sort_keys=True))
            if usage is not None:
                assignments.append("usage_json = ?")
                values.append(json.dumps(usage, ensure_ascii=False, sort_keys=True))
            if model_metadata is not None:
                assignments.append("model_metadata_json = ?")
                values.append(
                    json.dumps(model_metadata, ensure_ascii=False, sort_keys=True)
                )
            if report_id is not None:
                assignments.append("report_id = ?")
                values.append(report_id)
            if last_error is not None:
                assignments.append("last_error = ?")
                values.append(str(last_error)[:2000])
            if refresh_claimed_at:
                assignments.append("claimed_at_ms = ?")
                values.append(timestamp)
            if completed:
                assignments.append("completed_at_ms = ?")
                values.append(timestamp)
            where = "WHERE session_id = ?"
            values.append(session_id)
            if expected_statuses:
                placeholders = ",".join("?" for _ in expected_statuses)
                where += f" AND status IN ({placeholders})"
                values.extend(expected_statuses)
            cur = self.conn.execute(
                f"UPDATE response_agent_sessions SET {', '.join(assignments)} "
                f"{where}",
                values,
            )
            if cur.rowcount != 1:
                return None
            if _commit:
                self.conn.commit()
            row = self.conn.execute(
                "SELECT * FROM response_agent_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            return self._response_agent_session_row(row) if row else None

    def transition_response_agent_session(
        self,
        session_id: str,
        from_statuses: tuple[str, ...],
        to_status: str,
        *,
        last_error: str = "",
        _commit: bool = True,
    ) -> dict[str, Any] | None:
        with self._lock:
            placeholders = ",".join("?" for _ in from_statuses)
            timestamp = now_ms()
            existing = self.conn.execute(
                """
                SELECT status, claimed_at_ms, usage_json
                FROM response_agent_sessions WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()
            if not existing or str(existing["status"]) not in from_statuses:
                return None
            usage = json.loads(existing["usage_json"] or "{}")
            claimed_at_ms = int(existing["claimed_at_ms"] or 0)
            if (
                claimed_at_ms > 0
                and str(existing["status"])
                in {"running", "synthesizing", "validating"}
            ):
                usage["active_seconds"] = round(
                    max(0.0, float(usage.get("active_seconds") or 0))
                    + max(0, timestamp - claimed_at_ms) / 1_000,
                    3,
                )
            completed_at = (
                timestamp
                if to_status in {
                    "completed",
                    "review",
                    "blocked",
                    "failed",
                    "cancelled",
                    "budget_exhausted",
                }
                else None
            )
            cur = self.conn.execute(
                f"""
                UPDATE response_agent_sessions
                SET status = ?, updated_at_ms = ?, claimed_at_ms = NULL,
                    completed_at_ms = COALESCE(?, completed_at_ms), last_error = ?,
                    usage_json = ?
                WHERE session_id = ? AND status IN ({placeholders})
                """,
                (
                    to_status,
                    timestamp,
                    completed_at,
                    str(last_error)[:2000],
                    json.dumps(usage, ensure_ascii=False, sort_keys=True),
                    session_id,
                    *from_statuses,
                ),
            )
            if _commit:
                self.conn.commit()
            if cur.rowcount != 1:
                return None
            row = self.conn.execute(
                "SELECT * FROM response_agent_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            return self._response_agent_session_row(row) if row else None

    def append_response_agent_step(
        self,
        step: dict[str, Any],
        *,
        expected_statuses: tuple[str, ...] | None = None,
        usage: dict[str, Any] | None = None,
        _commit: bool = True,
    ) -> dict[str, Any] | None:
        with self._lock:
            if expected_statuses:
                placeholders = ",".join("?" for _ in expected_statuses)
                row = self.conn.execute(
                    f"""
                    SELECT status FROM response_agent_sessions
                    WHERE session_id = ? AND status IN ({placeholders})
                    """,
                    (step["session_id"], *expected_statuses),
                ).fetchone()
                if not row:
                    return None
                if usage is not None:
                    self.conn.execute(
                        """
                        UPDATE response_agent_sessions
                        SET usage_json = ?, updated_at_ms = ?
                        WHERE session_id = ?
                        """,
                        (
                            json.dumps(usage, ensure_ascii=False, sort_keys=True),
                            now_ms(),
                            step["session_id"],
                        ),
                    )
            sequence_row = self.conn.execute(
                """
                SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence
                FROM response_agent_steps WHERE session_id = ?
                """,
                (step["session_id"],),
            ).fetchone()
            sequence = int(sequence_row["next_sequence"])
            self.conn.execute(
                """
                INSERT INTO response_agent_steps(
                  step_id, session_id, sequence, phase, status, title, rationale,
                  detail_json, evidence_refs_json, created_at_ms, completed_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    step["step_id"],
                    step["session_id"],
                    sequence,
                    step["phase"],
                    step.get("status") or "completed",
                    str(step.get("title") or "")[:500],
                    str(step.get("rationale") or "")[:4000],
                    json.dumps(step.get("detail") or {}, ensure_ascii=False, sort_keys=True),
                    json.dumps(
                        step.get("evidence_refs") or [],
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    int(step.get("created_at_ms") or now_ms()),
                    int(step.get("completed_at_ms") or now_ms()),
                ),
            )
            if _commit:
                self.conn.commit()
            row = self.conn.execute(
                "SELECT * FROM response_agent_steps WHERE step_id = ?",
                (step["step_id"],),
            ).fetchone()
            if not row:  # pragma: no cover
                raise RuntimeError("Response Agent step was not persisted")
            return self._response_agent_step_row(row)

    def start_response_agent_tool_call(
        self, call: dict[str, Any], *, _commit: bool = True
    ) -> tuple[dict[str, Any], bool]:
        with self._lock:
            existing = self.conn.execute(
                "SELECT * FROM response_agent_tool_calls WHERE idempotency_key = ?",
                (call["idempotency_key"],),
            ).fetchone()
            if existing:
                return self._response_agent_tool_call_row(existing), False
            self.conn.execute(
                """
                INSERT INTO response_agent_tool_calls(
                  call_id, session_id, step_id, tool_name, tool_version,
                  arguments_json, status, idempotency_key, created_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?)
                """,
                (
                    call["call_id"],
                    call["session_id"],
                    call["step_id"],
                    call["tool_name"],
                    call.get("tool_version") or "1",
                    json.dumps(
                        call.get("arguments") or {}, ensure_ascii=False, sort_keys=True
                    ),
                    call["idempotency_key"],
                    int(call.get("created_at_ms") or now_ms()),
                ),
            )
            if _commit:
                self.conn.commit()
            row = self.conn.execute(
                "SELECT * FROM response_agent_tool_calls WHERE call_id = ?",
                (call["call_id"],),
            ).fetchone()
            if not row:  # pragma: no cover
                raise RuntimeError("Response Agent tool call was not persisted")
            return self._response_agent_tool_call_row(row), True

    def finish_response_agent_tool_call(
        self,
        call_id: str,
        *,
        result: dict[str, Any],
        result_hash: str,
        evidence_refs: list[dict[str, Any]],
        error: str = "",
        _commit: bool = True,
    ) -> dict[str, Any] | None:
        with self._lock:
            status = "failed" if error else "completed"
            self.conn.execute(
                """
                UPDATE response_agent_tool_calls
                SET status = ?, result_json = ?, result_hash = ?,
                    evidence_refs_json = ?, error = ?, completed_at_ms = ?
                WHERE call_id = ?
                """,
                (
                    status,
                    json.dumps(result, ensure_ascii=False, sort_keys=True),
                    result_hash,
                    json.dumps(evidence_refs, ensure_ascii=False, sort_keys=True),
                    str(error)[:2000],
                    now_ms(),
                    call_id,
                ),
            )
            if _commit:
                self.conn.commit()
            row = self.conn.execute(
                "SELECT * FROM response_agent_tool_calls WHERE call_id = ?",
                (call_id,),
            ).fetchone()
            return self._response_agent_tool_call_row(row) if row else None

    def insert_response_agent_report(
        self,
        report: dict[str, Any],
        refs: list[dict[str, Any]],
        *,
        _commit: bool = True,
    ) -> dict[str, Any]:
        with self._lock:
            existing = self.conn.execute(
                "SELECT * FROM response_agent_reports WHERE session_id = ?",
                (report["session_id"],),
            ).fetchone()
            if existing:
                existing_refs = [
                    dict(row)
                    for row in self.conn.execute(
                        """
                        SELECT claim_id, ref_type, ref_id, source_event_id, source_hash
                        FROM response_agent_report_refs WHERE report_id = ?
                        ORDER BY claim_id, ref_type, ref_id, source_event_id
                        """,
                        (existing["report_id"],),
                    ).fetchall()
                ]
                return self._response_agent_report_row(existing, existing_refs)
            version_row = self.conn.execute(
                """
                SELECT COALESCE(MAX(version), 0) + 1 AS next_version
                FROM response_agent_reports WHERE case_id = ?
                """,
                (report["case_id"],),
            ).fetchone()
            version = int(version_row["next_version"])
            self.conn.execute(
                """
                INSERT INTO response_agent_reports(
                  report_id, session_id, case_id, version, schema_version,
                  source_snapshot_hash, content_hash, content_json,
                  validation_status, validation_json, model_metadata_json,
                  created_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report["report_id"],
                    report["session_id"],
                    report["case_id"],
                    version,
                    report["schema_version"],
                    report["source_snapshot_hash"],
                    report["content_hash"],
                    json.dumps(report["content"], ensure_ascii=False, sort_keys=True),
                    report["validation_status"],
                    json.dumps(
                        report["validation"], ensure_ascii=False, sort_keys=True
                    ),
                    json.dumps(
                        report.get("model_metadata") or {},
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    int(report["created_at_ms"]),
                ),
            )
            for ref in refs:
                self.conn.execute(
                    """
                    INSERT OR IGNORE INTO response_agent_report_refs(
                      report_id, claim_id, ref_type, ref_id,
                      source_event_id, source_hash
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        report["report_id"],
                        str(ref.get("claim_id") or "report")[:128],
                        str(ref.get("ref_type") or "evidence")[:64],
                        str(ref.get("ref_id") or "")[:512],
                        str(ref.get("source_event_id") or "")[:256],
                        str(ref.get("source_hash") or "")[:128],
                    ),
                )
            self._retain_latest_response_agent_report(
                case_id=str(report["case_id"]),
                session_id=str(report["session_id"]),
                report_id=str(report["report_id"]),
            )
            if _commit:
                self.conn.commit()
            row = self.conn.execute(
                "SELECT * FROM response_agent_reports WHERE report_id = ?",
                (report["report_id"],),
            ).fetchone()
            saved_refs = [
                dict(item)
                for item in self.conn.execute(
                    """
                    SELECT claim_id, ref_type, ref_id, source_event_id, source_hash
                    FROM response_agent_report_refs WHERE report_id = ?
                    ORDER BY claim_id, ref_type, ref_id, source_event_id
                    """,
                    (report["report_id"],),
                ).fetchall()
            ]
            if not row:  # pragma: no cover
                raise RuntimeError("Response Agent report was not persisted")
            return self._response_agent_report_row(row, saved_refs)

    def _retain_latest_response_agent_report(
        self,
        *,
        case_id: str,
        session_id: str,
        report_id: str,
    ) -> int:
        """Keep one materialized Response Agent report per Case.

        Session steps, tool calls and audit events remain available for governance,
        while report content and claim references from superseded runs are removed.
        Callers invoke this inside the same transaction that commits the new report,
        so a failed rerun cannot delete the previous usable report.
        """
        self.conn.execute(
            """
            UPDATE response_agent_sessions
            SET report_id = NULL
            WHERE case_id = ? AND session_id <> ? AND report_id IS NOT NULL
            """,
            (case_id, session_id),
        )
        deleted = self.conn.execute(
            """
            DELETE FROM response_agent_reports
            WHERE case_id = ? AND report_id <> ?
            """,
            (case_id, report_id),
        )
        return int(deleted.rowcount)

    def get_response_agent_session(
        self, session_id: str, *, after_sequence: int = 0
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM response_agent_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if not row:
                return None
            payload = self._response_agent_session_row(row)
            payload["steps"] = [
                self._response_agent_step_row(item)
                for item in self.conn.execute(
                    """
                    SELECT * FROM response_agent_steps
                    WHERE session_id = ? AND sequence > ?
                    ORDER BY sequence ASC
                    """,
                    (session_id, max(0, int(after_sequence))),
                ).fetchall()
            ]
            payload["tool_calls"] = [
                self._response_agent_tool_call_row(item)
                for item in self.conn.execute(
                    """
                    SELECT * FROM response_agent_tool_calls
                    WHERE session_id = ?
                    ORDER BY created_at_ms ASC, call_id ASC
                    """,
                    (session_id,),
                ).fetchall()
            ]
            payload["report"] = None
            if payload.get("report_id"):
                report_row = self.conn.execute(
                    "SELECT * FROM response_agent_reports WHERE report_id = ?",
                    (payload["report_id"],),
                ).fetchone()
                if report_row:
                    refs = [
                        dict(item)
                        for item in self.conn.execute(
                            """
                            SELECT claim_id, ref_type, ref_id, source_event_id, source_hash
                            FROM response_agent_report_refs WHERE report_id = ?
                            ORDER BY claim_id, ref_type, ref_id, source_event_id
                            """,
                            (payload["report_id"],),
                        ).fetchall()
                    ]
                    payload["report"] = self._response_agent_report_row(
                        report_row, refs
                    )
            return payload

    def get_latest_response_agent_session(
        self, case_id: str
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                """
                SELECT session_id FROM response_agent_sessions
                WHERE case_id = ?
                ORDER BY created_at_ms DESC, session_id DESC LIMIT 1
                """,
                (case_id,),
            ).fetchone()
            if not row:
                return None
            return self.get_response_agent_session(str(row["session_id"]))

    def get_response_agent_source(
        self, session_id: str
    ) -> dict[str, Any] | None:
        """Return the immutable normalized source snapshot for worker use only."""
        with self._lock:
            row = self.conn.execute(
                "SELECT source_json FROM response_agent_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            return json.loads(row["source_json"]) if row else None

    def cancel_case_response_agents(
        self, case_id: str, *, reason: str, _commit: bool = True
    ) -> int:
        with self._lock:
            timestamp = now_ms()
            cur = self.conn.execute(
                """
                UPDATE response_agent_sessions
                SET status = 'cancelled', updated_at_ms = ?, completed_at_ms = ?,
                    claimed_at_ms = NULL, last_error = ?
                WHERE case_id = ? AND status IN (
                  'queued','running','waiting_input','paused','synthesizing','validating'
                )
                """,
                (timestamp, timestamp, str(reason)[:2000], case_id),
            )
            if _commit:
                self.conn.commit()
            return int(cur.rowcount)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            open_filter = "status = 'open'"
            unresolved_filter = "status NOT IN ('closed', 'false_positive')"
            case_count = self.conn.execute(f"SELECT COUNT(*) c FROM cases WHERE {open_filter}").fetchone()["c"]
            unresolved_case_count = self.conn.execute(
                f"SELECT COUNT(*) c FROM cases WHERE {unresolved_filter}"
            ).fetchone()["c"]
            total_case_count = self.conn.execute("SELECT COUNT(*) c FROM cases").fetchone()["c"]
            alert_count = self.conn.execute("SELECT COUNT(*) c FROM raw_alerts").fetchone()["c"]
            high_count = self.conn.execute(
                f"SELECT COUNT(*) c FROM cases WHERE {open_filter} AND severity IN ('high', 'critical')"
            ).fetchone()["c"]
            validation = {
                row["status"]: row["count"]
                for row in self.conn.execute(
                    "SELECT status, COUNT(*) AS count FROM validation_runs GROUP BY status"
                ).fetchall()
            }
            approvals = {
                row["status"]: row["count"]
                for row in self.conn.execute(
                    "SELECT status, COUNT(*) AS count FROM action_approvals GROUP BY status"
                ).fetchall()
            }
            return {
                "cases": case_count,
                "open_cases": case_count,
                "unresolved_cases": unresolved_case_count,
                "total_cases": total_case_count,
                "alerts": alert_count,
                "high_or_critical_cases": high_count,
                "validation": validation,
                "approvals": approvals,
            }


class _Transaction:
    """Serialize a group of repository writes into one atomic transaction.

    Acquires the repository RLock (reentrant) and, for the outermost block on a
    given thread, owns the final ``commit()`` / ``rollback()``. Writes performed
    by repository methods with ``_commit=False`` defer to this owner. The lock is
    held across the whole block so no other thread can interleave a write on the
    shared connection. We rely on sqlite3's implicit transaction (begun before
    the first DML) rather than an explicit ``BEGIN`` to avoid "cannot start a
    transaction within a transaction" errors.
    """

    def __init__(self, repo: Repository):
        self._repo = repo
        self._owns = False

    def __enter__(self) -> Repository:
        self._repo._lock.acquire()
        if self._repo._tx_depth() == 0:
            self._owns = True
        self._repo._tx_state.depth = self._repo._tx_depth() + 1
        return self._repo

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            depth = self._repo._tx_depth() - 1
            self._repo._tx_state.depth = max(depth, 0)
            if self._owns:
                if exc_type is None:
                    self._repo.conn.commit()
                else:
                    self._repo.conn.rollback()
        finally:
            self._repo._lock.release()
