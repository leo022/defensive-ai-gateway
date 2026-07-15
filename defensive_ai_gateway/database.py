from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import AgentResult, NormalizedEvent, RawAlert, now_ms


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
  created_at_ms INTEGER NOT NULL,
  UNIQUE (event_id, memory_id)
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
CREATE TABLE IF NOT EXISTS action_approvals (
  approval_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
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
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  available_at_ms INTEGER NOT NULL,
  claimed_at_ms INTEGER,
  completed_at_ms INTEGER,
  last_error TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  CHECK (status IN ('pending','processing','retry','completed','dead_letter'))
);
"""

# Indexes must be created after migrations. ``CREATE TABLE IF NOT EXISTS`` does
# not add new columns to an existing table, so creating an index here would make
# a legitimate legacy database fail before its ALTER TABLE migration can run.
INDEX_SCHEMA = """
CREATE INDEX IF NOT EXISTS idx_normalized_alert ON normalized_events(alert_id);
CREATE INDEX IF NOT EXISTS idx_agent_runs_case ON agent_runs(case_id);
CREATE INDEX IF NOT EXISTS idx_agent_runs_event ON agent_runs(event_id);
CREATE INDEX IF NOT EXISTS idx_case_links_alert ON case_alert_links(alert_id);
CREATE INDEX IF NOT EXISTS idx_case_links_case ON case_alert_links(case_id);
CREATE INDEX IF NOT EXISTS idx_case_links_case_created ON case_alert_links(case_id, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_cases_correlation ON cases(correlation_key, last_alert_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_memory_lookup ON memory_entries(layer, namespace, status);
CREATE INDEX IF NOT EXISTS idx_memory_lookup_created ON memory_entries(layer, namespace, status, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_memory_expiry ON memory_entries(status, expires_at_ms);
CREATE INDEX IF NOT EXISTS idx_memory_events_mem ON memory_events(memory_id);
CREATE INDEX IF NOT EXISTS idx_memory_matches_event ON memory_matches(event_id, overall_score DESC);
CREATE INDEX IF NOT EXISTS idx_memory_matches_memory ON memory_matches(memory_id, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_memory_matches_case ON memory_matches(case_id, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_log(case_id, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_audit_memory ON audit_log(memory_id, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_validation_case ON validation_runs(case_id, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_approvals_case ON action_approvals(case_id, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON action_approvals(status, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_approval_votes_approval ON approval_votes(approval_id, created_at_ms ASC);
CREATE INDEX IF NOT EXISTS idx_alert_dispositions_case ON alert_dispositions(case_id, updated_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_inbox_claim ON durable_alert_inbox(status, available_at_ms, created_at_ms);
"""

SCHEMA_VERSION = 9


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
        self.conn.executescript(INDEX_SCHEMA)

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
                 entities_json, evidence_json, sensitivity_tags_json, evidence_hash, created_at_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                  severity = excluded.severity,
                  classification = excluded.classification,
                  confidence = excluded.confidence,
                  summary = excluded.summary,
                  updated_at_ms = excluded.updated_at_ms,
                  last_alert_at_ms = MAX(cases.last_alert_at_ms, excluded.last_alert_at_ms)
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

    def insert_approval(self, approval: dict[str, Any], _commit: bool = True) -> bool:
        with self._lock:
            case = self.conn.execute(
                "SELECT status FROM cases WHERE case_id = ?", (approval["case_id"],)
            ).fetchone()
            validation = self.conn.execute(
                """
                SELECT status FROM validation_runs
                WHERE case_id = ? AND event_id = ? ORDER BY created_at_ms DESC LIMIT 1
                """,
                (approval["case_id"], approval["event_id"]),
            ).fetchone()
            if not case or case["status"] in {"closed", "false_positive"}:
                return False
            if not validation or validation["status"] != "passed":
                return False
            action_json = json.dumps(
                {
                    "action": approval["action"],
                    "rationale": approval["rationale"],
                    "rollback": approval["rollback"],
                    "mode": approval["mode"],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
            cur = self.conn.execute(
                """
                INSERT OR IGNORE INTO action_approvals
                (approval_id, case_id, event_id, action_json, status, requested_by,
                 decided_by, decision_reason, execution_status, required_approvals,
                 created_at_ms, updated_at_ms)
                VALUES (?, ?, ?, ?, 'pending', ?, '', '', 'not_executed', ?, ?, ?)
                """,
                (
                    approval["approval_id"],
                    approval["case_id"],
                    approval["event_id"],
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
        self, case_id: str | None = None, status: str | None = None, limit: int = 100
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
            sql = "SELECT * FROM action_approvals"
            if clauses:
                sql += " WHERE " + " AND ".join(clauses)
            sql += " ORDER BY created_at_ms DESC LIMIT ?"
            params.append(max(1, min(int(limit), 500)))
            return [self._approval_row(row) for row in self.conn.execute(sql, params).fetchall()]

    def _approval_row(self, row: sqlite3.Row) -> dict[str, Any]:
        payload = dict(row)
        payload["action"] = json.loads(payload.pop("action_json"))
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
        return payload

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

    def enqueue_alert(
        self,
        alert: RawAlert | dict[str, Any],
        max_attempts: int = 5,
        _commit: bool = True,
    ) -> bool:
        payload = (
            {
                "source": alert.source,
                "product": alert.product,
                "event_type": alert.event_type,
                "severity": alert.severity,
                "timestamp": alert.timestamp,
                "payload": alert.payload,
                "alert_id": alert.alert_id,
                "trusted_sample": bool(getattr(alert, "trusted_sample", False)),
            }
            if isinstance(alert, RawAlert)
            else dict(alert)
        )
        alert_id = str(payload.get("alert_id") or "").strip()
        if not alert_id:
            raise ValueError("alert_id is required for durable enqueue")
        with self._lock:
            created = now_ms()
            cur = self.conn.execute(
                """
                INSERT OR IGNORE INTO durable_alert_inbox
                (alert_id, raw_alert_json, source, product, status, attempts, max_attempts,
                 available_at_ms, claimed_at_ms, completed_at_ms, last_error, created_at_ms, updated_at_ms)
                VALUES (?, ?, ?, ?, 'pending', 0, ?, ?, NULL, NULL, '', ?, ?)
                """,
                (
                    alert_id,
                    json.dumps(payload, ensure_ascii=False, sort_keys=True),
                    str(payload.get("source") or "unknown"),
                    str(payload.get("product") or "unknown").lower(),
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
    ) -> str:
        """Atomically enforce durable-inbox capacity and idempotency.

        Returns ``inserted``, ``duplicate`` or ``full``. Keeping the count,
        duplicate check and insert under the repository transaction prevents a
        burst of concurrent HTTP workers from all passing a stale capacity
        check before inserting.
        """
        alert_id = str(
            alert.alert_id if isinstance(alert, RawAlert) else alert.get("alert_id", "")
        ).strip()
        if not alert_id:
            raise ValueError("alert_id is required for durable enqueue")
        with self.transaction():
            existing = self.conn.execute(
                "SELECT 1 FROM durable_alert_inbox WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
            if existing:
                return "duplicate"
            backlog = self.conn.execute(
                """
                SELECT COUNT(*) AS count FROM durable_alert_inbox
                WHERE status IN ('pending', 'retry', 'processing')
                """
            ).fetchone()["count"]
            if int(backlog) >= max(1, int(capacity)):
                return "full"
            inserted = self.enqueue_alert(
                alert,
                max_attempts=max_attempts,
                _commit=False,
            )
            return "inserted" if inserted else "duplicate"

    def claim_inbox_alert(self, alert_id: str | None = None) -> dict[str, Any] | None:
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
                row = self.conn.execute(
                    """
                    SELECT * FROM durable_alert_inbox
                    WHERE status IN ('pending','retry') AND available_at_ms <= ?
                    ORDER BY available_at_ms ASC, created_at_ms ASC LIMIT 1
                    """,
                    (now,),
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

    def list_inbox_alerts(self, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            if status:
                rows = self.conn.execute(
                    "SELECT * FROM durable_alert_inbox WHERE status = ? ORDER BY created_at_ms DESC LIMIT ?",
                    (status, max(1, min(int(limit), 500))),
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM durable_alert_inbox ORDER BY created_at_ms DESC LIMIT ?",
                    (max(1, min(int(limit), 500)),),
                ).fetchall()
            return [self._inbox_row(row) for row in rows]

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
                for status in ("pending", "retry", "processing", "completed", "dead_letter")
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
            "validations": 0,
            "approvals": 0,
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
                    "DELETE FROM validation_runs WHERE case_id = ?",
                    (case_id,),
                )
                counts["validations"] += cur.rowcount
                cur = self.conn.execute(
                    "DELETE FROM agent_runs WHERE case_id = ?",
                    (case_id,),
                )
                counts["agent_runs"] += cur.rowcount
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
                WHERE ne.event_id != ? AND ne.product != ?
                ORDER BY ne.created_at_ms DESC LIMIT 2000
                """,
                (event.event_id, event.product),
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
                self._archive_case_memory_locked(case_id, updated_at)
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
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN d.disposition = 'false_positive' THEN 1 ELSE 0 END) AS false_positives
                FROM case_alert_links l
                LEFT JOIN alert_dispositions d ON d.alert_id = l.alert_id
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

    def get_alert_disposition(self, alert_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM alert_dispositions WHERE alert_id = ?", (alert_id,)
            ).fetchone()
            return dict(row) if row else None

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

    def query_memory(
        self,
        layer: str | None = None,
        namespace: str | None = None,
        status: str | None = None,
        retrieval_key: str | None = None,
        query: str | None = None,
        limit: int = 50,
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
                f"SELECT {self._MEMORY_COLUMNS} FROM memory_entries {where} ORDER BY created_at_ms DESC LIMIT ?",
                (*params, limit),
            ).fetchall()
            return [dict(row) for row in rows]

    def query_matchable_product_memory(
        self,
        product: str,
        now_ms_value: int,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return the broad governed candidate pool before matcher hard filters."""
        with self._lock:
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
                ORDER BY updated_at_ms DESC, memory_id ASC
                LIMIT ?
                """,
                (f"product/{product.lower()}", now_ms_value, max(1, min(int(limit), 500))),
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
        _commit: bool = True,
    ) -> None:
        with self._lock:
            created = now_ms()
            for candidate in candidates:
                memory_id = str(candidate["memory_id"])
                digest = hashlib.sha256(f"{event_id}\0{memory_id}".encode("utf-8")).hexdigest()[:24]
                self.conn.execute(
                    """
                    INSERT INTO memory_matches
                    (match_id, event_id, alert_id, case_id, analysis_run_id, memory_id,
                     matcher_version, rank, structured_score, semantic_score, retrieval_score,
                     overall_score, decision, final_effect, matched_features_json,
                     score_breakdown_json, created_at_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(event_id, memory_id) DO UPDATE SET
                      analysis_run_id = excluded.analysis_run_id,
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
                      created_at_ms = excluded.created_at_ms
                    """,
                    (
                        f"mm_{digest}", event_id, alert_id, case_id, analysis_run_id, memory_id,
                        matcher_version, int(candidate.get("rank") or 0),
                        float(candidate.get("structured_score") or 0),
                        float(candidate.get("semantic_score") or 0),
                        float(candidate.get("retrieval_score") or 0),
                        float(candidate.get("overall_score") or 0),
                        str(candidate.get("decision") or "ignored"), final_effect,
                        json.dumps(candidate.get("matched_features") or [], ensure_ascii=False, sort_keys=True),
                        json.dumps(candidate.get("score_breakdown") or {}, ensure_ascii=False, sort_keys=True),
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
                       score_breakdown_json, created_at_ms
                FROM memory_matches {where}
                ORDER BY created_at_ms DESC, overall_score DESC LIMIT ?
                """,
                (*params, max(1, min(int(limit), 500))),
            ).fetchall()
            output: list[dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                item["matched_features"] = json.loads(item.pop("matched_features_json"))
                item["score_breakdown"] = json.loads(item.pop("score_breakdown_json"))
                output.append(item)
            return output

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
        self, memory_id: str | None = None, event_type: str | None = None, limit: int = 50
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
                FROM memory_events {where} ORDER BY created_at_ms DESC LIMIT ?
                """,
                (*params, limit),
            ).fetchall()
            out = []
            for row in rows:
                item = dict(row)
                item["detail"] = json.loads(item.pop("detail_json"))
                out.append(item)
            return out

    def load_evidence_refs(self, case_id: str) -> list[dict[str, Any]]:
        """Immutable evidence store: read-only, already-desensitized refs from normalized events."""
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT ne.event_id, ne.product, ne.evidence_json, ne.sensitivity_tags_json
                FROM case_alert_links l
                JOIN normalized_events ne ON ne.event_id = l.event_id
                WHERE l.case_id = ?
                ORDER BY l.created_at_ms ASC
                """,
                (case_id,),
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
        product: str | None = None,
        severity: str | None = None,
        status: str | None = None,
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
                    SELECT COUNT(*) FROM case_alert_links l WHERE l.case_id = c.case_id
                  ), 0) AS alert_count,
                  (
                    SELECT l.alert_id FROM case_alert_links l
                    WHERE l.case_id = c.case_id
                    ORDER BY l.created_at_ms DESC LIMIT 1
                  ) AS latest_alert_id
                FROM cases c {where}
                ORDER BY c.created_at_ms DESC, c.case_id ASC LIMIT ?
                """,
                (*params, limit),
            ).fetchall()
            return [dict(row) for row in rows]

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
                "SELECT result_json FROM validation_runs WHERE case_id = ? ORDER BY created_at_ms DESC",
                (case_id,),
            ).fetchall()
            result["validation_runs"] = [json.loads(item["result_json"]) for item in validations]
            result["approvals"] = self.list_approvals(case_id=case_id, limit=100)
            result["memory_matches"] = self.list_memory_matches(case_id=case_id, limit=200)
            result["linked_alerts"] = self._linked_alerts_locked(case_id)
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
              ad.disposition AS alert_disposition,
              ad.actor AS disposition_actor,
              ad.reason AS disposition_reason,
              ad.updated_at_ms AS disposition_updated_at_ms
            FROM case_alert_links l
            LEFT JOIN raw_alerts ra ON ra.alert_id = l.alert_id
            LEFT JOIN normalized_events ne ON ne.event_id = l.event_id
            LEFT JOIN alert_dispositions ad ON ad.alert_id = l.alert_id
            WHERE l.case_id = ?
            ORDER BY l.created_at_ms DESC
            """,
            (case_id,),
        ).fetchall()
        linked = []
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
            linked.append(
                {
                    "case_id": item["case_id"],
                    "alert_id": item["alert_id"],
                    "event_id": item["event_id"],
                    "linked_at_ms": item["linked_at_ms"],
                    "disposition": (
                        {
                            "status": item["alert_disposition"],
                            "actor": item["disposition_actor"],
                            "reason": item["disposition_reason"],
                            "updated_at_ms": item["disposition_updated_at_ms"],
                        }
                        if item.get("alert_disposition")
                        else None
                    ),
                    "raw_alert": raw_alert,
                    "normalized_event": normalized_event,
                }
            )
        return linked

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
