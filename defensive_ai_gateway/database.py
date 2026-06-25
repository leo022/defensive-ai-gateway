from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .models import AgentResult, NormalizedEvent, RawAlert, now_ms


SCHEMA = """
PRAGMA journal_mode=WAL;
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
  created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cases (
  case_id TEXT PRIMARY KEY,
  product TEXT NOT NULL,
  status TEXT NOT NULL,
  severity TEXT NOT NULL,
  classification TEXT NOT NULL,
  confidence REAL NOT NULL,
  summary TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_runs (
  run_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  agent TEXT NOT NULL,
  product TEXT NOT NULL,
  prompt_version TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS case_alert_links (
  case_id TEXT NOT NULL,
  alert_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (case_id, alert_id, event_id)
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
  updated_at_ms INTEGER NOT NULL DEFAULT 0
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
CREATE TABLE IF NOT EXISTS audit_log (
  audit_id TEXT PRIMARY KEY,
  trace_id TEXT NOT NULL,
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
"""


class Repository:
    def __init__(self, db_path: str):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        columns = {
            row["name"]
            for row in self.conn.execute("PRAGMA table_info(normalized_events)").fetchall()
        }
        if "source" not in columns:
            self.conn.execute("ALTER TABLE normalized_events ADD COLUMN source TEXT NOT NULL DEFAULT 'unknown'")
            self.conn.commit()
        # Multi-layer memory: backfill new columns on pre-existing memory_entries tables.
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
        added = False
        for col, decl in additions.items():
            if col not in mem_columns:
                self.conn.execute(f"ALTER TABLE memory_entries ADD COLUMN {col} {decl}")
                added = True
        if added:
            self.conn.commit()

    def insert_raw_alert(self, alert: RawAlert) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO raw_alerts
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
        self.conn.commit()

    def insert_normalized_event(self, event: NormalizedEvent) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO normalized_events
            (event_id, alert_id, source, product, event_type, severity, timestamp, entities_json, evidence_json, sensitivity_tags_json, created_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                json.dumps(event.evidence, ensure_ascii=False, sort_keys=True),
                json.dumps(event.sensitivity_tags, ensure_ascii=False),
                now_ms(),
            ),
        )
        self.conn.commit()

    def upsert_case(self, result: AgentResult, product: str) -> None:
        existing = self.conn.execute("SELECT created_at_ms FROM cases WHERE case_id = ?", (result.case_id,)).fetchone()
        created = existing["created_at_ms"] if existing else result.created_at_ms
        self.conn.execute(
            """
            INSERT OR REPLACE INTO cases
            (case_id, product, status, severity, classification, confidence, summary, created_at_ms, updated_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.case_id,
                product,
                "open",
                result.severity,
                result.classification,
                result.confidence,
                result.summary,
                created,
                now_ms(),
            ),
        )
        self.conn.commit()

    def insert_agent_run(self, run_id: str, result: AgentResult, product: str, prompt_version: str) -> None:
        self.conn.execute(
            """
            INSERT INTO agent_runs
            (run_id, case_id, agent, product, prompt_version, result_json, created_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                result.case_id,
                result.agent,
                product,
                prompt_version,
                json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True),
                now_ms(),
            ),
        )
        self.conn.commit()

    def link_case_alert(self, case_id: str, alert_id: str, event_id: str) -> None:
        self.conn.execute(
            """
            INSERT OR IGNORE INTO case_alert_links
            (case_id, alert_id, event_id, created_at_ms)
            VALUES (?, ?, ?, ?)
            """,
            (case_id, alert_id, event_id, now_ms()),
        )
        self.conn.commit()

    # ---- mapping profiles -------------------------------------------------

    def save_mapping_profile(self, profile: dict[str, Any]) -> None:
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
        self.conn.commit()

    def delete_mapping_profile(self, profile_id: str) -> None:
        self.conn.execute("DELETE FROM mapping_profiles WHERE profile_id = ?", (profile_id,))
        self.conn.commit()

    def list_mapping_profiles(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT profile_id, name, version, description, enabled, profile_json, created_at_ms, updated_at_ms
            FROM mapping_profiles ORDER BY updated_at_ms DESC
            """
        ).fetchall()
        return [self._mapping_profile_row(row) for row in rows]

    def get_mapping_profile(self, profile_id: str) -> dict[str, Any] | None:
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

    def save_memory(self, record: dict[str, Any]) -> None:
        ts = now_ms()
        self.conn.execute(
            f"""
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
        self.conn.commit()

    def update_memory(self, memory_id: str, **fields: Any) -> bool:
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
        self.conn.commit()
        return cur.rowcount > 0

    def get_memory(self, memory_id: str) -> dict[str, Any] | None:
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
        limit: int = 50,
        include_expired: bool = False,
    ) -> list[dict[str, Any]]:
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
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self.conn.execute(
            f"SELECT {self._MEMORY_COLUMNS} FROM memory_entries {where} ORDER BY created_at_ms DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def memory_due_for_expiry(self, now_ms_value: int) -> list[dict[str, Any]]:
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
        self, event_id: str, memory_id: str, layer: str, event_type: str, actor: str, detail: dict[str, Any]
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO memory_events
            (event_id, memory_id, layer, event_type, actor, detail_json, created_at_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, memory_id, layer, event_type, actor, json.dumps(detail, ensure_ascii=False, sort_keys=True), now_ms()),
        )
        self.conn.commit()

    def list_memory_events(
        self, memory_id: str | None = None, event_type: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
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

    def insert_audit(self, audit_id: str, trace_id: str, actor: str, action: str, detail: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT INTO audit_log
            (audit_id, trace_id, actor, action, detail_json, created_at_ms)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (audit_id, trace_id, actor, action, json.dumps(detail, ensure_ascii=False, sort_keys=True), now_ms()),
        )
        self.conn.commit()

    def list_cases(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
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
            FROM cases c ORDER BY c.updated_at_ms DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_case(self, case_id: str) -> dict[str, Any] | None:
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
        result["linked_alerts"] = self._linked_alerts(case_id)
        return result

    def get_linked_alert(self, alert_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT case_id FROM case_alert_links WHERE alert_id = ? ORDER BY created_at_ms DESC LIMIT 1",
            (alert_id,),
        ).fetchone()
        if not row:
            return None
        for item in self._linked_alerts(row["case_id"]):
            if item.get("alert_id") == alert_id:
                return item
        return None

    def _linked_alerts(self, case_id: str) -> list[dict[str, Any]]:
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
              ne.created_at_ms AS normalized_created_at_ms
            FROM case_alert_links l
            LEFT JOIN raw_alerts ra ON ra.alert_id = l.alert_id
            LEFT JOIN normalized_events ne ON ne.event_id = l.event_id
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
                    "raw_alert": raw_alert,
                    "normalized_event": normalized_event,
                }
            )
        return linked

    def stats(self) -> dict[str, Any]:
        case_count = self.conn.execute("SELECT COUNT(*) c FROM cases").fetchone()["c"]
        alert_count = self.conn.execute("SELECT COUNT(*) c FROM raw_alerts").fetchone()["c"]
        high_count = self.conn.execute("SELECT COUNT(*) c FROM cases WHERE severity IN ('high', 'critical')").fetchone()["c"]
        return {"cases": case_count, "alerts": alert_count, "high_or_critical_cases": high_count}
