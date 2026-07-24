from __future__ import annotations

# ruff: noqa: E402 -- source checkout scripts add the project root before imports.

import argparse
import json
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defensive_ai_gateway.config import load_config
from defensive_ai_gateway.memory import (
    LAYER_ASSET_PROFILE,
    LAYER_CASE_SHORT_TERM,
    LAYER_ORG_KNOWLEDGE,
    LAYER_PRODUCT_LONG_TERM,
    STATUS_PENDING,
)

# Alert/analysis runtime tables produced by the gateway during analysis.
# Cleared on every run. mapping_profiles (config) is never touched unless
# --include-profiles is passed.
ALERT_TABLES = [
    "audit_log",
    # Alert dispositions are alert-runtime state. They must be removed before
    # cases/raw alerts so a reused demo alert_id cannot inherit an old verdict.
    "alert_dispositions",
    "case_alert_links",
    "agent_runs",
    "approval_votes",
    "validation_review_resolutions",
    "validation_runs",
    "action_approvals",
    "memory_matches",
    "cases",
    "normalized_events",
    "raw_alerts",
    "durable_alert_inbox",
]


class ActiveAlertProcessingError(RuntimeError):
    pass


def _db_path(config_path: str) -> Path:
    try:
        config = load_config(config_path) if config_path else load_config("config/dev.yaml")
    except FileNotFoundError as exc:
        print(json.dumps({"error": f"配置文件不存在: {exc.filename or config_path}"}, ensure_ascii=False, indent=2))
        sys.exit(1)
    return Path(config.database.path)


def _count(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> int:
    return int(conn.execute(sql, params).fetchone()[0])


def _select_memory_ids(conn: sqlite3.Connection, include_approved: bool, include_org: bool) -> list[str]:
    """memory_ids to delete under the current flags.

    Default (newly-generated / unreviewed): case_short_term + asset_profile +
    pending product_long_term. Approved product_long_term and org_knowledge are
    governed/curated and are kept unless explicitly included.
    """
    clauses = [
        "layer = ?",
        "layer = ?",
    ]
    params: list = [LAYER_CASE_SHORT_TERM, LAYER_ASSET_PROFILE]
    # pending long-term candidates (newly proposed, awaiting approval)
    clauses.append("(layer = ? AND status = ?)")
    params += [LAYER_PRODUCT_LONG_TERM, STATUS_PENDING]
    if include_approved:
        # promoted long-term memories: status active with an approver recorded
        clauses.append("(layer = ? AND status = 'active' AND approved_by != '')")
        params += [LAYER_PRODUCT_LONG_TERM]
    if include_org:
        clauses.append("layer = ?")
        params += [LAYER_ORG_KNOWLEDGE]
    where = " OR ".join(clauses)
    rows = conn.execute(f"SELECT memory_id FROM memory_entries WHERE {where}", params).fetchall()
    return [r[0] for r in rows]


def _preview(conn: sqlite3.Connection, include_approved: bool, include_org: bool, include_profiles: bool) -> dict:
    alerts = {t: _count(conn, f"SELECT COUNT(*) FROM {t}") for t in ALERT_TABLES}
    active_inbox = {
        row[0]: int(row[1])
        for row in conn.execute(
            """
            SELECT status, COUNT(*)
            FROM durable_alert_inbox
            WHERE status IN ('pending', 'retry', 'deferred', 'processing')
            GROUP BY status
            """
        ).fetchall()
    }
    mem_deleted = _select_memory_ids(conn, include_approved, include_org)
    # memory_events that reference the to-be-deleted memories
    mem_events = _count(
        conn,
        "SELECT COUNT(*) FROM memory_events WHERE memory_id IN (%s)" % _placeholders(len(mem_deleted))
        if mem_deleted
        else "SELECT 0",
        tuple(mem_deleted),
    ) if mem_deleted else 0
    kept = {
        "org_knowledge": _count(conn, "SELECT COUNT(*) FROM memory_entries WHERE layer = ?", (LAYER_ORG_KNOWLEDGE,))
        if not include_org
        else 0,
        "approved_product_long_term": _count(
            conn,
            "SELECT COUNT(*) FROM memory_entries WHERE layer = ? AND status = 'active' AND approved_by != ''",
            (LAYER_PRODUCT_LONG_TERM,),
        )
        if not include_approved
        else 0,
    }
    profiles = _count(conn, "SELECT COUNT(*) FROM mapping_profiles")
    return {
        "alerts": alerts,
        "active_inbox": active_inbox,
        "memories_to_delete": len(mem_deleted),
        "memory_events_to_delete": mem_events,
        "memories_kept": kept,
        "mapping_profiles": profiles,
        "mapping_profiles_kept": not include_profiles,
    }


def _placeholders(n: int) -> str:
    return ",".join("?" * n)


def _delete(conn: sqlite3.Connection, include_approved: bool, include_org: bool, include_profiles: bool) -> dict:
    # The gateway Repository enables foreign keys, but this helper is also used
    # directly by tests and operators with a plain sqlite3 connection. Enable
    # them here so future runtime tables cannot silently leave orphan rows.
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("BEGIN IMMEDIATE")
    try:
        active = _count(
            conn,
            """
            SELECT COUNT(*) FROM durable_alert_inbox
            WHERE status IN ('pending', 'retry', 'deferred', 'processing')
            """,
        )
        if active:
            raise ActiveAlertProcessingError(
                f"refusing to clean while {active} alert(s) are pending, retrying, deferred, or processing"
            )

        deleted = {}
        for table in ALERT_TABLES:
            n = conn.execute(f"DELETE FROM {table}").rowcount
            deleted[table] = n

        mem_ids = _select_memory_ids(conn, include_approved, include_org)
        mem_events_deleted = 0
        if mem_ids:
            mem_events_deleted = conn.execute(
                "DELETE FROM memory_events WHERE memory_id IN (%s)" % _placeholders(len(mem_ids)),
                tuple(mem_ids),
            ).rowcount
        # Clean events for memory layers fully owned by this script, including
        # orphaned history left by older versions.
        conn.execute(
            "DELETE FROM memory_events WHERE layer IN (?, ?)",
            (LAYER_CASE_SHORT_TERM, LAYER_ASSET_PROFILE),
        )
        mem_deleted = 0
        if mem_ids:
            mem_deleted = conn.execute(
                "DELETE FROM memory_entries WHERE memory_id IN (%s)" % _placeholders(len(mem_ids)),
                tuple(mem_ids),
            ).rowcount
        if include_org:
            conn.execute("DELETE FROM memory_entries WHERE layer = ?", (LAYER_ORG_KNOWLEDGE,))
        if include_approved:
            conn.execute(
                "DELETE FROM memory_entries WHERE layer = ? AND status = 'active' AND approved_by != ''",
                (LAYER_PRODUCT_LONG_TERM,),
            )
        profiles_deleted = 0
        if include_profiles:
            profiles_deleted = conn.execute("DELETE FROM mapping_profiles").rowcount
        deleted["memory_entries"] = mem_deleted
        deleted["memory_events"] = mem_events_deleted
        deleted["mapping_profiles_deleted"] = profiles_deleted
        conn.commit()
        return deleted
    except Exception:
        conn.rollback()
        raise


def main() -> None:
    parser = argparse.ArgumentParser(
        description="清理告警与新生成记忆，保留治理种子记忆（org_knowledge）与已审批长期记忆。"
    )
    parser.add_argument("--config", default="config/dev.yaml", help="网关配置文件路径（用于定位数据库）")
    parser.add_argument("--include-approved", action="store_true", help="同时清理已审批的 product_long_term 记忆（默认保留）")
    parser.add_argument("--include-org", action="store_true", help="同时清理 org_knowledge 治理种子记忆（默认保留）")
    parser.add_argument("--include-profiles", action="store_true", help="同时清理 mapping_profiles（默认保留）")
    parser.add_argument("--dry-run", action="store_true", help="只预览将清理的内容，不实际删除")
    parser.add_argument("-y", "--yes", action="store_true", help="跳过确认提示")
    args = parser.parse_args()

    db_path = _db_path(args.config)
    if not db_path.exists():
        print(json.dumps({"error": f"数据库不存在: {db_path}", "db_path": str(db_path)}, ensure_ascii=False, indent=2))
        sys.exit(1)

    conn = sqlite3.connect(str(db_path))
    try:
        preview = _preview(conn, args.include_approved, args.include_org, args.include_profiles)
        print(json.dumps(
            {
                "db_path": str(db_path),
                "dry_run": args.dry_run,
                "will_delete": preview,
                "note": (
                    "默认保留 org_knowledge 治理种子与已审批长期记忆；用 --include-approved / --include-org 扩大清理范围。"
                ),
            },
            ensure_ascii=False, indent=2,
        ))
        if args.dry_run:
            return
        if not args.yes:
            answer = input("\n确认清理以上告警与记忆？输入 yes 继续：").strip().lower()
            if answer not in {"yes", "y"}:
                print("已取消。")
                return
        try:
            deleted = _delete(conn, args.include_approved, args.include_org, args.include_profiles)
        except ActiveAlertProcessingError as exc:
            print(
                json.dumps(
                    {
                        "error": str(exc),
                        "hint": "等待 Dashboard 待处理队列和 inflight 都变为 0 后再清理。",
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            sys.exit(2)
        print(json.dumps({"deleted": deleted, "db_path": str(db_path)}, ensure_ascii=False, indent=2))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
