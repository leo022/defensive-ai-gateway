from __future__ import annotations

# ruff: noqa: E402 -- source checkout scripts add the project root before imports.

import argparse
import json
import os
import random
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defensive_ai_gateway.sample_alerts import PRODUCTS, SCENARIOS, available_features, generate_alerts

HK_TZ = timezone(timedelta(hours=8))
# Leaf keys whose values identify a single alert instance rather than a scenario.
# Mutating them yields a distinct alert while preserving the template's semantics.
_MUTATE_LEAF_KEYS = {
    "alert_id", "request_id", "session", "src_ip", "attack_source", "dst_ip",
    "xff", "rasp_trace_id", "same_user_failed_login_10m", "authorization",
    "same_src_ip_5m", "same_session_5m", "same_uri_5m",
}
_TIMESTAMP_LEAF_KEYS = {"timestamp", "attack_time", "trigger_time", "created_at"}


def _rand_alert_id(product: str, rng: random.Random) -> str:
    now = datetime.now(HK_TZ)
    return f"{product}-{now.strftime('%Y%m%d%H%M%S')}-{rng.randrange(1000, 9999)}"


def _jitter_ip(value: str, rng: random.Random) -> str:
    parts = str(value).split(".")
    if len(parts) == 4 and parts[0].isdigit():
        parts[-1] = str(rng.randrange(10, 250))
        return ".".join(parts)
    return value


def _now_iso(rng: random.Random) -> str:
    base = datetime.now(HK_TZ) - timedelta(seconds=rng.randrange(0, 600))
    return base.isoformat()


def _mutate_value(key: str, value, rng: random.Random):
    """Return a randomized replacement for a known variable leaf, or None to keep."""
    if key in _TIMESTAMP_LEAF_KEYS and isinstance(value, str):
        return _now_iso(rng)
    if key == "alert_id" and isinstance(value, str):
        product = str(value).split("-", 1)[0] or "alert"
        return _rand_alert_id(product, rng)
    if key in {"src_ip", "attack_source", "dst_ip"} and isinstance(value, str):
        return _jitter_ip(value, rng)
    if key == "xff" and isinstance(value, str):
        return _jitter_ip(value, rng)
    if key == "request_id" and isinstance(value, str):
        return f"req-{rng.randrange(10**7, 10**8):x}"
    if key == "session" and isinstance(value, str):
        return f"redacted-session-{rng.randrange(1000, 9999)}"
    if key == "rasp_trace_id" and isinstance(value, str):
        return f"rasp-trace-{rng.randrange(1000, 9999)}"
    if key == "same_user_failed_login_10m" and isinstance(value, int):
        return rng.randrange(1, 6)
    if key == "authorization" and isinstance(value, str):
        return f"Bearer demo-token-{rng.randrange(1000, 9999)}"
    if key == "same_src_ip_5m" and isinstance(value, int):
        return rng.randrange(30, 120)
    if key == "same_session_5m" and isinstance(value, int):
        return rng.randrange(8, 30)
    if key == "same_uri_5m" and isinstance(value, int):
        return rng.randrange(40, 130)
    if key == "confidence" and isinstance(value, (int, float)):
        return round(rng.uniform(0.72, 0.93), 2)
    return None


def _sync_rate_narrative(payload: dict, old_by_key: dict[str, str], rng: random.Random) -> None:
    """Keep evidence_assessment narrative numbers consistent with randomized rates."""
    assessment = payload.get("evidence_assessment") if isinstance(payload, dict) else None
    if not isinstance(assessment, dict):
        return
    rate_window = payload.get("rate_window") if isinstance(payload, dict) else None
    if not isinstance(rate_window, dict):
        return
    for key in ("same_src_ip_5m", "same_session_5m", "same_uri_5m"):
        old = old_by_key.get(key)
        new = rate_window.get(key)
        if old is None or new is None or str(old) == str(new):
            continue
        pattern = re.compile(rf"(?<!\d){re.escape(str(old))}(?!\d)")
        for dim in assessment.get("analysis_dimensions", []) or []:
            if isinstance(dim, dict) and isinstance(dim.get("evidence"), str):
                dim["evidence"] = pattern.sub(str(new), dim["evidence"])
        for field in ("success_assessment", "business_impact"):
            if isinstance(assessment.get(field), str):
                assessment[field] = pattern.sub(str(new), assessment[field])


def mutate_alert(payload: dict, rng: random.Random) -> dict:
    """Return a deep-copied alert with per-instance fields randomized.

    Keeps the template's product, event type, rule, scenario verdict and
    whitelist semantics intact, so each send produces a distinct alert (and a
    distinct case) while remaining a coherent sample.
    """
    snapshot: dict[str, str] = {}

    def walk(node):
        if isinstance(node, dict):
            for key in list(node.keys()):
                value = node[key]
                if isinstance(value, (dict, list)):
                    walk(value)
                    continue
                if key in {"same_src_ip_5m", "same_session_5m", "same_uri_5m"}:
                    snapshot[key] = value
                replacement = _mutate_value(key, value, rng)
                if replacement is not None:
                    node[key] = replacement
        elif isinstance(node, list):
            for item in node:
                walk(item)

    result = json.loads(json.dumps(payload, ensure_ascii=False))
    walk(result)
    payload_node = result.get("payload") if isinstance(result, dict) else None
    if isinstance(payload_node, dict):
        _sync_rate_narrative(payload_node, snapshot, rng)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", help="Static JSON alert file to send")
    parser.add_argument("--random", action="store_true", help="Generate randomized sample alert(s) instead of reading --file")
    parser.add_argument("--mutate", action="store_true", help="Read --file but randomize per-instance fields (alert_id, IPs, timestamps, rates) so each send is a distinct alert")
    parser.add_argument("--count", type=int, default=1, help="Number of alerts to send (used with --random or --mutate)")
    parser.add_argument("--product", choices=PRODUCTS, help="Product to randomize; omitted means mixed products")
    parser.add_argument("--scenario", choices=SCENARIOS, default="random", help="Randomized scenario type")
    parser.add_argument(
        "--feature",
        help="Product feature to generate (for example ndr: brute_force); omitted means random feature",
    )
    parser.add_argument(
        "--list-features",
        action="store_true",
        help="List supported product features and exit",
    )
    parser.add_argument("--seed", type=int, help="Seed for repeatable randomized/mutated samples")
    parser.add_argument("--print-only", action="store_true", help="Print payloads without sending them")
    parser.add_argument("--url", default="http://127.0.0.1:8080/api/alerts")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument(
        "--token",
        default=os.getenv("DEFENSIVE_AI_API_TOKEN", ""),
        help="Gateway bearer token (defaults to env DEFENSIVE_AI_API_TOKEN). Set when the gateway requires auth.",
    )
    args = parser.parse_args()

    if args.list_features:
        if args.product:
            print(json.dumps({args.product: available_features(args.product)}, ensure_ascii=False, indent=2))
        else:
            print(json.dumps(available_features(), ensure_ascii=False, indent=2))
        return

    if args.feature and not args.random:
        parser.error("--feature can only be used with --random")
    if args.feature and not args.product:
        parser.error("--product is required when --feature is specified")

    if args.random:
        payloads = generate_alerts(
            args.count,
            product=args.product,
            scenario=args.scenario,
            seed=args.seed,
            feature=args.feature,
        )
    elif args.mutate:
        if not args.file:
            parser.error("--file is required with --mutate")
        rng = random.Random(args.seed)
        template = json.loads(Path(args.file).read_text(encoding="utf-8"))
        payloads = [mutate_alert(template, rng) for _ in range(max(1, args.count))]
    else:
        if not args.file:
            parser.error("--file is required unless --random or --mutate is set")
        payloads = [json.loads(Path(args.file).read_text(encoding="utf-8"))]

    if args.print_only:
        print(json.dumps({"generated": len(payloads), "alerts": payloads}, ensure_ascii=False, indent=2))
        return

    responses = []
    headers = {
        "Content-Type": "application/json",
        "X-Defensive-AI-Demo-Sample": "1",
    }
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"
    for payload in payloads:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(args.url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=args.timeout) as resp:
                responses.append({"status": resp.status, "alert_id": payload.get("alert_id"), "response": json.loads(resp.read().decode("utf-8"))})
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            try:
                response = json.loads(body)
            except json.JSONDecodeError:
                response = body
            responses.append({"status": exc.code, "alert_id": payload.get("alert_id"), "error": response})
            print(json.dumps({"sent": len(responses) - 1, "failed": 1, "results": responses}, ensure_ascii=False, indent=2))
            raise SystemExit(1) from None
    print(json.dumps({"sent": len(responses), "results": responses}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
