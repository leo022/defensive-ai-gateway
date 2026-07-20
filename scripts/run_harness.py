from __future__ import annotations

# ruff: noqa: E402 -- source checkout scripts add the project root before imports.

import argparse
import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defensive_ai_gateway.config import GatewayConfig, load_config
from defensive_ai_gateway.database import Repository
from defensive_ai_gateway.log_adapter import (
    LogAdapter,
    MappingProfile,
    default_mapping_profile,
    demo_rasp_profile,
    explicit_product,
    fingerprint_product,
)
from defensive_ai_gateway.llm import LocalHeuristicLLM, build_llm
from defensive_ai_gateway.memory import MemoryManager
from defensive_ai_gateway.models import RawAlert
from defensive_ai_gateway.models import now_ms
from defensive_ai_gateway.normalizer import EventNormalizer
from defensive_ai_gateway.orchestrator import Orchestrator
from defensive_ai_gateway.policy import PolicyEngine
from defensive_ai_gateway.sample_alerts import PRODUCTS, SCENARIOS, generate_alerts


def load_alert(path: Path, adapter: LogAdapter | None = None) -> RawAlert:
    data = json.loads(path.read_text(encoding="utf-8"))
    if adapter and not explicit_product(data) and fingerprint_product(data) == "rasp":
        result = adapter.adapt(demo_rasp_profile(), data)
        if result["ok"]:
            result["raw_alert"].trusted_sample = True
            return result["raw_alert"]
    return RawAlert(
        source=str(data.get("source", "harness")),
        product=str(data.get("product", "siem")),
        event_type=str(data.get("event_type", "unknown")),
        severity=str(data.get("severity", "medium")),
        timestamp=str(data.get("timestamp", "")),
        payload=dict(data.get("payload", data)),
        alert_id=str(data.get("alert_id", data.get("id", ""))),
        trusted_sample=True,
    )


def load_profile(profile_id: str, profile_file: str | None) -> MappingProfile | None:
    if profile_file:
        data = json.loads(Path(profile_file).read_text(encoding="utf-8"))
        return MappingProfile.from_dict(data)
    if not profile_id:
        return None
    builtins = {profile.profile_id: profile for profile in [default_mapping_profile(), demo_rasp_profile()]}
    if profile_id not in builtins:
        raise SystemExit(f"Unknown built-in mapping profile: {profile_id}. Use --mapping-profile-file for custom profiles.")
    return builtins[profile_id]


def load_alert_with_profile(path: Path, adapter: LogAdapter, profile: MappingProfile) -> RawAlert:
    data = json.loads(path.read_text(encoding="utf-8"))
    result = adapter.adapt(profile, data)
    if not result["ok"]:
        raise SystemExit(f"Mapping failed for {path}: {', '.join(result['errors'])}")
    result["raw_alert"].trusted_sample = True
    return result["raw_alert"]


def seed_demo_false_positive_memory(repo: Repository, memory: MemoryManager) -> None:
    future = now_ms() + 90 * 24 * 3600 * 1000
    records = [
        {
            "memory_id": "mem_demo_waf_synthetic_search",
            "layer": "product_long_term",
            "namespace": memory.product_namespace("waf"),
            "retrieval_key": "WAF-941-APP-ANOMALY",
            "content": "false_positive: approved synthetic-browser traffic for /openbanking/v2/payments/search on mobile-payment-api",
            "source_case_id": "demo_prior_case_waf_synthetic",
            "scope": "waf:false_positive_pattern",
            "trust_level": "medium",
            "status": "active",
            "sensitivity_ok": True,
            "approved_by": "demo-analyst",
            "expires_at_ms": future,
        },
        {
            "memory_id": "mem_demo_waf_partner_batch",
            "layer": "product_long_term",
            "namespace": memory.product_namespace("waf"),
            "retrieval_key": "WAF-920-PROTOCOL",
            "content": "false_positive: approved bank-partner-batch-client/2.4 traffic for /partner/settlement/upload",
            "source_case_id": "demo_prior_case_waf_partner",
            "scope": "waf:false_positive_pattern",
            "trust_level": "medium",
            "status": "active",
            "sensitivity_ok": True,
            "approved_by": "demo-analyst",
            "expires_at_ms": future,
        },
    ]
    for record in records:
        repo.save_memory(record)


def main():
    parser = argparse.ArgumentParser(description="Replay sample alerts through the local harness")
    parser.add_argument("--samples", default="samples", help="Directory containing *.json alert samples")
    parser.add_argument("--fail-on-low-confidence", type=float, default=0.0)
    parser.add_argument(
        "--fail-on-validation-review",
        action="store_true",
        help="Fail when Validator returns review or blocked instead of passed",
    )
    parser.add_argument("--config", default="config/dev.yaml")
    parser.add_argument("--use-config-llm", action="store_true", help="Use the LLM provider from config instead of deterministic local analyzer")
    parser.add_argument("--random-count", type=int, default=0, help="Append N randomized sample alerts to the replay")
    parser.add_argument("--random-product", choices=PRODUCTS, help="Product for randomized alerts; omitted means mixed products")
    parser.add_argument("--random-scenario", choices=SCENARIOS, default="random", help="Scenario type for randomized alerts")
    parser.add_argument("--random-feature", help="Feature for randomized alerts; omitted means random feature")
    parser.add_argument("--seed", type=int, help="Seed for repeatable randomized alerts")
    parser.add_argument("--seed-demo-memory", action="store_true", help="Seed approved demo false-positive memory before replay")
    parser.add_argument("--mapping-profile", help="Apply a built-in mapping profile to static sample files before replay")
    parser.add_argument("--mapping-profile-file", help="Apply a custom mapping profile JSON file to static sample files before replay")
    args = parser.parse_args()

    sample_dir = Path(args.samples)
    paths = sorted(sample_dir.glob("*.json"))
    if not paths:
        raise SystemExit(f"No JSON samples found in {sample_dir}")

    with tempfile.TemporaryDirectory() as tmp:
        config = load_config(args.config) if args.use_config_llm else GatewayConfig()
        repo = Repository(str(Path(tmp) / "harness.db"))
        policy = PolicyEngine(config.policy)
        llm = build_llm(config.llm) if args.use_config_llm else LocalHeuristicLLM()
        memory = MemoryManager(repo, policy)
        if args.seed_demo_memory:
            seed_demo_false_positive_memory(repo, memory)
        normalizer = EventNormalizer(policy)
        adapter = LogAdapter(normalizer)
        profile = load_profile(args.mapping_profile or "", args.mapping_profile_file)
        orchestrator = Orchestrator(repo, normalizer, memory, llm, policy)
        results = []
        for path in paths:
            alert = load_alert_with_profile(path, adapter, profile) if profile else load_alert(path, adapter)
            result = orchestrator.handle_alert(alert)
            item = {
                "sample": str(path),
                "mapping_profile": profile.profile_id if profile else "",
                "case_id": result.case_id,
                "agent": result.agent,
                "classification": result.classification,
                "severity": result.severity,
                "confidence": result.confidence,
                "summary": result.summary,
                "verdict": result.explanation.get("verdict"),
                "analysis_dimensions": result.explanation.get("dimensions", []),
                "whitelist_recommendation": result.explanation.get("whitelist_recommendation"),
                "missing_evidence": result.missing_evidence,
                "recommended_actions": [action.action for action in result.recommended_actions],
                "skill": result.explanation.get("skill", {}),
                "validation": result.explanation.get("validation", {}),
                "approval_request_ids": result.explanation.get("approval_request_ids", []),
            }
            results.append(item)
            if args.fail_on_low_confidence and result.confidence < args.fail_on_low_confidence:
                raise SystemExit(f"Low confidence for {path}: {result.confidence}")
            if args.fail_on_validation_review and item["validation"].get("status") != "passed":
                raise SystemExit(
                    f"Validation gate failed for {path}: {item['validation'].get('status', 'missing')}"
                )
        for idx, payload in enumerate(
            generate_alerts(
                args.random_count,
                product=args.random_product,
                scenario=args.random_scenario,
                seed=args.seed,
                feature=args.random_feature,
            ),
            start=1,
        ):
            alert = RawAlert(
                source=str(payload.get("source", "harness-random")),
                product=str(payload.get("product", "siem")),
                event_type=str(payload.get("event_type", "unknown")),
                severity=str(payload.get("severity", "medium")),
                timestamp=str(payload.get("timestamp", "")),
                payload=dict(payload.get("payload", payload)),
                alert_id=str(payload.get("alert_id", payload.get("id", ""))),
                trusted_sample=True,
            )
            result = orchestrator.handle_alert(alert)
            item = {
                "sample": f"random:{idx}:{alert.product}:{args.random_scenario}",
                "case_id": result.case_id,
                "agent": result.agent,
                "classification": result.classification,
                "severity": result.severity,
                "confidence": result.confidence,
                "summary": result.summary,
                "verdict": result.explanation.get("verdict"),
                "analysis_dimensions": result.explanation.get("dimensions", []),
                "whitelist_recommendation": result.explanation.get("whitelist_recommendation"),
                "missing_evidence": result.missing_evidence,
                "recommended_actions": [action.action for action in result.recommended_actions],
                "skill": result.explanation.get("skill", {}),
                "validation": result.explanation.get("validation", {}),
                "approval_request_ids": result.explanation.get("approval_request_ids", []),
            }
            results.append(item)
            if args.fail_on_low_confidence and result.confidence < args.fail_on_low_confidence:
                raise SystemExit(f"Low confidence for randomized alert {idx}: {result.confidence}")
            if args.fail_on_validation_review and item["validation"].get("status") != "passed":
                raise SystemExit(
                    f"Validation gate failed for randomized alert {idx}: "
                    f"{item['validation'].get('status', 'missing')}"
                )

    validation_counts: dict[str, int] = {}
    for item in results:
        status = str(item.get("validation", {}).get("status") or "missing")
        validation_counts[status] = validation_counts.get(status, 0) + 1
    print(
        json.dumps(
            {
                "samples": len(results),
                "static_samples": len(paths),
                "random_samples": args.random_count,
                "validation": validation_counts,
                "results": results,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
