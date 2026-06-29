from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defensive_ai_gateway.sample_alerts import generate_alert

# 15 curated demo alerts covering all 5 products, all 3 classifications
# (real attack / needs-manual-review / false-positive) and a spread of
# severities (critical / high / medium / low).
#
# Ordered so the demo queue staggers alert type (scenario/product) and severity
# instead of grouping by verdict or product.
#
# (product, scenario, label_zh, seed)
DEMO_ALERTS: list[tuple[str, str, str, int]] = [
    ("hips", "suspicious", "需人工排查-编码PowerShell缺闭环", 2002),
    ("siem", "attack", "真实攻击-横向移动/服务账号滥用", 1001),
    ("waf", "false_positive", "误报-合成浏览器/合作方批次", 4003),
    ("rasp", "attack", "真实攻击-反序列化/JNDI注入", 5001),
    ("siem", "suspicious", "需人工排查-服务账号弱关联信号", 1002),
    ("ndr", "false_positive", "误报-备份复制流量突增", 3003),
    ("waf", "suspicious", "需人工排查-SQL/XSS疑似命中", 4002),
    ("ndr", "attack", "真实攻击-C2 beacon/数据外传", 3001),
    ("siem", "false_positive", "误报-已批准维护窗口", 1003),
    ("hips", "attack", "真实攻击-凭证访问与横向移动", 2001),
    ("ndr", "suspicious", "需人工排查-罕见出站TLS连接", 3002),
    ("rasp", "false_positive", "误报-Canary防护巡检", 5003),
    ("waf", "attack", "真实攻击-SQL注入/路径遍历", 4001),
    ("hips", "false_positive", "误报-补丁盘点脚本", 2003),
    ("rasp", "suspicious", "需人工排查-SQL注入疑似触达", 5002),
]

# 10-alert coverage batch: 2 alerts per product, covering all 3 scenarios
# (attack/suspicious/false_positive) and all 4 severities (critical/high/
# medium/low). Seeds are tuned so WAF attack -> high (SQLi) and NDR attack
# -> critical (exfiltration).
COVERAGE_BATCH_10: list[tuple[str, str, str, int]] = [
    ("ndr", "attack", "NDR-数据外传(critical)", 7401),
    ("waf", "suspicious", "WAF-SQL注入疑似(medium)", 7102),
    ("hips", "attack", "HIPS-凭证访问横向(high)", 7201),
    ("rasp", "false_positive", "RASP-Canary巡检(low)", 7302),
    ("siem", "attack", "SIEM-横向移动(critical)", 7501),
    ("ndr", "suspicious", "NDR-罕见出站TLS(medium)", 7402),
    ("waf", "attack", "WAF-SQL注入(high)", 7107),
    ("hips", "false_positive", "HIPS-补丁盘点脚本(medium)", 7202),
    ("rasp", "attack", "RASP-命令执行(high)", 7301),
    ("siem", "suspicious", "SIEM-服务账号弱关联(medium)", 7502),
]

BATCHES = {"demo": DEMO_ALERTS, "coverage": COVERAGE_BATCH_10}


def coverage_summary(payloads: list[tuple[str, dict]]) -> dict:
    products = Counter(p["product"] for _, p in payloads)
    scenarios = Counter(p.get("_scenario", "") for _, p in payloads)
    severities = Counter(p["severity"] for _, p in payloads)
    return {
        "count": len(payloads),
        "products": dict(sorted(products.items())),
        "scenarios": dict(sorted(scenarios.items())),
        "severities": dict(sorted(severities.items())),
        "covers_all_products": set(products) == {"waf", "hips", "rasp", "ndr", "siem"},
        "covers_all_scenarios": set(scenarios) == {"attack", "suspicious", "false_positive"},
        "covers_all_severities": set(severities) == {"critical", "high", "medium", "low"},
    }


def send_alert(payload: dict, url: str, timeout: int, token: str = "") -> dict:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return {"status": resp.status, "response": json.loads(resp.read().decode("utf-8"))}


def main() -> None:
    parser = argparse.ArgumentParser(description="Send curated demo alerts to the gateway")
    parser.add_argument("--batch", choices=BATCHES, default="demo", help="demo=15 alerts; coverage=10 alerts covering all systems/types/levels")
    parser.add_argument("--url", default="http://127.0.0.1:8080/api/alerts")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--print-only", action="store_true", help="Print payloads without sending")
    parser.add_argument(
        "--token",
        default=os.getenv("DEFENSIVE_AI_API_TOKEN", ""),
        help="Gateway bearer token (defaults to env DEFENSIVE_AI_API_TOKEN). Set when the gateway requires auth.",
    )
    args = parser.parse_args()

    selected = BATCHES[args.batch]
    payloads = []
    for product, scenario, label, seed in selected:
        payload = generate_alert(product=product, scenario=scenario, seed=seed)
        payload["_scenario"] = scenario  # tag for coverage summary (stripped before send)
        payloads.append((label, payload))

    summary = coverage_summary(payloads)
    print(json.dumps({"batch": args.batch, "coverage": summary}, ensure_ascii=False, indent=2))

    if args.print_only:
        print(json.dumps({"generated": len(payloads), "alerts": [p for _, p in payloads]}, ensure_ascii=False, indent=2))
        return

    rows = []
    for label, payload in payloads:
        payload.pop("_scenario", None)  # don't send the internal tag
        try:
            result = send_alert(payload, args.url, args.timeout, args.token)
        except Exception as exc:  # noqa: BLE001
            rows.append({"label": label, "alert_id": payload.get("alert_id"), "error": str(exc)})
            continue
        body = result["response"]
        rows.append(
            {
                "label": label,
                "alert_id": payload.get("alert_id"),
                "status": result["status"],
                "case_id": body.get("case_id"),
                "classification": body.get("classification"),
                "severity": body.get("severity"),
                "confidence": body.get("confidence"),
                "verdict": (body.get("explanation") or {}).get("verdict"),
                "summary": body.get("summary"),
            }
        )

    print(json.dumps({"sent": len(rows), "results": rows}, ensure_ascii=False, indent=2))
    # Fail loudly if every send failed (e.g. auth misconfig) so CI/gates notice.
    succeeded = [r for r in rows if "error" not in r]
    if rows and not succeeded:
        sys.exit(1)


if __name__ == "__main__":
    main()
