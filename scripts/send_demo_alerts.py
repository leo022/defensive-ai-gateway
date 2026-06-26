from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defensive_ai_gateway.sample_alerts import generate_alert

# 15 curated demo alerts covering all 5 products, all 3 classifications
# (real attack / needs-manual-review / false-positive) and a spread of
# severities (critical / high / medium / low).
#
# (product, scenario, label_zh, seed)
DEMO_ALERTS: list[tuple[str, str, str, int]] = [
    # --- 真实攻击 (real attacks) ---
    ("siem", "attack", "真实攻击-横向移动/服务账号滥用", 1001),
    ("hips", "attack", "真实攻击-凭证访问与横向移动", 2001),
    ("ndr", "attack", "真实攻击-C2 beacon/数据外传", 3001),
    ("waf", "attack", "真实攻击-SQL注入/路径遍历", 4001),
    ("rasp", "attack", "真实攻击-反序列化/JNDI注入", 5001),
    # --- 需人工排查 (needs manual review) ---
    ("siem", "suspicious", "需人工排查-服务账号弱关联信号", 1002),
    ("hips", "suspicious", "需人工排查-编码PowerShell缺闭环", 2002),
    ("ndr", "suspicious", "需人工排查-罕见出站TLS连接", 3002),
    ("waf", "suspicious", "需人工排查-SQL/XSS疑似命中", 4002),
    ("rasp", "suspicious", "需人工排查-SQL注入疑似触达", 5002),
    # --- 误报 (false positives) ---
    ("siem", "false_positive", "误报-已批准维护窗口", 1003),
    ("hips", "false_positive", "误报-补丁盘点脚本", 2003),
    ("ndr", "false_positive", "误报-备份复制流量突增", 3003),
    ("waf", "false_positive", "误报-合成浏览器/合作方批次", 4003),
    ("rasp", "false_positive", "误报-Canary防护巡检", 5003),
]


def send_alert(payload: dict, url: str, timeout: int) -> dict:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return {"status": resp.status, "response": json.loads(resp.read().decode("utf-8"))}


def main() -> None:
    parser = argparse.ArgumentParser(description="Send 15 curated demo alerts to the gateway")
    parser.add_argument("--url", default="http://127.0.0.1:8080/api/alerts")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--print-only", action="store_true", help="Print payloads without sending")
    args = parser.parse_args()

    payloads = [
        (label, generate_alert(product=product, scenario=scenario, seed=seed))
        for product, scenario, label, seed in DEMO_ALERTS
    ]

    if args.print_only:
        print(json.dumps({"generated": len(payloads), "alerts": [p for _, p in payloads]}, ensure_ascii=False, indent=2))
        return

    rows = []
    for label, payload in payloads:
        try:
            result = send_alert(payload, args.url, args.timeout)
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


if __name__ == "__main__":
    main()
