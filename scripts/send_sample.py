from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defensive_ai_gateway.sample_alerts import PRODUCTS, SCENARIOS, generate_alerts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", help="Static JSON alert file to send")
    parser.add_argument("--random", action="store_true", help="Generate randomized sample alert(s) instead of reading --file")
    parser.add_argument("--count", type=int, default=1, help="Number of randomized alerts to send")
    parser.add_argument("--product", choices=PRODUCTS, help="Product to randomize; omitted means mixed products")
    parser.add_argument("--scenario", choices=SCENARIOS, default="random", help="Randomized scenario type")
    parser.add_argument("--seed", type=int, help="Seed for repeatable randomized samples")
    parser.add_argument("--print-only", action="store_true", help="Print payloads without sending them")
    parser.add_argument("--url", default="http://127.0.0.1:8080/api/alerts")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()

    if args.random:
        payloads = generate_alerts(args.count, product=args.product, scenario=args.scenario, seed=args.seed)
    else:
        if not args.file:
            parser.error("--file is required unless --random is set")
        payloads = [json.loads(Path(args.file).read_text(encoding="utf-8"))]

    if args.print_only:
        print(json.dumps({"generated": len(payloads), "alerts": payloads}, ensure_ascii=False, indent=2))
        return

    responses = []
    for payload in payloads:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(args.url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            responses.append({"status": resp.status, "alert_id": payload.get("alert_id"), "response": json.loads(resp.read().decode("utf-8"))})
    print(json.dumps({"sent": len(responses), "results": responses}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
