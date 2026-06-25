from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any


PRODUCTS = ("waf", "hips", "rasp", "ndr", "siem")
SCENARIOS = ("random", "attack", "suspicious", "false_positive")
HK_TZ = timezone(timedelta(hours=8))


def generate_alert(product: str | None = None, scenario: str = "random", seed: int | None = None) -> dict[str, Any]:
    rng = random.Random(seed)
    selected_product = (product or rng.choice(PRODUCTS)).lower()
    if selected_product not in PRODUCTS:
        raise ValueError(f"Unsupported product: {product}")
    selected_scenario = scenario.lower()
    if selected_scenario not in SCENARIOS:
        raise ValueError(f"Unsupported scenario: {scenario}")
    return _BUILDERS[selected_product](rng, selected_scenario)


def generate_alerts(
    count: int,
    product: str | None = None,
    scenario: str = "random",
    seed: int | None = None,
) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    return [
        generate_alert(product=product, scenario=scenario, seed=rng.randrange(1, 10_000_000))
        for _ in range(count)
    ]


def _scenario(rng: random.Random, requested: str) -> str:
    if requested != "random":
        return requested
    roll = rng.random()
    if roll < 0.24:
        return "false_positive"
    if roll < 0.58:
        return "suspicious"
    return "attack"


def _timestamp(rng: random.Random) -> str:
    base = datetime(2026, 6, 24, 9, 30, tzinfo=HK_TZ)
    return (base + timedelta(seconds=rng.randrange(0, 7200))).isoformat()


def _alert_id(product: str, rng: random.Random) -> str:
    return f"{product}-{rng.randrange(20260624090000, 20260624125959)}-{rng.randrange(1000, 9999)}"


def _ip(rng: random.Random, prefix: str) -> str:
    return f"{prefix}.{rng.randrange(10, 250)}"


def _choice(rng: random.Random, items: list[dict[str, Any]]) -> dict[str, Any]:
    return dict(rng.choice(items))


def _dimension(title: str, evidence: str, status: str = "info") -> dict[str, str]:
    return {"title": title, "status": status, "evidence": evidence}


def _assessment(
    verdict: str,
    dimensions: list[dict[str, str]],
    success: str,
    impact: str,
    missing: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "expected_verdict": verdict,
        "analysis_dimensions": dimensions,
        "success_assessment": success,
        "business_impact": impact,
        "missing_evidence": missing or [],
    }


def _waf(rng: random.Random, requested: str) -> dict[str, Any]:
    scenario = _scenario(rng, requested)
    fp = scenario == "false_positive"
    suspicious = scenario == "suspicious"
    attack_variants = [
        {
            "rule_id": "WAF-942-SQLI",
            "rule_name": "SQL injection anomaly threshold exceeded",
            "event_type": "web_attack_sqli_anomaly",
            "severity": "high",
            "uri": "/openbanking/v2/payments/search",
            "matched_parameters": ["beneficiaryName", "remarks"],
            "payload_category": "boolean expression and SQL keyword markers observed; raw payload withheld",
            "rate": (35, 90),
            "attack_type": "SQL 注入",
            "attack_marker": "SQL boolean expression markers",
        },
        {
            "rule_id": "WAF-941-XSS",
            "rule_name": "XSS marker in customer profile update",
            "event_type": "web_attack_xss_marker",
            "severity": "medium",
            "uri": "/retail/profile/update",
            "matched_parameters": ["displayName", "addressLine2"],
            "payload_category": "script marker and encoded HTML entity observed; raw payload withheld",
            "rate": (8, 25),
            "attack_type": "跨站脚本攻击",
            "attack_marker": "encoded script and HTML entity markers",
        },
        {
            "rule_id": "WAF-930-LFI",
            "rule_name": "Path traversal attempt against document endpoint",
            "event_type": "web_attack_path_traversal",
            "severity": "high",
            "uri": "/corporate/docs/download",
            "matched_parameters": ["file", "template"],
            "payload_category": "directory traversal marker observed; raw payload withheld",
            "rate": (12, 40),
            "attack_type": "目录遍历漏洞",
            "attack_marker": "directory traversal markers",
        },
    ]
    fp_variants = [
        {
            "rule_id": "WAF-941-APP-ANOMALY",
            "rule_name": "Known synthetic browser search anomaly",
            "event_type": "web_attack_rule_hit_with_account_context",
            "severity": "medium",
            "uri": "/openbanking/v2/payments/search",
            "matched_parameters": ["beneficiaryName", "remarks"],
            "payload_category": "QA synthetic browser encoded search term matched generic anomaly rule",
            "rate": (1, 5),
            "user_agent": "Mozilla/5.0 synthetic-browser",
            "memory_hint": "candidate_false_positive_pattern",
            "attack_type": "Web 通用异常规则",
            "whitelist_content": "URI=/openbanking/v2/payments/search; method=POST; parameter=beneficiaryName; UA=synthetic-browser",
            "whitelist_reason": "QA 合成浏览器在支付搜索接口提交编码搜索词，低频且有固定 UA 与会话特征。",
        },
        {
            "rule_id": "WAF-920-PROTOCOL",
            "rule_name": "Approved batch partner malformed header pattern",
            "event_type": "waf_protocol_anomaly_known_partner",
            "severity": "low",
            "uri": "/partner/settlement/upload",
            "matched_parameters": ["content-type"],
            "payload_category": "known partner client sends duplicate header during settlement batch",
            "rate": (1, 4),
            "user_agent": "bank-partner-batch-client/2.4",
            "memory_hint": "candidate_false_positive_pattern",
            "attack_type": "HTTP 协议异常",
            "whitelist_content": "URI=/partner/settlement/upload; method=POST; header=content-type; UA=bank-partner-batch-client/2.4",
            "whitelist_reason": "已批准合作方批处理客户端在结算上传接口发送稳定重复头模式。",
        },
    ]
    suspicious_variants = [
        {
            "rule_id": "WAF-942-SQLI",
            "rule_name": "SQL injection anomaly threshold partially matched",
            "event_type": "web_attack_sqli_needs_review",
            "severity": "medium",
            "uri": "/openbanking/v2/payments/search",
            "matched_parameters": ["beneficiaryName"],
            "payload_category": "single SQL keyword marker observed in a free-text business field; raw payload withheld",
            "rate": (6, 15),
            "attack_type": "SQL 注入疑似",
            "attack_marker": "single SQL keyword marker",
        },
        {
            "rule_id": "WAF-941-XSS",
            "rule_name": "XSS marker with possible rich-text business input",
            "event_type": "web_attack_xss_needs_review",
            "severity": "medium",
            "uri": "/retail/profile/update",
            "matched_parameters": ["addressLine2"],
            "payload_category": "encoded HTML entity observed in field that may accept rich text; raw payload withheld",
            "rate": (4, 12),
            "attack_type": "跨站脚本疑似",
            "attack_marker": "encoded HTML entity marker",
        },
    ]
    if fp:
        variant = _choice(rng, fp_variants)
    elif suspicious:
        variant = _choice(rng, suspicious_variants)
    else:
        variant = _choice(rng, attack_variants)
    same_src_ip = rng.randrange(*variant["rate"])
    user_agent = variant.get("user_agent") or rng.choice(
        ["Mozilla/5.0", "curl/8.4 synthetic-probe", "python-requests/2.x", "mobile-app/2026.06"]
    )
    app = "mobile-payment-api" if "openbanking" in variant["uri"] else rng.choice(["retail-web", "partner-gateway", "document-service"])
    method = "POST" if fp or suspicious else rng.choice(["POST", "GET"])
    status = 403 if scenario == "attack" else rng.choice([200, 403])
    request_id = f"req-{rng.randrange(10**7, 10**8):x}"
    action = "blocked" if scenario == "attack" else rng.choice(["logged", "blocked"])
    if scenario == "attack":
        assessment = _assessment(
            f"【真实攻击】- {variant['attack_type']}",
            [
                _dimension("请求特征", f"{method} {variant['uri']} 命中互联网侧业务接口，来源短时间请求 {same_src_ip} 次。", "risk"),
                _dimension("参数/Header", f"命中参数 {', '.join(variant['matched_parameters'])}，载荷摘要为 {variant['attack_marker']}。", "risk"),
                _dimension("规则匹配", f"{variant['rule_id']} / {variant['rule_name']} 与 {variant['attack_type']} 特征一致。", "risk"),
                _dimension("响应与处置", f"WAF 动作为 {action}，响应码 {status}，当前样本显示请求已被边界层拦截。", "blocked"),
                _dimension("行为基线", f"same_src_ip_5m={same_src_ip}，明显高于普通单用户查询频率。", "risk"),
                _dimension("关联证据", "样本预留 RASP/SIEM 关联字段，可用于确认是否到达应用层。", "review"),
            ],
            "WAF 已阻断请求；仍需通过 RASP 或应用日志确认是否存在绕过或后续请求成功。",
            f"可能影响 {app} 上的敏感接口，若绕过可能造成数据查询、脚本执行或文件访问风险。",
            ["RASP trace 或应用访问日志", "同源 IP 后续请求结果", "账号/session 的认证上下文"],
        )
        whitelist = {}
    elif suspicious:
        assessment = _assessment(
            f"【需人工复核】- {variant['attack_type']}，命中证据不完整",
            [
                _dimension("请求特征", f"{method} {variant['uri']} 命中业务接口，来源短时间请求 {same_src_ip} 次，未达到明显扫描强度。", "review"),
                _dimension("参数/Header", f"命中参数 {', '.join(variant['matched_parameters'])}，载荷摘要为 {variant['attack_marker']}，可能与业务输入混淆。", "review"),
                _dimension("规则匹配", f"{variant['rule_id']} 与攻击类型有部分重合，但当前仅单字段、单特征命中。", "review"),
                _dimension("响应与处置", f"WAF 动作为 {action}，响应码 {status}，尚不能确认是否到达应用层。", "review"),
                _dimension("行为基线", "频率高于普通请求但低于批量扫描；需要结合账号与历史请求判断。", "review"),
            ],
            "无法确认攻击成功；需要应用日志或 RASP trace 确认是否触达危险 sink。",
            f"若为真实攻击，可能影响 {app}；若为业务输入误伤，直接阻断会影响正常交易或资料更新。",
            ["RASP trace", "应用参数校验日志", "同账号近期正常请求样本", "响应体摘要或后端异常"],
        )
        whitelist = {}
    else:
        assessment = _assessment(
            f"【误报】- {variant['whitelist_reason']}",
            [
                _dimension("请求特征", f"{method} {variant['uri']} 为已知业务接口，状态码 {status}，请求频率 same_src_ip_5m={same_src_ip}。", "normal"),
                _dimension("参数/Header", f"命中字段 {', '.join(variant['matched_parameters'])} 与固定客户端 {user_agent} 相关。", "benign"),
                _dimension("规则匹配", f"{variant['rule_id']} 属于泛化或协议类规则，当前命中点更符合业务客户端特征。", "benign"),
                _dimension("响应与处置", f"WAF 动作为 {action}，没有样本证据显示应用异常或数据风险。", "normal"),
                _dimension("行为基线", "低频、固定 UA、固定接口和候选误报记忆一致。", "benign"),
            ],
            "未发现攻击成功迹象；更像业务流量被泛化规则命中。",
            "若确认误报，可降低 SOC 噪声；需保留偏离频率、来源或参数时升级复核。",
        )
        whitelist = {
            "rule_type": "WAF 白名单",
            "attack_type": variant["attack_type"],
            "detection_content": variant["whitelist_content"],
            "match_method": "相等",
            "scope": f"app={app}; rule_id={variant['rule_id']}",
            "reason": variant["whitelist_reason"],
            "review_cycle": "30 天后复核或客户端版本变更时复核",
        }
    return {
        "alert_id": _alert_id("waf", rng),
        "source": "direct",
        "product": "waf",
        "event_type": variant["event_type"],
        "severity": variant["severity"],
        "timestamp": _timestamp(rng),
        "payload": {
            "rule_id": variant["rule_id"],
            "rule_name": variant["rule_name"],
            "rule_info": f"{variant['rule_name']} on fields {', '.join(variant['matched_parameters'])}",
            "action": action,
            "confidence": round(rng.uniform(0.62, 0.93), 2),
            "src_ip": _ip(rng, "10.24.8"),
            "dst_ip": _ip(rng, "10.30.2"),
            "xff": f"203.0.113.{rng.randrange(10, 240)}",
            "geo": rng.choice(["HK", "SG", "JP", "US"]),
            "method": method,
            "uri": variant["uri"],
            "query": rng.choice(["page=1&sort=created_at", "locale=en_HK", "batch=true"]),
            "status": status,
            "request_id": request_id,
            "session": f"redacted-session-{rng.randrange(1000, 9999)}",
            "user": rng.choice(["retail-user-8842", "retail-user-1290", "partner-batch-user", "anonymous"]),
            "app": app,
            "business_owner": rng.choice(["Digital Banking", "Corporate Banking", "Payments Platform"]),
            "asset_criticality": rng.choice(["tier-1", "tier-2", "internet-facing"]),
            "upstream": rng.choice(["pay-api-prod-03", "retail-web-prod-11", "partner-gw-prod-02"]),
            "matched_parameters": variant["matched_parameters"],
            "payload_category": variant["payload_category"],
            "memory_hint": variant.get("memory_hint", ""),
            "matched_field_samples": {
                "parameter": variant["matched_parameters"][0],
                "payload_marker": variant.get("attack_marker") or "known client formatting pattern",
                "raw_payload": "[WITHHELD]",
            },
            "rate_window": {
                "same_src_ip_5m": same_src_ip,
                "same_session_5m": max(1, same_src_ip // rng.randrange(2, 6)),
                "same_uri_5m": same_src_ip + rng.randrange(0, 15),
            },
            "correlation": {
                "rasp_trace_id": "" if scenario == "false_positive" else f"rasp-trace-{rng.randrange(1000, 9999)}",
                "same_user_failed_login_10m": 0 if scenario == "false_positive" else rng.randrange(1, 5),
                "recent_rule_ids": [variant["rule_id"]],
            },
            "headers": {
                "user-agent": user_agent,
                "authorization": f"Bearer demo-token-{rng.randrange(1000, 9999)}",
            },
            "evidence_assessment": assessment,
            "whitelist_candidate": whitelist,
        },
    }


def _hips(rng: random.Random, requested: str) -> dict[str, Any]:
    scenario = _scenario(rng, requested)
    fp = scenario == "false_positive"
    suspicious = scenario == "suspicious"
    host = rng.choice(["ops-jump-04", "ops-jump-07", "patch-srv-02"])
    parent_process = "software_center.exe" if fp else rng.choice(["wmiprvse.exe", "winword.exe", "psexesvc.exe"])
    user = "svc-patch" if fp else rng.choice(["adm.ops.l2", "svc-reporting", "adm.db"])
    rule_id = "HIPS-WIN-ADMIN-017" if fp else ("HIPS-WIN-PS-REVIEW-021" if suspicious else "HIPS-WIN-CRED-042")
    behavior = (
        ["approved patch inventory collection", "script hash matches change ticket", "signed script launched by software center"]
        if fp
        else (
            ["encoded script launched", "single suspicious registry query", "no credential store access observed"]
            if suspicious
            else ["credential store access attempt", "remote thread creation blocked", "attempted connection to core database segment"]
        )
    )
    change_ticket = f"CHG-{rng.randrange(30000, 99999)}" if fp else ""
    if fp:
        assessment = _assessment(
            "【误报】- 已批准补丁盘点脚本触发主机规则",
            [
                _dimension("主机与身份", f"{host} 位于运维区，账号 {user} 与补丁任务匹配，变更单 {change_ticket} 存在。", "benign"),
                _dimension("进程链", f"{parent_process} 拉起 powershell.exe，符合软件中心分发脚本链路。", "benign"),
                _dimension("命令行与脚本", "命令行仅保留摘要，脚本哈希与变更单匹配。", "benign"),
                _dimension("主机行为", "行为集中在补丁盘点和资产采集，没有凭证转储、持久化或横向移动证据。", "normal"),
                _dimension("规则与处置", f"{rule_id} 命中管理员脚本特征，属于运维场景误伤。", "benign"),
                _dimension("基线与变更", "处于批准维护窗口，签名状态为 signed_internal。", "benign"),
            ],
            "未发现攻击执行成功；该行为应归类为已批准运维脚本。",
            "确认误报后可减少补丁窗口内告警噪声，但需限定主机、账号、签名和变更窗口。",
        )
        whitelist = {
            "rule_type": "HIPS 白名单",
            "attack_type": "管理员脚本误报",
            "detection_content": f"host={host}; user={user}; parent_process={parent_process}; process=powershell.exe; signer=signed_internal",
            "match_method": "相等",
            "scope": f"rule_id={rule_id}; change_ticket={change_ticket}",
            "reason": "已批准补丁盘点脚本由软件中心分发，脚本哈希和签名稳定。",
            "review_cycle": "每个补丁月或脚本哈希变更时复核",
        }
    elif suspicious:
        assessment = _assessment(
            "【需人工复核】- 编码 PowerShell 行为缺少攻击闭环",
            [
                _dimension("主机与身份", f"{host} 上账号 {user} 发起脚本行为，但缺少变更单和完整登录来源确认。", "review"),
                _dimension("进程链", f"{parent_process} 拉起 powershell.exe，组合存在风险但未见明确 Office 宏或远程服务滥用闭环。", "review"),
                _dimension("命令行与脚本", "命令行存在编码脚本摘要，但原始脚本、签名和哈希信誉尚未确认。", "review"),
                _dimension("主机行为", "仅见注册表查询和脚本执行，没有凭证访问、注入、持久化或横向移动成功证据。", "review"),
                _dimension("规则与处置", f"{rule_id} 命中可疑脚本规则，当前为需人工复核级别。", "review"),
            ],
            "暂未确认攻击成功；需要脚本解码摘要、哈希信誉和登录来源确认。",
            "若为攻击，可能是侦察或后续执行前置；若为运维脚本，误阻断会影响补丁或巡检任务。",
            ["脚本哈希与签名", "完整父子进程树", "登录来源与变更单", "同主机后续行为"],
        )
        whitelist = {}
    else:
        assessment = _assessment(
            "【真实攻击】- 凭证访问与横向移动前置行为",
            [
                _dimension("主机与身份", f"{host} 为特权访问区资产，账号 {user} 来源不在变更窗口。", "risk"),
                _dimension("进程链", f"{parent_process} 拉起 powershell.exe，属于高风险父子进程组合。", "risk"),
                _dimension("命令行与脚本", "命令行包含编码脚本特征，原始内容已脱敏保留。", "risk"),
                _dimension("主机行为", "出现凭证存储访问、远程线程创建和核心数据库网段连接尝试。", "risk"),
                _dimension("规则与处置", f"{rule_id} 命中凭证访问链，HIPS 阻断进程树。", "blocked"),
                _dimension("基线与变更", "无变更窗口和变更单支持，签名状态为 unsigned。", "risk"),
            ],
            "HIPS 阻断了进程树；仍需确认阻断前是否已有凭证读取或远程连接成功。",
            "可能影响特权账号和核心数据库访问路径，应优先复核账号会话与同源主机行为。",
            ["进程树完整上下文", "脚本哈希信誉", "同账号登录日志", "目标主机安全日志"],
        )
        whitelist = {}
    return {
        "alert_id": _alert_id("hips", rng),
        "source": "direct",
        "product": "hips",
        "event_type": "approved_admin_script_flagged" if fp else ("powershell_behavior_needs_review" if suspicious else "suspicious_powershell_credential_access_chain"),
        "severity": "medium" if fp or suspicious else "high",
        "timestamp": _timestamp(rng),
        "payload": {
            "rule_id": rule_id,
            "rule_name": "Approved admin script pattern" if fp else ("PowerShell behavior needs analyst review" if suspicious else "PowerShell credential access behavior chain"),
            "host": host,
            "asset_criticality": rng.choice(["privileged-access-zone", "server-admin-zone"]),
            "user": user,
            "src_ip": _ip(rng, "10.12.9"),
            "process_name": "powershell.exe",
            "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "process_id": rng.randrange(2000, 9500),
            "parent_process": parent_process,
            "parent_process_id": rng.randrange(500, 1800),
            "command_line": "encoded command observed; raw command withheld",
            "file_hash_sha256": "8b7d5f-demo-approved" if fp else ("pending-reputation-demo" if suspicious else "1fb4d4f2d0b7e501f6c64f9fbd-demo"),
            "signature_status": "signed_internal" if fp else ("unknown" if suspicious else "unsigned"),
            "behavior": behavior,
            "hips_action": "logged_approved_admin_script" if fp else "blocked_process_tree",
            "change_window": fp,
            "change_ticket": change_ticket,
            "recent_context": {
                "same_user_logins_1h": rng.randrange(1, 4),
                "same_host_admin_sessions_1h": rng.randrange(1, 3),
                "change_window": fp,
                "known_good_hash": fp,
            },
            "evidence_assessment": assessment,
            "whitelist_candidate": whitelist,
        },
    }


def _rasp(rng: random.Random, requested: str) -> dict[str, Any]:
    scenario = _scenario(rng, requested)
    fp = scenario == "false_positive"
    suspicious = scenario == "suspicious"
    route = "/openbanking/v2/payments/search" if not fp else "/internal/canary/sql-guard-check"
    method = rng.choice(["POST", "GET"])
    trace_id = f"rasp-trace-{rng.randrange(1000, 9999)}"
    stack_trace = (
        ["CanarySqlGuardController.check", "SqlGuardHealthProbe.run", "JdbcTemplate.query"]
        if fp
        else ["PaymentSearchController.search", "BeneficiaryRepository.findByFilter", "JdbcTemplate.query"]
    )
    attack_data = [
        {
            "rule_info": "SQL 注入风险：用户可控参数进入动态 SQL 查询构造",
            "context": {
                "hook_data": {
                    "source": "synthetic_canary" if fp else "request_parameter:beneficiaryName",
                    "sink": "JdbcTemplate.query",
                    "payload_marker": (
                        "expected canary token"
                        if fp
                        else ("single SQL keyword marker; raw payload withheld" if suspicious else "SQL boolean expression markers; raw payload withheld")
                    ),
                    "sql": "withheld; normalized query shape only",
                },
                "stacktrace": stack_trace,
            },
        }
    ]
    if fp:
        assessment = _assessment(
            "【误报】- 合成 canary SQL 防护巡检触发预期异常",
            [
                _dimension("参数特征", "污染源为 synthetic_canary，payload_marker 为预期巡检 token。", "benign"),
                _dimension("危险调用", "调用栈经过 SqlGuardHealthProbe.run，属于内部健康检查路径。", "benign"),
                _dimension("规则匹配", "RASP-CANARY-SQL-010 命中预期 canary 规则，不代表外部用户攻击。", "benign"),
                _dimension("上下文", "rasp_action=logged_expected_canary，deployment_window=true。", "normal"),
            ],
            "未执行攻击 SQL；该异常由健康检查主动触发并被记录。",
            "确认误报后可降低 canary 巡检噪声，但必须限定内部路由和 synthetic-canary 用户。",
        )
        whitelist = {
            "rule_type": "RASP 白名单",
            "attack_type": "SQL 注入",
            "detection_content": "route=/internal/canary/sql-guard-check; user=synthetic-canary; stacktrace=SqlGuardHealthProbe.run",
            "match_method": "包含",
            "scope": "rule_id=RASP-CANARY-SQL-010; app=mobile-payment-api",
            "reason": "内部 canary 巡检用于验证 RASP SQL 防护是否生效。",
            "review_cycle": "巡检路由或 canary 用户变更时复核",
        }
    elif suspicious:
        assessment = _assessment(
            "【需人工复核】- SQL 注入疑似触达查询路径但证据不足",
            [
                _dimension("参数特征", "taint_source=request_parameter:beneficiaryName，仅见单一 SQL 关键字标记。", "review"),
                _dimension("危险调用", "调用栈经过 BeneficiaryRepository.findByFilter，但 hook_data 未确认动态拼接完整形态。", "review"),
                _dimension("规则匹配", "规则与 SQL 注入相关，但载荷证据弱于明确攻击样本。", "review"),
                _dimension("上下文", "RASP 动作为 logged_suspicious_query，未阻断，需结合数据库审计确认。", "review"),
            ],
            "暂未确认 SQL 执行是否包含攻击语义；需要数据库审计和应用日志确认。",
            "若为攻击可能影响客户支付搜索；若为业务关键字误伤，过度阻断会影响搜索功能。",
            ["数据库审计日志", "RASP hook_data 原始归一化摘要", "WAF request_id", "用户正常搜索基线"],
        )
        whitelist = {}
    else:
        assessment = _assessment(
            "【真实攻击】- SQL 注入触达动态查询 sink",
            [
                _dimension("参数特征", "taint_source=request_parameter:beneficiaryName，参数摘要包含 SQL boolean expression markers。", "risk"),
                _dimension("危险调用", "调用栈经过 BeneficiaryRepository.findByFilter -> JdbcTemplate.query。", "risk"),
                _dimension("规则匹配", "RASP-SQL-GUARD-221 与动态 SQL 查询构造风险一致。", "risk"),
                _dimension("上下文", "hook_data 显示用户可控输入触达 JdbcTemplate.query，RASP 动作为 blocked_query_execution。", "blocked"),
            ],
            "RASP 阻断查询执行；目前没有证据显示 SQL 已成功执行。",
            "若绕过可能影响客户支付搜索和收款人数据读取，应关联 WAF request_id 与应用审计日志确认影响面。",
            ["WAF request_id", "数据库审计日志", "应用访问日志", "同 trace 后续异常"],
        )
        whitelist = {}
    return {
        "alert_id": _alert_id("rasp", rng),
        "source": "direct",
        "product": "rasp",
        "event_type": "canary_sql_guard_expected_exception" if fp else ("runtime_sql_guard_needs_review" if suspicious else "runtime_sql_guard_and_sensitive_query_exception"),
        "severity": "low" if fp else ("medium" if suspicious else "high"),
        "timestamp": _timestamp(rng),
        "payload": {
            "rule_id": "RASP-CANARY-SQL-010" if fp else ("RASP-SQL-REVIEW-118" if suspicious else "RASP-SQL-GUARD-221"),
            "rule_name": "Expected canary SQL guard check" if fp else ("Runtime SQL guard needs review" if suspicious else "Runtime SQL injection guard"),
            "trace_id": trace_id,
            "app": "mobile-payment-api",
            "host": rng.choice(["pay-api-prod-03", "pay-api-prod-04"]),
            "method": method,
            "route": f"{method} {route}",
            "user": "synthetic-canary" if fp else rng.choice(["retail-user-8842", "retail-user-1290"]),
            "src_ip": _ip(rng, "10.24.8"),
            "release_version": rng.choice(["2026.06.21-r3", "2026.06.24-r1"]),
            "deployment_window": fp,
            "attack_data": attack_data,
            "stack_trace": stack_trace,
            "taint_source": "synthetic_canary" if fp else "request_parameter:beneficiaryName",
            "sink": "sql_query_builder",
            "hook_data": attack_data[0]["context"]["hook_data"],
            "rasp_action": "logged_expected_canary" if fp else ("logged_suspicious_query" if suspicious else "blocked_query_execution"),
            "exception": (
                "Expected canary validation path"
                if fp
                else (
                    "RASP observed tainted query path but did not confirm exploit semantics"
                    if suspicious
                    else "RASP prevented dynamic SQL query assembled from tainted request parameter; raw query withheld"
                )
            ),
            "business_context": {
                "api_sensitivity": "canary-health-check" if fp else "customer-payment-search",
                "customer_data_access": "none_expected" if fp else "possible_if_query_executed",
                "same_trace_waf_request_id": "" if fp else f"req-{rng.randrange(10**7, 10**8):x}",
            },
            "evidence_assessment": assessment,
            "whitelist_candidate": whitelist,
        },
    }


def _ndr(rng: random.Random, requested: str) -> dict[str, Any]:
    scenario = _scenario(rng, requested)
    fp = scenario == "false_positive"
    suspicious = scenario == "suspicious"
    rule_id = "NDR-BACKUP-BASELINE-004" if fp else ("NDR-TLS-REVIEW-014" if suspicious else rng.choice(["NDR-TLS-BEACON-018", "NDR-EXFIL-RATIO-031"]))
    host = rng.choice(["pay-api-prod-03", "core-db-17", "reporting-srv-09"])
    dst_ip = "10.80.4.20" if fp else f"198.51.100.{rng.randrange(10, 240)}"
    sni = "backup-vault.internal" if fp else rng.choice(["cdn-update-check.example", "storage-sync.example", "telemetry-edge.example"])
    bytes_out = rng.randrange(2_000_000, 50_000_000)
    bytes_in = rng.randrange(10_000, 600_000) if not fp else rng.randrange(1_000_000, 12_000_000)
    sessions = rng.randrange(5, 120)
    interval = rng.choice([30, 60, 120, 300])
    if fp:
        assessment = _assessment(
            "【误报】- 已知备份复制窗口流量突增",
            [
                _dimension("通信主体", f"{host} 到 backup-vault.internal:443，目的地址 {dst_ip} 为内部备份库。", "benign"),
                _dimension("时序与流量", f"session_count_30m={sessions}，流量发生在备份窗口，出入流量比例符合复制任务。", "benign"),
                _dimension("协议与指纹", "TLS/SNI 与备份服务基线一致，没有罕见 JA3 或伪装端口证据。", "normal"),
                _dimension("目的地信誉", "目的地为 approved backup target，非新出现公网低信誉地址。", "benign"),
                _dimension("关联证据", "无 HIPS/RASP/WAF 异常链路支持攻击假设。", "normal"),
                _dimension("数据风险", "存在大流量但方向和窗口符合备份策略。", "benign"),
            ],
            "连接成功但属于预期备份复制；未见异常外传迹象。",
            "调优后可降低备份窗口噪声，但需限定源资产、SNI、目的 IP 和时间窗口。",
        )
        whitelist = {
            "rule_type": "NDR 白名单",
            "attack_type": "数据外传/高流量异常",
            "detection_content": f"src_host={host}; dst_ip={dst_ip}; sni={sni}; protocol=TLS; port=443",
            "match_method": "相等",
            "scope": "backup_window=02:00-04:00; rule_id=NDR-BACKUP-BASELINE-004",
            "reason": "已批准备份复制任务，目的地和 SNI 均为内部备份库。",
            "review_cycle": "备份策略或目的地址变更时复核",
        }
    elif suspicious:
        event_type = "rare_outbound_tls_needs_review"
        assessment = _assessment(
            "【需人工复核】- 罕见出站 TLS 连接缺少主机侧确认",
            [
                _dimension("通信主体", f"{host} 访问低普及目的地 {dst_ip}:443 / {sni}，但会话数量尚未达到明确 beacon 阈值。", "review"),
                _dimension("时序与流量", f"session_count_30m={sessions}，beacon_interval_seconds={interval}，存在一定周期性但样本窗口较短。", "review"),
                _dimension("协议与指纹", "TLS 指纹罕见，载荷加密不可见，需要代理或主机进程补充。", "review"),
                _dimension("目的地信誉", "目的地为新观察低普及目标，但缺少威胁情报命中。", "review"),
                _dimension("关联证据", "当前缺少 HIPS/RASP/WAF 直接关联事件。", "review"),
            ],
            "连接已建立，但无法确认 C2 或数据外传成功。",
            "若为攻击可能代表入侵后外联；若为新业务依赖，需要登记资产基线避免重复误报。",
            ["源主机进程连接日志", "代理域名分类", "目的域名威胁情报", "业务 Owner 确认"],
        )
        whitelist = {}
    else:
        event_type = "possible_data_exfiltration" if rule_id == "NDR-EXFIL-RATIO-031" else "rare_outbound_tls_beacon_from_server_segment"
        assessment = _assessment(
            "【真实攻击】- C2 beacon 或疑似数据外传",
            [
                _dimension("通信主体", f"{host} 从生产网段访问新观察目的地 {dst_ip}:443 / {sni}。", "risk"),
                _dimension("时序与流量", f"session_count_30m={sessions}，beacon_interval_seconds={interval}，呈固定间隔连接。", "risk"),
                _dimension("协议与指纹", "TLS 元数据存在低普及目的地和少见指纹组合，载荷加密不可见。", "risk"),
                _dimension("目的地信誉", "baseline 标记 first_seen_dst=true，reputation 为 newly observed low-prevalence destination。", "risk"),
                _dimension("关联证据", "related_events 可关联 WAF/RASP 异常，支持入侵后外联假设。", "risk"),
                _dimension("数据风险", f"bytes_out={bytes_out} 明显高于 bytes_in={bytes_in}，存在低慢外传或分阶段传输风险。", "risk"),
            ],
            "NDR 观察到连接成功；由于载荷加密，无法仅凭网络侧确认数据内容是否外传。",
            "可能影响生产服务器及其可访问数据，应关联主机进程、代理日志和应用层事件确认源进程。",
            ["源主机进程连接日志", "代理/防火墙完整会话", "目的域名信誉情报", "同资产 HIPS 事件"],
        )
        whitelist = {}
    if fp:
        event_type = "known_backup_replication_spike"
    return {
        "alert_id": _alert_id("ndr", rng),
        "source": "direct",
        "product": "ndr",
        "event_type": event_type,
        "severity": "low" if fp else ("medium" if suspicious else rng.choice(["medium", "high"])),
        "timestamp": _timestamp(rng),
        "payload": {
            "rule_id": rule_id,
            "rule_name": "Approved backup replication baseline" if fp else ("Rare outbound TLS needs review" if suspicious else "Rare outbound TLS beacon or exfiltration pattern"),
            "src_ip": _ip(rng, "10.30.2"),
            "host": host,
            "src_host": host,
            "dst_ip": dst_ip,
            "dst_port": 443,
            "protocol": "tls",
            "sni": sni,
            "ja3": "771,4865-4866-4867,0-11-10,23-24,0",
            "bytes_out": bytes_out,
            "bytes_in": bytes_in,
            "session_count_30m": sessions,
            "beacon_interval_seconds": interval,
            "network_segment": "payment-api-prod" if "pay" in host else "server-prod",
            "baseline": {
                "first_seen_dst": not fp,
                "usual_outbound_from_segment": fp,
                "same_ja3_seen_assets_24h": (rng.randrange(3, 8) if suspicious else rng.randrange(1, 3)) if not fp else rng.randrange(10, 40),
                "domain_age_days": (rng.randrange(15, 60) if suspicious else rng.randrange(1, 6)) if not fp else 900,
                "reputation": "approved backup target" if fp else ("unknown low-prevalence destination" if suspicious else "newly observed low-prevalence destination"),
                "proxy_category": "business-backup" if fp else ("uncategorized-but-not-malicious" if suspicious else "uncategorized"),
            },
            "related_events": (
                []
                if fp or suspicious
                else [
                    "WAF request blocked before first outbound beacon",
                    "RASP trace recorded abnormal SQL exception",
                ]
            ),
            "evidence_assessment": assessment,
            "whitelist_candidate": whitelist,
        },
    }


def _siem(rng: random.Random, requested: str) -> dict[str, Any]:
    scenario = _scenario(rng, requested)
    fp = scenario == "false_positive"
    suspicious = scenario == "suspicious"
    host = rng.choice(["core-db-17", "core-db-22", "ledger-rpt-04"])
    user = "svc-maintenance" if fp else rng.choice(["svc-reporting", "adm.db", "adm.ops.l2"])
    rule_id = "SIEM-MAINT-FP-003" if fp else ("SIEM-CORR-REVIEW-006" if suspicious else "SIEM-CORR-LATERAL-PRIV-009")
    if fp:
        signals = [
            {"product": "change", "event": "approved maintenance window", "details": "Change ticket and owner approval present"},
            {"product": "iam", "event": "service_account_maintenance_login", "details": "Login source matches approved jump host"},
            {"product": "hips", "event": "admin_script_logged_only", "details": "Signed maintenance script, no block action"},
        ]
        timeline = [
            "10:00:00 approved change window opened",
            "10:05:18 svc-maintenance login from approved jump host",
            "10:07:31 signed maintenance script collected inventory",
            "10:09:44 SIEM correlation threshold matched maintenance-like behavior",
        ]
        assessment = _assessment(
            "【误报】- 已批准维护窗口触发关联规则",
            [
                _dimension("时间线", "事件全部落在已批准维护窗口内，顺序符合变更执行流程。", "benign"),
                _dimension("实体关系", f"用户 {user}、主机 {host}、来源跳板机与变更单绑定。", "benign"),
                _dimension("攻击链假设", "信号可映射到执行和管理访问，但缺少凭证访问、横向移动或外传证据。", "normal"),
                _dimension("多源一致性", "change/IAM/HIPS 信号相互支持合法维护假设。", "benign"),
                _dimension("影响面", "行为限于维护目标，没有新增高价值主机或异常数据访问。", "normal"),
                _dimension("证据缺口", "需要保留变更单、审批人和维护脚本哈希用于审计。", "review"),
            ],
            "未发现攻击成功；关联规则把维护行为误判为攻击链。",
            "降低重复误报可提升 SOC 效率，但必须设置到期复核和偏离基线升级条件。",
        )
        whitelist = {
            "rule_type": "SIEM 关联规则调优",
            "attack_type": "横向移动/执行关联误报",
            "detection_content": f"rule_id={rule_id}; user={user}; host={host}; change_window=true; script_signer=signed_internal",
            "match_method": "相等",
            "scope": "仅限已批准变更单和维护窗口",
            "reason": "维护窗口内的签名脚本和服务账号登录符合变更流程。",
            "review_cycle": "变更结束后自动过期，最长 7 天",
        }
    elif suspicious:
        signals = [
            {"product": "iam", "event": "service_account_login_from_new_workstation", "details": "New workstation but from managed subnet"},
            {"product": "ndr", "event": "rare_smb_access_to_server_segment", "details": "Single ADMIN$ access outside normal hour"},
            {"product": "hips", "event": "powershell_inventory_command", "process_name": "powershell.exe", "details": "No credential access behavior observed"},
        ]
        timeline = [
            "10:41:12 service account login from new managed workstation",
            "10:44:03 single SMB admin share access",
            "10:45:10 PowerShell inventory command observed",
            "10:49:28 no follow-up credential dump or data access alert",
        ]
        assessment = _assessment(
            "【需人工复核】- 服务账号异常登录与弱横向移动信号",
            [
                _dimension("时间线", "服务账号新工作站登录后出现单次 SMB 管理共享访问，但未见连续横向移动。", "review"),
                _dimension("实体关系", f"用户 {user} 访问 {host}，来源为受管网段但不在近期基线内。", "review"),
                _dimension("攻击链假设", "可疑点覆盖登录与访问阶段，但缺少凭证访问、执行成功或外传证据。", "review"),
                _dimension("多源一致性", "IAM/NDR/HIPS 信号弱相关，尚不足以形成闭环攻击链。", "review"),
                _dimension("影响面", "目标为高价值资产，需要确认是否有真实数据访问。", "review"),
                _dimension("证据缺口", "缺少数据库审计、目标主机日志和变更单信息。", "review"),
            ],
            "尚未确认攻击成功；需要补齐目标主机和数据库审计后判断。",
            "可能是服务账号滥用早期迹象，也可能是未登记维护任务。",
            ["数据库审计日志", "目标主机安全日志", "变更单或工单", "服务账号使用人确认"],
        )
        whitelist = {}
    else:
        signals = [
            {"product": "ndr", "event": "rare_smb_admin_share_access", "details": "ADMIN$ and C$ shares outside baseline"},
            {"product": "hips", "event": "encoded_powershell_spawned_by_wmi_provider", "process_name": "powershell.exe"},
            {"product": "iam", "event": "service_account_login_from_new_workstation", "mfa_status": "not_applicable_service_account"},
        ]
        timeline = [
            "10:57:44 service account interactive login from new workstation",
            "10:58:31 rare SMB admin share access",
            "10:59:08 encoded PowerShell child process",
            "11:02:36 HIPS blocked credential-dump behavior",
        ]
        assessment = _assessment(
            "【真实事件】- 服务账号滥用与横向移动攻击链",
            [
                _dimension("时间线", "服务账号异常登录后出现 SMB 管理共享访问，再出现 WMI 拉起编码 PowerShell。", "risk"),
                _dimension("实体关系", f"用户 {user} 连接 {host} 等高价值资产，来源工作站不在历史基线内。", "risk"),
                _dimension("攻击链假设", "可映射到 credential_access、lateral_movement、execution 阶段。", "risk"),
                _dimension("多源一致性", "NDR/HIPS/IAM 三类信号互相支持同一服务账号滥用假设。", "risk"),
                _dimension("影响面", "目标为 crown-jewel 资产，可能影响核心账务或清算业务。", "risk"),
                _dimension("证据缺口", "持久化、数据访问和最终外传尚未确认。", "review"),
                _dimension("响应优先级", "P1 Case，应优先做只读会话复核并按审批流程升级响应。", "risk"),
            ],
            "HIPS 阻断一条凭证转储行为，但登录和横向访问已经发生；攻击链部分成功。",
            "可能影响核心数据库主机、服务账号权限和关键业务数据访问，需要优先确认数据访问范围。",
            ["服务账号完整登录历史", "目标主机安全日志", "数据库审计日志", "网络文件共享访问明细"],
        )
        whitelist = {}
    return {
        "alert_id": _alert_id("siem", rng),
        "source": "siem",
        "product": "siem",
        "event_type": "approved_maintenance_correlation" if fp else ("multi_product_service_account_needs_review" if suspicious else "multi_product_lateral_movement_and_privilege_case"),
        "severity": "medium" if fp or suspicious else "critical",
        "timestamp": _timestamp(rng),
        "payload": {
            "rule_id": rule_id,
            "rule_name": "Approved maintenance behavior matched correlation rule" if fp else ("Service account weak correlation needs review" if suspicious else "High value asset lateral movement with suspicious admin share and PowerShell chain"),
            "case_priority": "P3" if fp else ("P2" if suspicious else "P1"),
            "host": host,
            "asset_criticality": "crown-jewel",
            "src_ip": _ip(rng, "10.12.9"),
            "dst_ip": _ip(rng, "10.14.2"),
            "user": user,
            "user_risk": "approved-maintenance-service-account" if fp else ("new-workstation-managed-subnet" if suspicious else "service-account-interactive-login"),
            "business_service": rng.choice(["Core Ledger Reporting", "Payments Clearing", "Digital Banking"]),
            "mitre_tactic": ["maintenance"] if fp else (["initial_access", "lateral_movement"] if suspicious else ["credential_access", "lateral_movement", "execution"]),
            "signals": signals,
            "timeline": timeline,
            "correlation_logic": {
                "window_minutes": 15,
                "entity_join": ["user", "src_ip", "host"],
                "threshold": "maintenance pattern matched generic threshold" if fp else ("weak correlation threshold, analyst review required" if suspicious else "3 distinct security domains"),
            },
            "case_summary": (
                "Known approved maintenance matched correlation rule."
                if fp
                else (
                    "Multiple weak signals suggest possible service account misuse but key confirmation is missing."
                    if suspicious
                    else "Multiple controls suggest possible service account abuse and lateral movement."
                )
            ),
            "evidence_assessment": assessment,
            "whitelist_candidate": whitelist,
        },
    }


def _rasp_realistic(rng: random.Random, requested: str) -> dict[str, Any]:
    scenario = _scenario(rng, requested)
    fp = scenario == "false_positive"
    suspicious = scenario == "suspicious"
    variants = [
        {
            "kind": "deserialization_jndi",
            "label": "反序列化/JNDI",
            "event_type": "runtime_deserialization_jndi_guard",
            "rule_id": "cloudrasp_jndi_108",
            "review_rule_id": "cloudrasp_jndi_review_108",
            "fp_rule_id": "RASP-CANARY-JNDI-010",
            "rule_name": "请求触发 JNDI 连接判断",
            "review_rule_name": "JNDI 连接行为需人工复核",
            "fp_rule_name": "Expected canary JNDI guard check",
            "attack_type": "jndi",
            "method": "POST",
            "path": "/cloudrasp-vulns/deserialization/fastjson/postBody",
            "fp_path": "/internal/canary/deserialization-jndi-check",
            "content_type": "application/x-www-form-urlencoded; charset=UTF-8",
            "parameter_key": "payload",
            "payload_marker": "Fastjson autoType and JNDI lookup markers observed; raw object withheld",
            "suspicious_marker": "deserialization type marker observed without confirmed remote lookup; raw object withheld",
            "fp_marker": "expected canary deserialization marker",
            "source": "request_body:payload",
            "fp_source": "synthetic_canary",
            "sink": "javax.naming.InitialContext.lookup",
            "hook_data": {"url": "ldap://127.0.0.1:1389/obj"},
            "fp_hook_data": {"url": "ldap://127.0.0.1:1389/canary"},
            "stack_trace": [
                "com.sun.jndi.toolkit.url.GenericURLContext.lookup(GenericURLContext.java)",
                "javax.naming.InitialContext.lookup(InitialContext.java:417)",
                "com.sun.rowset.JdbcRowSetImpl.connect(JdbcRowSetImpl.java:624)",
                "com.alibaba.fastjson.parser.deserializer.FieldDeserializer.setValue(FieldDeserializer.java:110)",
                "com.alibaba.fastjson.JSON.parseObject(JSON.java:365)",
                "cn.rasp.vuln.deserialization.Deserialization.fastJson(Deserialization.java:45)",
                "cn.rasp.vuln.controller.FastJsonController.execute(DeserializationController.java:28)",
            ],
            "fp_stack_trace": [
                "CanaryDeserializationController.check(CanaryDeserializationController.java:31)",
                "DeserializationGuardHealthProbe.run(DeserializationGuardHealthProbe.java:44)",
                "javax.naming.InitialContext.lookup(InitialContext.java:417)",
            ],
            "blocked_action": "blocked_jndi_lookup",
            "logged_action": "logged_jndi_lookup_review",
            "success": "RASP 识别到反序列化触发的 JNDI lookup；当前样本未提供远程类加载成功证据。",
            "impact": "若未被限制，可能导致应用出站连接、远程对象加载或后续代码执行风险。",
            "missing": ["出站网络连接日志", "应用异常日志", "WAF request_id", "同源请求序列"],
        },
        {
            "kind": "sql_injection",
            "label": "SQL 注入",
            "event_type": "runtime_sql_guard",
            "rule_id": "cloudrasp_sql_201",
            "review_rule_id": "RASP-SQL-REVIEW-118",
            "fp_rule_id": "RASP-CANARY-SQL-010",
            "rule_name": "SQL 注入执行前检测",
            "review_rule_name": "SQL 注入疑似触达查询路径",
            "fp_rule_name": "Expected canary SQL guard check",
            "attack_type": "sql_injection",
            "method": rng.choice(["POST", "GET"]),
            "path": "/openbanking/v2/payments/search",
            "fp_path": "/internal/canary/sql-guard-check",
            "content_type": "application/json;charset=UTF-8",
            "parameter_key": "beneficiaryName",
            "payload_marker": "SQL boolean expression and union keyword markers observed; raw payload withheld",
            "suspicious_marker": "single SQL keyword marker observed in free-text field; raw payload withheld",
            "fp_marker": "expected canary SQL token",
            "source": "request_parameter:beneficiaryName",
            "fp_source": "synthetic_canary",
            "sink": "org.springframework.jdbc.core.JdbcTemplate.query",
            "hook_data": {
                "sql": "withheld; normalized query shape only",
                "parameter": "beneficiaryName",
                "sink": "JdbcTemplate.query",
            },
            "fp_hook_data": {
                "sql": "withheld; canary query shape only",
                "parameter": "syntheticCanary",
                "sink": "JdbcTemplate.query",
            },
            "stack_trace": [
                "com.mysql.cj.jdbc.StatementImpl.executeQuery(StatementImpl.java:1235)",
                "org.springframework.jdbc.core.JdbcTemplate.query(JdbcTemplate.java:723)",
                "com.bank.payment.repository.BeneficiaryRepository.findByFilter(BeneficiaryRepository.java:88)",
                "com.bank.payment.controller.PaymentSearchController.search(PaymentSearchController.java:51)",
            ],
            "fp_stack_trace": [
                "CanarySqlGuardController.check(CanarySqlGuardController.java:27)",
                "SqlGuardHealthProbe.run(SqlGuardHealthProbe.java:39)",
                "org.springframework.jdbc.core.JdbcTemplate.query(JdbcTemplate.java:723)",
            ],
            "blocked_action": "blocked_query_execution",
            "logged_action": "logged_suspicious_query",
            "success": "RASP 在 SQL 执行前识别到用户可控输入触达查询 sink；当前样本未显示 SQL 已成功执行。",
            "impact": "若绕过可能影响客户支付搜索和收款人数据读取。",
            "missing": ["数据库审计日志", "WAF request_id", "应用访问日志", "同 trace 后续异常"],
        },
        {
            "kind": "command_execution",
            "label": "命令执行",
            "event_type": "runtime_command_execution_guard",
            "rule_id": "cloudrasp_cmd_301",
            "review_rule_id": "RASP-CMD-REVIEW-118",
            "fp_rule_id": "RASP-CANARY-CMD-010",
            "rule_name": "危险命令执行行为判断",
            "review_rule_name": "命令执行疑似行为需人工复核",
            "fp_rule_name": "Expected canary process guard check",
            "attack_type": "command_execution",
            "method": "POST",
            "path": "/ops/tools/ping",
            "fp_path": "/internal/canary/process-guard-check",
            "content_type": "application/json;charset=UTF-8",
            "parameter_key": "target",
            "payload_marker": "shell metacharacter and process spawn markers observed; raw command withheld",
            "suspicious_marker": "network diagnostic argument includes shell-like delimiter marker; raw command withheld",
            "fp_marker": "expected canary process token",
            "source": "request_parameter:target",
            "fp_source": "release_smoke_test",
            "sink": "java.lang.ProcessBuilder.start",
            "hook_data": {
                "command_line": "withheld; shell metacharacter marker observed",
                "class": "java.lang.ProcessBuilder",
                "working_directory": "/app",
            },
            "fp_hook_data": {
                "command_line": "withheld; approved health-check command shape",
                "class": "java.lang.ProcessBuilder",
                "working_directory": "/app",
            },
            "stack_trace": [
                "java.lang.ProcessBuilder.start(ProcessBuilder.java:1048)",
                "java.lang.Runtime.exec(Runtime.java:620)",
                "com.bank.ops.service.NetworkToolService.ping(NetworkToolService.java:64)",
                "com.bank.ops.controller.NetworkToolController.execute(NetworkToolController.java:42)",
            ],
            "fp_stack_trace": [
                "CanaryProcessGuardController.check(CanaryProcessGuardController.java:29)",
                "ProcessGuardHealthProbe.run(ProcessGuardHealthProbe.java:45)",
                "java.lang.ProcessBuilder.start(ProcessBuilder.java:1048)",
            ],
            "blocked_action": "blocked_process_execution",
            "logged_action": "logged_process_execution_review",
            "success": "RASP 在进程启动前识别到用户可控输入触达命令执行 sink；当前样本未显示命令已执行成功。",
            "impact": "若绕过可能导致应用容器内命令执行、横向移动或敏感文件访问风险。",
            "missing": ["主机进程审计", "容器运行时日志", "应用访问日志", "同源 IP 后续行为"],
        },
    ]
    variant = _choice(rng, variants)
    trace_id = f"rasp-trace-{rng.randrange(1000, 9999)}"
    request_id = f"{rng.getrandbits(128):032x}"
    attack_time = _timestamp(rng)
    created_at = (datetime.fromisoformat(attack_time) + timedelta(minutes=rng.randrange(1, 8), seconds=rng.randrange(0, 59))).isoformat()
    app = "mobile-payment-api" if variant["kind"] == "sql_injection" else rng.choice(["cloudrasp-vulns", "ops-admin-api", "retail-web"])
    path = variant["fp_path"] if fp else variant["path"]
    method = variant["method"]
    host_ip = f"192.168.15.{rng.randrange(20, 240)}"
    port = 8080 if app == "cloudrasp-vulns" else 8443
    url = f"http://{host_ip}:{port}{path}"
    source = variant["fp_source"] if fp else variant["source"]
    marker = variant["fp_marker"] if fp else (variant["suspicious_marker"] if suspicious else variant["payload_marker"])
    hook_data = dict(variant["fp_hook_data"] if fp else variant["hook_data"])
    stack_trace = list(variant["fp_stack_trace"] if fp else variant["stack_trace"])
    rule_id = variant["fp_rule_id"] if fp else (variant["review_rule_id"] if suspicious else variant["rule_id"])
    rule_name = variant["fp_rule_name"] if fp else (variant["review_rule_name"] if suspicious else variant["rule_name"])
    intercept_state = "log" if fp or suspicious else "block"
    attack_level = 4 if fp else (2 if suspicious else 1)
    response_status = 200 if fp or suspicious else rng.choice([200, 403, 500])
    response_body = (
        "expected canary guard check logged"
        if fp
        else ("request logged for analyst review" if suspicious else f"{variant['label']} guard blocked by RASP")
    )
    item = {
        "sequence": 1,
        "trigger_time": attack_time,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "attack_type": variant["attack_type"],
        "attack_level": attack_level,
        "intercept_state": intercept_state,
        "hook_data": hook_data,
        "stacktrace": stack_trace,
        "advices": [
            f"确认{variant['label']}告警是否来自外部用户输入触达 {variant['sink']}。",
            "保留 RASP、应用、WAF 和主机审计日志用于同 trace 关联分析。",
        ],
    }
    event = {
        "request_id": request_id,
        "attack_time": attack_time,
        "created_at": created_at,
        "app_name": app,
        "application_id": rng.randrange(100, 999),
        "agent_id": f"{rng.getrandbits(128):032x}",
        "path": path,
        "attack_source": _ip(rng, "10.0.10"),
        "server_nic": [
            {"ip": host_ip, "name": ""},
            {"ip": "172.24.0.1", "name": ""},
            {"ip": "172.17.0.1", "name": ""},
        ],
        "server_hostname": rng.choice(["localhost.localdomain", "pay-api-prod-03", "ops-api-prod-02"]),
        "server_type": "Tomcat",
        "server_version": rng.choice(["8.5.77", "9.0.82"]),
        "web_path": f"/mnt/apache-tomcat/webapps/{app}/",
        "server_domain": "",
        "request_message": {
            "protocol": "HTTP/1.1",
            "method": method,
            "url": url,
            "parameter": f"{variant['parameter_key']}={marker}",
            "body": None,
            "header": {
                "connection": "keep-alive",
                "content-type": variant["content_type"],
                "host": f"{host_ip}:{port}",
                "user-agent": rng.choice(["Apache-HttpClient/4.5.7 (Java/1.8.0_321)", "Mozilla/5.0", "bank-mobile-app/2026.06"]),
            },
        },
        "response_message": {
            "status_code": response_status,
            "header": {"content-type": "application/json;charset=UTF-8", "connection": "keep-alive"},
            "body": response_body,
        },
    }
    raw_rasp_log = {"data_type": "attack_event", "event": event, "items": [item]}
    if fp:
        assessment = _assessment(
            f"【误报】- 合成 canary {variant['label']} 防护巡检触发预期异常",
            [
                _dimension("参数特征", f"污染源为 {source}，payload_marker 为预期巡检 token。", "benign"),
                _dimension("危险调用", f"调用栈经过 {stack_trace[0]}，属于内部健康检查路径。", "benign"),
                _dimension("规则匹配", f"{rule_id} 命中预期 canary 规则，不代表外部用户攻击。", "benign"),
                _dimension("上下文", "rasp_action=logged_expected_canary，deployment_window=true。", "normal"),
            ],
            "未执行真实攻击动作；该异常由健康检查主动触发并被记录。",
            "确认误报后可降低 canary 巡检噪声，但必须限定内部路由、来源和固定调用栈。",
        )
        whitelist = {
            "rule_type": "RASP 白名单",
            "attack_type": variant["label"],
            "detection_content": f"route={path}; source={source}; stacktrace={stack_trace[0]}",
            "match_method": "包含",
            "scope": f"rule_id={rule_id}; app={app}",
            "reason": f"内部 canary 巡检用于验证 RASP {variant['label']} 防护是否生效。",
            "review_cycle": "巡检路由或 canary 用户变更时复核",
        }
    elif suspicious:
        assessment = _assessment(
            f"【需人工复核】- {variant['label']} 疑似触达危险 sink 但证据不足",
            [
                _dimension("参数特征", f"taint_source={source}，{marker}。", "review"),
                _dimension("危险调用", f"调用栈出现 {variant['sink']}，但 hook_data 未确认完整攻击语义。", "review"),
                _dimension("规则匹配", f"{rule_id} 与{variant['label']}相关，但证据弱于明确攻击样本。", "review"),
                _dimension("上下文", f"RASP 动作为 {variant['logged_action']}，未阻断，需结合审计日志确认。", "review"),
            ],
            variant["success"],
            f"真实攻击影响：{variant['impact']}；若为业务误伤，直接阻断会影响正常功能。",
            variant["missing"],
        )
        whitelist = {}
    else:
        assessment = _assessment(
            f"【真实攻击】- {variant['label']} 触达危险 sink",
            [
                _dimension("参数特征", f"taint_source={source}，参数摘要包含 {marker}。", "risk"),
                _dimension("危险调用", f"调用栈出现 {variant['sink']}，用户输入触达运行时危险点。", "risk"),
                _dimension("规则匹配", f"{rule_id} / {rule_name} 与 {variant['label']} 特征一致。", "risk"),
                _dimension("上下文", f"hook_data 显示用户可控输入触达 {variant['sink']}，RASP 动作为 {variant['blocked_action']}。", "blocked"),
            ],
            variant["success"],
            f"{variant['impact']} 应关联 WAF request_id、应用日志和运行时审计确认影响面。",
            variant["missing"],
        )
        whitelist = {}
    return {
        "alert_id": _alert_id("rasp", rng),
        "source": "direct",
        "product": "rasp",
        "event_type": (
            f"canary_{variant['kind']}_expected_exception"
            if fp
            else (f"{variant['event_type']}_needs_review" if suspicious else f"{variant['event_type']}_exception")
        ),
        "severity": "low" if fp else ("medium" if suspicious else "high"),
        "timestamp": attack_time,
        "payload": {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "trace_id": trace_id,
            "app": app,
            "host": event["server_hostname"],
            "method": method,
            "route": f"{method} {path}",
            "user": "synthetic-canary" if fp else rng.choice(["retail-user-8842", "ops-user-1290", "anonymous"]),
            "src_ip": event["attack_source"],
            "release_version": rng.choice(["2026.06.21-r3", "2026.06.24-r1"]),
            "deployment_window": fp,
            "attack_data": [
                {
                    "rule_info": f"{variant['label']}风险：用户可控输入触达 {variant['sink']}",
                    "context": {"hook_data": hook_data, "stacktrace": stack_trace},
                }
            ],
            "stack_trace": stack_trace,
            "taint_source": source,
            "sink": variant["sink"],
            "hook_data": hook_data,
            "rasp_action": "logged_expected_canary" if fp else (variant["logged_action"] if suspicious else variant["blocked_action"]),
            "exception": response_body,
            "business_context": {
                "api_sensitivity": "canary-health-check" if fp else variant["label"],
                "customer_data_access": "none_expected" if fp else "possible_if_sink_executed",
                "same_trace_waf_request_id": "" if fp else f"req-{rng.randrange(10**7, 10**8):x}",
            },
            "raw_rasp_log": raw_rasp_log,
            "event": event,
            "items": [item],
            "evidence_assessment": assessment,
            "whitelist_candidate": whitelist,
        },
    }


_BUILDERS = {
    "waf": _waf,
    "hips": _hips,
    "rasp": _rasp_realistic,
    "ndr": _ndr,
    "siem": _siem,
}
