from __future__ import annotations

import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .config import LLMConfig
from .agents.evidence_helpers import (
    fact,
    hook_data_fact,
    join_facts,
    normalize_classification,
    request_context_fact,
    request_parameters_fact,
    short_text,
)
from .json_safety import loads_bounded_json
from .network_safety import EndpointPin, pinned_endpoint_handlers, resolve_http_endpoint_pin


MAX_LLM_RESPONSE_BYTES = 2_000_000
MAX_LLM_ERROR_BYTES = 4096
MAX_LLM_ATTEMPTS = 2
_RETRYABLE_HTTP_CODES = {429, 502, 503, 504}
ANTHROPIC_VERSION = "2023-06-01"
ANTHROPIC_MAX_TOKENS = 4096
GATEWAY_USER_AGENT = "defensive-ai-gateway/1.0"
_WEBSOCKET_ENDPOINT_PATH_SEGMENTS = frozenset({"realtime", "socket.io", "websocket", "ws"})
WEBSOCKET_ENDPOINT_GUIDANCE = (
    "LLM gateway endpoint requires a WebSocket/Realtime protocol, but this service only supports "
    "HTTP JSON APIs. Configure an HTTP endpoint such as /v1/responses or /v1/chat/completions."
)


class LLMEndpointConfigurationError(RuntimeError):
    """A remote-model endpoint cannot be used by the HTTP request client."""


def is_websocket_endpoint(endpoint: str) -> bool:
    """Identify conventional WebSocket-only endpoint URLs before sending a prompt."""
    parsed = urllib.parse.urlsplit(str(endpoint or ""))
    if parsed.scheme.lower() in {"ws", "wss"}:
        return True
    path_segments = {
        urllib.parse.unquote(segment).strip().lower()
        for segment in parsed.path.split("/")
        if segment.strip()
    }
    return bool(path_segments & _WEBSOCKET_ENDPOINT_PATH_SEGMENTS)


def validate_gateway_http_endpoint(endpoint: str) -> None:
    if is_websocket_endpoint(endpoint):
        raise ValueError(WEBSOCKET_ENDPOINT_GUIDANCE)


def is_websocket_upgrade_required(status: int, body: str) -> bool:
    return int(status) == 426 and "websocket" in str(body or "").lower()


def _bounded_timeout(value: Any) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        timeout = 30.0
    return max(1.0, min(timeout, 120.0))


def _validate_http_endpoint(
    endpoint: str,
    *,
    backend: str,
    loopback_only: bool = False,
    allowed_hosts: list[str] | None = None,
) -> EndpointPin:
    """Validate an endpoint and retain the exact safe addresses for the request."""
    if backend == "LLM gateway":
        try:
            validate_gateway_http_endpoint(endpoint)
        except ValueError as exc:
            raise LLMEndpointConfigurationError(str(exc)) from exc
    try:
        return resolve_http_endpoint_pin(
            endpoint,
            backend=backend,
            loopback_only=loopback_only,
            allowed_hosts=allowed_hosts,
            require_https_for_remote=backend == "LLM gateway",
            resolver=socket.getaddrinfo,
        )
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(req.full_url, code, "redirects are not allowed", headers, fp)


def _open_no_redirect(
    req: urllib.request.Request,
    timeout: float,
    *,
    bypass_proxy: bool = False,
    endpoint_pin: EndpointPin | None = None,
):
    handlers: list[Any] = [_NoRedirectHandler()]
    if bypass_proxy:
        # Ollama is a local or explicitly allowlisted internal service. urllib
        # otherwise inherits HTTP(S)_PROXY from the process environment, which
        # can send localhost requests to a corporate proxy and turn a healthy
        # local Ollama instance into an unexpected HTTP 403.
        handlers.insert(0, urllib.request.ProxyHandler({}))
    if endpoint_pin is not None:
        handlers.extend(pinned_endpoint_handlers(endpoint_pin))
    return urllib.request.build_opener(*handlers).open(req, timeout=timeout)


def _open_with_retry(
    req: urllib.request.Request,
    timeout: Any,
    max_retries: int = 1,
    *,
    bypass_proxy: bool = False,
    endpoint_pin: EndpointPin | None = None,
):
    bounded_timeout = _bounded_timeout(timeout)
    attempts = max(1, min(int(max_retries) + 1, 4))
    for attempt in range(attempts):
        try:
            return _open_no_redirect(
                req,
                timeout=bounded_timeout,
                bypass_proxy=bypass_proxy,
                endpoint_pin=endpoint_pin,
            )
        except urllib.error.HTTPError as exc:
            if exc.code not in _RETRYABLE_HTTP_CODES or attempt + 1 >= attempts:
                raise
            exc.close()
        except (urllib.error.URLError, TimeoutError):
            if attempt + 1 >= attempts:
                raise
        time.sleep(0.05 * (attempt + 1))
    raise RuntimeError("model request failed after bounded retry")  # pragma: no cover


def _read_limited_response(resp: Any, limit: int = MAX_LLM_RESPONSE_BYTES) -> bytes:
    headers = getattr(resp, "headers", None)
    if headers:
        try:
            content_length = int(headers.get("Content-Length", "0") or 0)
        except (TypeError, ValueError):
            content_length = 0
        if content_length > limit:
            raise RuntimeError(f"model response exceeds {limit} byte limit")
    try:
        data = resp.read(limit + 1)
    except TypeError:
        # Small test doubles and a few alternate urllib-compatible transports do
        # not expose the optional size argument; still verify after reading.
        data = resp.read()
    if not isinstance(data, (bytes, bytearray)):
        raise RuntimeError("model response body is not bytes")
    if len(data) > limit:
        raise RuntimeError(f"model response exceeds {limit} byte limit")
    return bytes(data)


def _read_error_body(exc: urllib.error.HTTPError) -> str:
    try:
        try:
            body = exc.read(MAX_LLM_ERROR_BYTES + 1)
        except TypeError:
            body = exc.read()
    finally:
        exc.close()
    return bytes(body[:MAX_LLM_ERROR_BYTES]).decode("utf-8", errors="ignore")


def is_anthropic_messages_endpoint(endpoint: str) -> bool:
    path = urllib.parse.urlsplit(endpoint).path.rstrip("/")
    return path == "/v1/messages"


def is_openai_responses_endpoint(endpoint: str) -> bool:
    path = urllib.parse.urlsplit(endpoint).path.rstrip("/")
    return path == "/v1/responses"


def is_openai_chat_completions_endpoint(endpoint: str) -> bool:
    path = urllib.parse.urlsplit(endpoint).path.rstrip("/")
    return path == "/v1/chat/completions"


def resolve_gateway_api_key(
    endpoint: str,
    configured_key: str = "",
    api_key_env: str = "",
) -> str:
    if configured_key:
        return configured_key
    if api_key_env:
        api_key = str(os.getenv(api_key_env, ""))
        if api_key:
            return api_key
    anthropic_base = str(os.getenv("ANTHROPIC_BASE_URL", "")).strip()
    if not anthropic_base or not is_anthropic_messages_endpoint(endpoint):
        return ""
    endpoint_url = urllib.parse.urlsplit(endpoint)
    base_url = urllib.parse.urlsplit(anthropic_base)
    if (
        endpoint_url.scheme.lower() == base_url.scheme.lower()
        and endpoint_url.hostname == base_url.hostname
        and endpoint_url.port == base_url.port
    ):
        return str(os.getenv("ANTHROPIC_AUTH_TOKEN", ""))
    return ""


def build_gateway_request(
    endpoint: str,
    model: str,
    prompt: str,
    context: dict[str, Any],
    api_key: str = "",
    *,
    max_tokens: int = ANTHROPIC_MAX_TOKENS,
) -> urllib.request.Request:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": GATEWAY_USER_AGENT,
    }
    if is_anthropic_messages_endpoint(endpoint):
        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": max(1, min(int(max_tokens), ANTHROPIC_MAX_TOKENS)),
            "messages": [{"role": "user", "content": prompt}],
        }
        headers["anthropic-version"] = ANTHROPIC_VERSION
    elif is_openai_responses_endpoint(endpoint):
        payload = {
            "model": model,
            "input": [
                {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": prompt}],
                }
            ],
            "max_output_tokens": max(1, min(int(max_tokens), ANTHROPIC_MAX_TOKENS)),
        }
    elif is_openai_chat_completions_endpoint(endpoint):
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max(1, min(int(max_tokens), ANTHROPIC_MAX_TOKENS)),
        }
    else:
        payload = {"model": model, "prompt": prompt, "context": context}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return urllib.request.Request(
        endpoint,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="POST",
    )


def _text_from_content(content: Any) -> str:
    if isinstance(content, str):
        return content.strip()
    if not isinstance(content, list):
        return ""
    return "\n".join(
        str(item.get("text", ""))
        for item in content
        if isinstance(item, dict)
        and str(item.get("type", "")).lower() in {"text", "output_text"}
        and isinstance(item.get("text"), str)
    ).strip()


def _openai_response_text(parsed: dict[str, Any]) -> str:
    text = _text_from_content(parsed.get("output_text"))
    if text:
        return text
    output = parsed.get("output")
    if isinstance(output, list):
        parts = [
            _text_from_content(item.get("content"))
            for item in output
            if isinstance(item, dict) and isinstance(item.get("content"), list)
        ]
        text = "\n".join(part for part in parts if part).strip()
        if text:
            return text
    choices = parsed.get("choices")
    if isinstance(choices, list):
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message")
            if isinstance(message, dict):
                text = _text_from_content(message.get("content"))
                if text:
                    return text
    return ""


def parse_gateway_response(parsed: Any, model: str) -> dict[str, Any]:
    if isinstance(parsed, dict) and parsed.get("type") == "message" and isinstance(parsed.get("content"), list):
        text = _text_from_content(parsed["content"])
        if not text:
            raise RuntimeError("Anthropic gateway returned no text content")
        parsed = _parse_json_object(text)
    elif isinstance(parsed, dict):
        text = _openai_response_text(parsed)
        if text:
            parsed = _parse_json_object(text)
    return _validate_result_shape(parsed, model)


class LLMClient:
    def analyze(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    @property
    def is_deterministic(self) -> bool:
        """True for analyzers whose judgment is grounded in structured evidence."""
        return False

    @property
    def runtime_metadata(self) -> dict[str, Any]:
        return {"provider": "unknown", "model": "", "endpoint_host": ""}

    @property
    def defer_on_failure(self) -> bool:
        """Whether a model failure should return work to the durable inbox."""
        return False

    @property
    def retry_after_seconds(self) -> float:
        """Minimum delay before a durable retry after the latest failure."""
        return 0.0


class _CircuitBreaker:
    def __init__(self, threshold: int = 3, reset_seconds: float = 30.0):
        self.threshold = threshold
        self.reset_seconds = reset_seconds
        self.failures = 0
        self.opened_until = 0.0
        self._lock = threading.Lock()

    def before_request(self) -> None:
        with self._lock:
            now = time.monotonic()
            if self.opened_until > now:
                raise RuntimeError("model circuit breaker is open")
            if self.opened_until:
                self.opened_until = 0.0
                self.failures = 0

    def success(self) -> None:
        with self._lock:
            self.failures = 0
            self.opened_until = 0.0

    def failure(self) -> None:
        with self._lock:
            self.failures += 1
            if self.failures >= self.threshold:
                self.opened_until = time.monotonic() + self.reset_seconds

    def retry_after_seconds(self) -> float:
        with self._lock:
            return max(0.0, self.opened_until - time.monotonic())

    def snapshot(self) -> dict[str, Any]:
        retry_after = self.retry_after_seconds()
        with self._lock:
            return {
                "state": "open" if retry_after > 0 else "closed",
                "consecutive_failures": self.failures,
                "retry_after_seconds": round(retry_after, 3),
            }


class LocalHeuristicLLM(LLMClient):
    """Deterministic local analyzer for offline MVP and tests."""

    is_deterministic = True

    @property
    def runtime_metadata(self) -> dict[str, Any]:
        return {"provider": "local", "model": "local-rule-analyst", "endpoint_host": ""}

    HIGH_WORDS = [
        "rce",
        "sql",
        "xss",
        "c2",
        "exfil",
        "lateral",
        "credential",
        "webshell",
        "jndi",
        "ldap://",
        "fastjson",
        "deserialization",
        "processbuilder",
        "提权",
        "横向",
        "外传",
        "反序列化",
        "命令执行",
    ]
    def analyze(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        # Historical memory may itself mention SQL/RCE/C2. Attack keyword scoring
        # must only inspect the current alert; governed-memory influence is applied
        # later by the provider-neutral MemoryMatcher.
        text = json.dumps(
            {
                "product": context.get("product"),
                "severity": context.get("severity"),
                "event_type": context.get("event_type"),
                "entities": context.get("entities"),
                "evidence": context.get("evidence"),
            },
            ensure_ascii=False,
        ).lower()
        score = sum(1 for word in self.HIGH_WORDS if word in text)
        severity = context.get("severity", "medium").lower()
        sample_assessment = self._sample_assessment(context)
        if sample_assessment:
            return sample_assessment
        if self._strong_attack_signal(context, score, severity):
            classification = "malicious"
            confidence = min(0.92, 0.72 + score * 0.05)
        elif severity in {"critical", "high"} or score >= 2:
            classification = "suspicious"
            confidence = min(0.9, 0.62 + score * 0.08)
        elif score == 1:
            classification = "suspicious"
            confidence = 0.58
        else:
            classification = "insufficient_evidence"
            confidence = 0.42
        return {
            "classification": classification,
            "confidence": confidence,
            "verdict": self._verdict_from_classification(classification),
            "analysis_dimensions": self._fallback_dimensions(context, score, severity),
            "reason": self._fallback_reason(context, classification, score, severity),
            "recommended_next_steps": self._fallback_next_steps(context, classification),
            "missing_evidence": ["缺少可交叉验证的产品证据或企业 LLM 深度研判结果"],
            "business_impact": self._fallback_business_impact(context, classification),
        }

    def _sample_assessment(self, context: dict[str, Any]) -> dict[str, Any] | None:
        evidence = context.get("evidence") or []
        if not isinstance(evidence, list):
            return None
        expected_verdict = ""
        dimensions: list[dict[str, Any]] = []
        whitelist: dict[str, Any] = {}
        success = ""
        impact = ""
        missing: list[str] = []
        for item in evidence:
            if not isinstance(item, dict):
                continue
            item_type = item.get("type")
            value = item.get("value")
            if item_type == "expected_verdict" and value:
                expected_verdict = str(value)
            elif item_type == "analysis_dimension" and isinstance(value, dict):
                dimensions.append(
                    {
                        "title": str(value.get("title") or "证据维度"),
                        "status": str(value.get("status") or item.get("weight") or "info"),
                        "evidence": str(value.get("evidence") or ""),
                    }
                )
            elif item_type == "whitelist_candidate" and isinstance(value, dict):
                whitelist = value
            elif item_type == "success_assessment" and value:
                success = str(value)
            elif item_type == "business_impact" and value:
                impact = str(value)
            elif item_type == "missing_evidence":
                if isinstance(value, list):
                    missing.extend(str(part) for part in value if part)
                elif value:
                    missing.append(str(value))
        if not expected_verdict and not dimensions:
            return None
        classification = self._classification_from_verdict(expected_verdict, context)
        confidence = self._confidence_from_assessment(classification, dimensions, context)
        verdict = expected_verdict or self._verdict_from_classification(classification)
        reason = self._reason_from_assessment(verdict, dimensions, success, impact, whitelist)
        next_steps = self._next_steps_from_assessment(classification, whitelist, missing)
        return {
            "classification": classification,
            "confidence": confidence,
            "verdict": verdict,
            "analysis_dimensions": dimensions,
            "reason": reason,
            "recommended_next_steps": next_steps,
            "missing_evidence": missing,
            "business_impact": impact,
            "whitelist_recommendation": whitelist,
        }

    def _classification_from_verdict(self, verdict: str, context: dict[str, Any]) -> str:
        text = verdict.lower()
        if "误报" in text or "benign" in text:
            return "benign"
        if "真实" in text or "真实攻击" in text or "真实事件" in text or "malicious" in text:
            return "malicious"
        if "需人工复核" in text or "可疑" in text or "suspicious" in text:
            return "suspicious"
        severity = str(context.get("severity", "")).lower()
        return "suspicious" if severity in {"critical", "high"} else "insufficient_evidence"

    def _confidence_from_assessment(self, classification: str, dimensions: list[dict[str, Any]], context: dict[str, Any]) -> float:
        status_text = " ".join(str(item.get("status", "")) for item in dimensions).lower()
        support = len([item for item in dimensions if str(item.get("evidence", "")).strip()])
        confidence = 0.62 + min(0.18, support * 0.025)
        if classification == "benign":
            confidence += 0.08 if any(word in status_text for word in ["benign", "normal", "allow"]) else 0.02
        if classification == "malicious":
            confidence += 0.08 if any(word in status_text for word in ["risk", "malicious", "blocked"]) else 0.04
        if str(context.get("severity", "")).lower() in {"critical", "high"}:
            confidence += 0.04
        return round(max(0.35, min(0.94, confidence)), 2)

    def _verdict_from_classification(self, classification: str) -> str:
        return {
            "malicious": "【真实攻击】- 样本证据指向攻击行为",
            "suspicious": "【需人工复核】- 样本证据支持可疑但缺少关键确认",
            "benign": "【误报】- 样本证据指向合法业务或已知误报",
        }.get(classification, "【需人工复核】- 证据不足")

    def _reason_from_assessment(
        self,
        verdict: str,
        dimensions: list[dict[str, Any]],
        success: str,
        impact: str,
        whitelist: dict[str, Any],
    ) -> str:
        lines = [f"研判结论：{verdict}", "分析报告："]
        for item in dimensions:
            title = str(item.get("title") or "证据维度")
            evidence = str(item.get("evidence") or "无补充说明")
            lines.append(f"- {title}：{evidence}")
        if success:
            lines.append(f"- 成功与危害：{success}")
        if impact:
            lines.append(f"- 业务影响：{impact}")
        if whitelist:
            lines.append(f"- 误报与白名单：{self._format_whitelist(whitelist)}")
        return "\n".join(lines)

    def _next_steps_from_assessment(
        self,
        classification: str,
        whitelist: dict[str, Any],
        missing: list[str],
    ) -> list[str]:
        steps = []
        if classification == "benign" and whitelist:
            steps.append("建议添加以下白名单：" + self._format_whitelist(whitelist))
        if missing:
            steps.append("补充证据：" + "；".join(missing[:4]))
        if classification in {"malicious", "suspicious"}:
            steps.append("基于当前证据进行只读复核，确认产品动作、业务影响和是否存在后续关联告警")
        if not steps:
            steps.append("复核样本证据维度是否与当前告警完全一致")
        return steps

    def _format_whitelist(self, whitelist: dict[str, Any]) -> str:
        order = [
            "rule_type",
            "attack_type",
            "detection_content",
            "match_method",
            "scope",
            "reason",
            "review_cycle",
        ]
        parts = []
        for key in order:
            value = whitelist.get(key)
            if value:
                parts.append(f"{key}=`{value}`")
        for key, value in whitelist.items():
            if key not in order and value:
                parts.append(f"{key}=`{value}`")
        return "；".join(parts)

    def _fallback_dimensions(self, context: dict[str, Any], score: int, severity: str) -> list[dict[str, str]]:
        entities = context.get("entities") or {}
        evidence = context.get("evidence") or []
        classification = "malicious" if self._strong_attack_signal(context, score, severity) else ("suspicious" if severity in {"critical", "high"} or score else "insufficient_evidence")
        status = {
            "malicious": "risk",
            "suspicious": "review",
            "benign": "benign",
        }.get(classification, "info")
        by_type = self._evidence_by_type(evidence)
        outline = context.get("report_outline") or ["综合判断", "关键证据", "处置动作", "证据缺口", "误报与白名单"]
        dims = []
        for title in outline:
            detail = self._fallback_dimension_detail(str(context.get("product", "")), str(title), entities, by_type, score, severity)
            dims.append({"title": str(title), "status": self._fallback_dimension_status(str(title), detail, status), "evidence": detail})
        return dims

    def _fallback_reason(self, context: dict[str, Any], classification: str, score: int, severity: str) -> str:
        verdict = self._verdict_from_classification(classification)
        lines = [f"研判结论：{verdict}", "分析报告："]
        for item in self._fallback_dimensions(context, score, severity):
            lines.append(f"- {item['title']}：{item['evidence']}")
        return "\n".join(lines)

    def _fallback_next_steps(self, context: dict[str, Any], classification: str) -> list[str]:
        product = str(context.get("product") or "security").upper()
        steps = [
            f"只读复核 {product} 原始告警，确认规则、关键实体、处置动作和时间窗口",
            "关联同一资产、同一来源、同一账号在前后 30 分钟内的相关告警",
        ]
        if classification in {"suspicious", "malicious"}:
            steps.append("补充产品原始日志或接入内网 LLM Gateway 后重新生成深度研判")
        else:
            steps.append("若确认业务合法，再评估最小范围白名单或规则调优")
        return steps

    def _fallback_business_impact(self, context: dict[str, Any], classification: str) -> str:
        entities = context.get("entities") or {}
        asset = entities.get("app") or entities.get("host") or entities.get("url") or entities.get("src_ip") or "相关资产"
        if classification == "suspicious":
            return f"{asset} 存在可疑安全信号，当前证据不足以确认影响范围；需优先补齐原始日志和关联证据。"
        if classification == "malicious":
            return f"{asset} 可能受到真实攻击影响，需要确认是否已被阻断以及是否存在后续横向、外联或数据风险。"
        return f"{asset} 暂未形成明确攻击证据，主要风险是告警噪声或证据不足导致的误判。"

    def _strong_attack_signal(self, context: dict[str, Any], score: int, severity: str) -> bool:
        product = str(context.get("product") or "").lower()
        evidence = context.get("evidence") or []
        by_type = self._evidence_by_type(evidence)
        if product == "rasp":
            has_runtime_path = bool(by_type.get("sink") or by_type.get("stack_trace") or by_type.get("stacktrace"))
            has_attack_context = bool(by_type.get("hook_data") or by_type.get("taint_source") or by_type.get("payload_category"))
            if has_runtime_path and (has_attack_context or score >= 2):
                return True
        if product == "waf":
            action = str((context.get("entities") or {}).get("action") or by_type.get("action") or "").lower()
            if not (
                severity in {"critical", "high"}
                and any(word in action for word in ["block", "阻断"])
            ):
                return False
            # A single detector phrase such as "SQL injection" contributes only
            # one keyword to the generic score.  For a high-severity request
            # already blocked by the WAF, a specific detector-level attack
            # marker is independent evidence and is sufficient to escalate the
            # local, deterministic assessment to malicious.  This still avoids
            # treating a generic high-severity block as a confirmed attack.
            detector_text = " ".join(
                str(value or "")
                for value in (
                    context.get("event_type"),
                    (context.get("entities") or {}).get("rule"),
                    by_type.get("rule_id"),
                    by_type.get("rule_name"),
                    by_type.get("payload_category"),
                )
            ).lower()
            detector_markers = (
                "sqli",
                "sql injection",
                "sql注入",
                "xss",
                "cross-site scripting",
                "cross site scripting",
                "rce",
                "remote code execution",
                "command injection",
                "命令注入",
                "ssrf",
                "server-side request forgery",
                "path traversal",
                "directory traversal",
                "路径遍历",
                "file inclusion",
                "文件包含",
                "webshell",
                "deserialization",
                "反序列化",
            )
            return score >= 2 or any(marker in detector_text for marker in detector_markers)
        if product in {"hips", "ndr", "siem"}:
            return severity in {"critical", "high"} and score >= 2
        return severity == "critical" and score >= 3

    def _evidence_by_type(self, evidence: Any) -> dict[str, Any]:
        by_type: dict[str, Any] = {}
        if not isinstance(evidence, list):
            return by_type
        for item in evidence:
            if isinstance(item, dict) and item.get("type") and item.get("type") not in by_type:
                by_type[str(item["type"])] = item.get("value")
        return by_type

    def _fallback_dimension_detail(
        self,
        product: str,
        title: str,
        entities: dict[str, Any],
        by_type: dict[str, Any],
        score: int,
        severity: str,
    ) -> str:
        product = product.lower()
        if product == "rasp":
            if "参数" in title:
                return self._join_facts(
                    [
                        self._fact("方法", entities.get("method") or by_type.get("method")),
                        self._fact("URL", entities.get("url") or by_type.get("url") or by_type.get("uri")),
                        request_context_fact(by_type.get("request_context")),
                        request_parameters_fact(by_type.get("request_parameters")),
                        self._fact("污染源", by_type.get("taint_source")),
                        self._fact("载荷摘要", by_type.get("payload_category")),
                    ],
                    "缺少参数、路径或污染源明细，无法完整判断入口特征。",
                )
            if "危险调用" in title:
                return self._join_facts(
                    [
                        self._fact("sink", by_type.get("sink")),
                        self._fact("stack", by_type.get("stack_trace") or by_type.get("stacktrace")),
                    ],
                    "缺少危险 sink 或调用栈，需要回看 RASP 原始 stacktrace。",
                )
            if "规则" in title:
                return self._join_facts([self._fact("规则", entities.get("rule") or by_type.get("rule_id") or by_type.get("rule_name"))], "缺少 RASP 规则信息。")
            if "上下文" in title:
                return self._join_facts(
                    [
                        hook_data_fact(by_type.get("hook_data")),
                        request_context_fact(by_type.get("request_context")),
                        self._fact("动作", entities.get("action") or by_type.get("action")),
                        self._fact("应用", entities.get("app")),
                        self._fact("主机", entities.get("host")),
                    ],
                    "缺少 hook_data、动作或应用上下文。",
                )
            if "成功" in title:
                action = entities.get("action") or by_type.get("action")
                return f"产品动作为 {self._short(action)}；需要结合响应、异常和后续日志确认是否成功。" if action else "缺少动作、响应或异常证据，无法判断成功性。"
            if "误报" in title:
                return "如判定误报，白名单必须限定规则、路径/参数、应用、sink 或 stacktrace，避免宽泛放行。"
        if product == "waf":
            if "请求" in title:
                return self._join_facts([self._fact("方法", entities.get("method") or by_type.get("method")), self._fact("URL", entities.get("url") or by_type.get("uri")), self._fact("来源", entities.get("src_ip"))], "缺少 URL、方法或来源。")
            if "参数" in title:
                return self._join_facts([self._fact("命中字段", by_type.get("matched_parameters")), self._fact("载荷摘要", by_type.get("payload_category"))], "缺少命中参数/Header 或载荷摘要。")
            if "规则" in title:
                return self._join_facts([self._fact("规则", entities.get("rule") or by_type.get("rule_id") or by_type.get("rule_name"))], "缺少 WAF 规则信息。")
            if "响应" in title:
                return self._join_facts([self._fact("动作", entities.get("action") or by_type.get("action")), self._fact("状态码", by_type.get("status"))], "缺少 WAF 动作或响应码。")
        if product == "hips":
            if "主机" in title:
                return self._join_facts([self._fact("主机", entities.get("host")), self._fact("用户", entities.get("user")), self._fact("来源", entities.get("src_ip"))], "缺少主机、用户或登录来源。")
            if "进程链" in title:
                return self._join_facts([self._fact("进程", entities.get("process") or by_type.get("process_name")), self._fact("父进程", by_type.get("parent_process"))], "缺少父子进程证据。")
            if "命令行" in title:
                return self._join_facts([self._fact("命令行摘要", by_type.get("command_line"))], "缺少命令行或脚本摘要。")
            if "规则" in title:
                return self._join_facts([self._fact("规则", entities.get("rule") or by_type.get("rule_id")), self._fact("动作", entities.get("action") or by_type.get("action"))], "缺少 HIPS 规则或动作。")
        if product == "ndr":
            if "通信" in title:
                return self._join_facts([self._fact("源", entities.get("src_ip") or entities.get("host")), self._fact("目的", entities.get("dst_ip") or by_type.get("sni")), self._fact("协议", by_type.get("protocol"))], "缺少源、目的或协议方向。")
            if "时序" in title or "流量" in title:
                return self._join_facts([self._fact("会话", by_type.get("session_count_30m")), self._fact("间隔", by_type.get("beacon_interval_seconds")), self._fact("出站字节", by_type.get("bytes_out"))], "缺少时序或流量证据。")
            if "协议" in title or "指纹" in title:
                return self._join_facts([self._fact("SNI", by_type.get("sni")), self._fact("JA3", by_type.get("ja3")), self._fact("JA4", by_type.get("ja4"))], "缺少 DNS/TLS/HTTP 指纹。")
        if product == "siem":
            if "时间线" in title:
                return self._join_facts([self._fact("时间线", by_type.get("timeline"))], "缺少关键事件时间线。")
            if "实体" in title:
                return self._join_facts([self._fact("用户", entities.get("user")), self._fact("主机", entities.get("host")), self._fact("源", entities.get("src_ip"))], "缺少实体关系。")
            if "攻击链" in title:
                return self._join_facts([self._fact("摘要", by_type.get("case_summary")), self._fact("信号", by_type.get("signals"))], "缺少多源攻击链信号。")
        if "误报" in title or "白名单" in title:
            return "仅在业务合法、边界明确且有复核周期时建议白名单或规则调优。"
        if "成功" in title or "危害" in title or "影响" in title or "数据" in title:
            return "需要结合产品动作、后续日志和业务资产画像判断成功性与影响范围。"
        if "关联" in title or "多源" in title:
            return "缺少跨产品关联证据，需要补充 HIPS/RASP/NDR/WAF/SIEM 或应用日志。"
        if "缺口" in title or "响应" in title:
            return "当前为本地规则分析器输出，需补充原始日志、上下文和 Gateway 深度研判。"
        return f"严重级别为 {severity}，上下文命中 {score} 个高风险关键词，关键实体为 {json.dumps(entities, ensure_ascii=False, sort_keys=True)}。"

    def _fallback_dimension_status(self, title: str, detail: str, default: str) -> str:
        if "缺少" in detail or "无法" in detail or "需要" in detail:
            return "review"
        if "动作" in title or "响应" in title or "成功" in title:
            if any(word in detail.lower() for word in ["block", "blocked", "阻断", "拦截"]):
                return "blocked"
        if "误报" in title or "白名单" in title:
            return "review"
        return default

    def _join_facts(self, facts: list[str], fallback: str) -> str:
        return join_facts(facts, fallback)

    def _fact(self, label: str, value: Any) -> str:
        return fact(label, value)

    def _short(self, value: Any) -> str:
        return short_text(value)

class GatewayLLM(LLMClient):
    """Enterprise gateway adapter supporting generic JSON and Anthropic Messages."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self._circuit = _CircuitBreaker()

    @property
    def runtime_metadata(self) -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(self.config.endpoint)
        return {
            "provider": "gateway",
            "model": self.config.model,
            "endpoint_host": parsed.hostname or "",
            "failure_mode": "durable_retry",
            "circuit": self._circuit.snapshot(),
        }

    @property
    def defer_on_failure(self) -> bool:
        return True

    @property
    def retry_after_seconds(self) -> float:
        # A short floor avoids exhausting the durable attempt budget during a
        # fast 401/5xx loop; an open breaker extends it to its remaining window.
        return max(5.0, self._circuit.retry_after_seconds())

    def analyze(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        self._circuit.before_request()
        try:
            result = self._analyze(prompt, context)
        except Exception:
            self._circuit.failure()
            raise
        self._circuit.success()
        return result

    def _analyze(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        if not self.config.endpoint:
            raise RuntimeError("LLM endpoint is not configured")
        endpoint_pin = _validate_http_endpoint(
            self.config.endpoint,
            backend="LLM gateway",
            allowed_hosts=self.config.allowed_hosts,
        )
        api_key = resolve_gateway_api_key(
            self.config.endpoint,
            self.config.api_key,
            self.config.api_key_env,
        )
        if not api_key:
            # Do not send an analysis prompt to a remote endpoint that cannot
            # authenticate it. The orchestrator records this as a durable
            # retry so an operator can add the deployment secret and resume.
            raise RuntimeError("LLM gateway API key is not configured")
        # ``context`` is already redacted + size-bounded by SecurityAgent.analyze.
        # Anthropic receives it inside ``prompt``; generic gateways retain the
        # separate context field used by the original enterprise contract.
        req = build_gateway_request(
            self.config.endpoint,
            self.config.model,
            prompt,
            context,
            api_key,
        )
        try:
            with _open_with_retry(
                req,
                self.config.timeout_seconds,
                self.config.max_retries,
                bypass_proxy=True,
                endpoint_pin=endpoint_pin,
            ) as resp:
                if resp.status >= 400:
                    raise RuntimeError(f"LLM gateway returned HTTP {resp.status}")
                limit = max(65_536, min(int(self.config.max_response_bytes), 10_000_000))
                body = _read_limited_response(resp, limit).decode("utf-8")
        except urllib.error.HTTPError as exc:
            body = _read_error_body(exc)
            if is_websocket_upgrade_required(exc.code, body):
                raise LLMEndpointConfigurationError(WEBSOCKET_ENDPOINT_GUIDANCE) from exc
            raise RuntimeError(f"LLM gateway HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"LLM gateway unreachable: {exc.reason}") from exc
        except TimeoutError as exc:
            raise RuntimeError("LLM gateway request timed out") from exc
        try:
            parsed = loads_bounded_json(body)
        except ValueError as exc:
            raise RuntimeError(f"LLM gateway returned invalid JSON response: {body[:200]}") from exc
        return parse_gateway_response(parsed, self.config.model)


def _validate_result_shape(parsed: Any, model: str) -> dict[str, Any]:
    """Ensure an LLM result conforms to the analysis contract.

    The enterprise gateway is the least-constrained backend (no grammar
    enforcement like Ollama's ``format``), so we validate the response here and
    fall back to a safe ``insufficient_evidence`` shell on any mismatch rather
    than letting a malformed dict propagate to reconciliation.
    """
    if not isinstance(parsed, dict):
        return {
            "classification": "insufficient_evidence",
            "confidence": 0.2,
            "reason": "LLM 网关返回非对象 JSON，已降级为证据不足。",
            "model": model,
        }
    parsed = dict(parsed)
    # Normalize Chinese classification labels (e.g. "真实攻击"/"误报") to the
    # canonical enum before the allow-list check, so a compliant-in-spirit but
    # Chinese-labeled gateway response is not downgraded to insufficient_evidence.
    original = str(parsed.get("classification", "")).strip().lower()
    normalized = normalize_classification(original)
    parsed["classification"] = normalized
    if normalized == "insufficient_evidence" and original and original not in {
        "malicious", "suspicious", "benign", "insufficient_evidence", "insufficient",
    }:
        # Unknown classification text: downgrade and explain.
        if "confidence" not in parsed:
            parsed["confidence"] = 0.2
        parsed.setdefault("reason", "LLM 网关返回的 classification 不合规，已降级为证据不足。")
    parsed.setdefault("model", model)
    return parsed


# JSON Schema for Ollama structured outputs. Mirrors the result contract that
# SecurityAgent._build_prompt asks for, so local models are grammar-constrained
# into the exact fields instead of free-form (or wrong-schema) JSON.
OLLAMA_ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "classification": {
            "type": "string",
            "enum": ["malicious", "suspicious", "benign", "insufficient_evidence"],
        },
        "confidence": {"type": "number"},
        "verdict": {"type": "string"},
        "reason": {"type": "string"},
        "analysis_dimensions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "status": {
                        "type": "string",
                        "enum": ["risk", "benign", "normal", "blocked", "review", "info"],
                    },
                    "evidence": {"type": "string"},
                },
                "required": ["title", "status", "evidence"],
            },
        },
        "whitelist_recommendation": {
            "type": "object",
            "properties": {
                "rule_type": {"type": "string"},
                "detection_content": {"type": "string"},
                "match_method": {"type": "string"},
                "reason": {"type": "string"},
            },
        },
        "recommended_next_steps": {"type": "array", "items": {"type": "string"}},
        "missing_evidence": {"type": "array", "items": {"type": "string"}},
        "attack_stage": {"type": "array", "items": {"type": "string"}},
        "business_impact": {"type": "string"},
    },
    "required": [
        "classification",
        "confidence",
        "verdict",
        "reason",
        "analysis_dimensions",
        "business_impact",
        "missing_evidence",
        "recommended_next_steps",
    ],
}


class OllamaLLM(LLMClient):
    """Adapter for local Ollama models such as gemma3:4b."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self.endpoint = config.endpoint or "http://127.0.0.1:11434/api/generate"
        self._circuit = _CircuitBreaker()

    @property
    def runtime_metadata(self) -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(self.endpoint)
        return {
            "provider": "ollama",
            "model": self.config.model or "gemma3:4b",
            "endpoint_host": parsed.hostname or "",
            "failure_mode": "durable_retry",
            "circuit": self._circuit.snapshot(),
        }

    @property
    def defer_on_failure(self) -> bool:
        return True

    @property
    def retry_after_seconds(self) -> float:
        return max(5.0, self._circuit.retry_after_seconds())

    def analyze(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        self._circuit.before_request()
        try:
            result = self._analyze(prompt, context)
        except Exception:
            self._circuit.failure()
            raise
        self._circuit.success()
        return result

    def _analyze(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        model = self.config.model or "gemma3:4b"
        try:
            return self._generate(model, prompt)
        except urllib.error.HTTPError as exc:
            body = _read_error_body(exc)
            if exc.code == 404 and model == "gemma3:4b":
                try:
                    result = self._generate("gemma3:latest", prompt)
                except urllib.error.HTTPError as fallback_exc:
                    detail = _read_error_body(fallback_exc)
                    raise RuntimeError(f"Ollama HTTP {fallback_exc.code}: {detail[:200]}") from fallback_exc
                except urllib.error.URLError as fallback_exc:
                    raise RuntimeError(f"Ollama unreachable: {fallback_exc.reason}") from fallback_exc
                except TimeoutError as fallback_exc:
                    raise RuntimeError("Ollama request timed out") from fallback_exc
                result["model_fallback"] = "gemma3:4b not found; used gemma3:latest"
                return result
            raise RuntimeError(f"Ollama HTTP {exc.code}: {body[:200]}") from exc
        except urllib.error.URLError as exc:
            # Connection refused / DNS / timeout — surface as a RuntimeError so the
            # orchestrator can degrade to the deterministic heuristic rather than
            # abort the whole alert.
            raise RuntimeError(f"Ollama unreachable: {exc.reason}") from exc
        except TimeoutError as exc:
            raise RuntimeError("Ollama request timed out") from exc
        except ValueError as exc:
            raise RuntimeError("Ollama returned invalid JSON response") from exc

    def _generate(self, model: str, prompt: str) -> dict[str, Any]:
        endpoint_pin = _validate_http_endpoint(
            self.endpoint,
            backend="Ollama",
            allowed_hosts=self.config.allowed_hosts,
        )
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            # 结构化输出：用 JSON Schema 约束模型必须产出 Agent 约定的字段。
            # 仅靠 format:"json" 时，reasoning 模型（如 deepseek-r1）的 <think> 被
            # 语法约束抑制，容易原样回吐输入字段或产出错误 schema；显式 schema 可
            # 强制字段名与枚举值，显著提升本地小模型的字段遵循率。
            "format": OLLAMA_ANALYSIS_SCHEMA,
            "options": {
                # temperature 0 + fixed seed for reproducible harness replay; a
                # failing sample should fail consistently rather than pass on retry.
                "temperature": 0,
                "top_p": 0.9,
                "seed": 0,
            },
        }
        req = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with _open_with_retry(
            req,
            self.config.timeout_seconds,
            self.config.max_retries,
            bypass_proxy=True,
            endpoint_pin=endpoint_pin,
        ) as resp:
            limit = max(65_536, min(int(self.config.max_response_bytes), 10_000_000))
            data = loads_bounded_json(_read_limited_response(resp, limit).decode("utf-8"))
        if not isinstance(data, dict):
            raise RuntimeError("Ollama returned non-object JSON")
        response = str(data.get("response", "")).strip()
        parsed = _parse_json_object(response)
        parsed.setdefault("reason", "Ollama 本地模型完成分析。")
        parsed.setdefault("model", model)
        return _validate_result_shape(parsed, model)


def _parse_json_object(text: str) -> dict[str, Any]:
    if not text:
        return {"classification": "insufficient_evidence", "confidence": 0.2, "reason": "模型返回为空。"}
    # Reasoning models (e.g. deepseek-r1) may wrap chain-of-thought in
    # <think>...</think>; strip it so we parse only the final answer.
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    try:
        parsed = loads_bounded_json(text)
        if isinstance(parsed, dict):
            return parsed
    except ValueError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                parsed = loads_bounded_json(match.group(0))
                if isinstance(parsed, dict):
                    return parsed
            except ValueError:
                pass
    return {
        "classification": "insufficient_evidence",
        "confidence": 0.25,
        "reason": f"模型未返回合法 JSON，原始摘要：{text[:500]}",
    }


def build_llm(config: LLMConfig) -> LLMClient:
    provider = str(config.provider or "").strip().lower()
    if provider == "local":
        return LocalHeuristicLLM()
    if provider == "ollama":
        endpoint = config.endpoint or "http://127.0.0.1:11434/api/generate"
        _validate_http_endpoint(
            endpoint,
            backend="Ollama",
            allowed_hosts=config.allowed_hosts,
        )
        return OllamaLLM(config)
    if provider == "gateway":
        if not config.endpoint:
            raise RuntimeError("LLM endpoint is not configured")
        _validate_http_endpoint(
            config.endpoint,
            backend="LLM gateway",
            allowed_hosts=config.allowed_hosts,
        )
        return GatewayLLM(config)
    raise RuntimeError(f"unsupported LLM provider: {provider or '<empty>'}")
