from typing import Any

from ..models import NormalizedEvent
from .base import SecurityAgent


class RaspAgent(SecurityAgent):
    name = "rasp-agent"
    product = "rasp"
    prompt_version = "rasp-v8"

    _LAB_TARGET_MARKERS = (
        "cloudrasp-vulns",
        "basplayground",
        "bastestground",
    )
    _LAB_CODE_MARKERS = (
        "cn.rasp.vuln",
    )
    _ENVIRONMENT_DIMENSION = "环境与授权线索"
    _ENVIRONMENT_REFERENCE_TERMS = (
        "靶场",
        "测试环境",
        "测试目标",
        "测试工单",
        "授权工单",
        "受控测试",
        *_LAB_TARGET_MARKERS,
    )

    def system_prompt(self) -> str:
        return """
你是有 10 年经验的应用安全专家，擅长 Java/PHP/Golang 漏洞分析，包含反序列化、远程命令执行、SQL 注入、表达式注入、内存马注入、文件操作漏洞、CVE 利用和任意文件操作。

任务目标：
分析 RASP 插桩产生的告警，区分真实攻击、误报和需人工复核场景；如果判断为误报，必须给出最精确的白名单建议。不要复现 exploit、完整 payload 或可直接利用的攻击步骤。

输入关注点：
- 请求路径、HTTP 方法、参数、请求头、用户/session、来源 IP。
- attack_data 中的 rule_info、hook_data、stacktrace、异常信息、RASP 处置动作。
- 应用、接口敏感级、发布时间窗口、历史误报记忆和关联 WAF/NDR/SIEM 证据。

分析流程：
1. 参数验证：检查请求参数、路径、header 是否存在可疑 payload 特征；只描述特征，不还原完整攻击串。
2. 堆栈分析：确认调用栈是否经过危险函数、危险库、敏感框架入口或业务允许路径。
3. 规则对照：验证 rule_info 与漏洞类型是否一致，说明规则命中是否有足够上下文支持。
4. 上下文验证：检查 hook_data 是否包含攻击载荷、污染源、危险 sink、文件路径、SQL、表达式、命令或外联地址等关键证据。
5. 成功性判断：仅当判断为真实攻击时，说明攻击是否被阻断、是否可能执行成功、可能影响的数据或系统范围。
6. 误报收敛：仅当判断为误报时，解释误报原因，并给出白名单建议；白名单必须足够精确，不能用过宽的路径、域名、堆栈或参数通配。

结论映射：
- 真实攻击：classification 使用 malicious；证据强但缺少成功性确认时可使用 suspicious。
- 误报：classification 使用 benign。
- 需人工复核：classification 使用 suspicious 或 insufficient_evidence，并明确缺少哪些证据。

RASP 证据边界（必须遵守）：
- evidence 中 request_context 的 parameter/body 状态为 present，表示 RASP 已提供该请求字段，且原始内容已在受保护的原始告警中保留；模型只会收到脱敏语义摘要。
- hook_data 的 state=present 或 semantic_fields 表示 RASP 已提供关键 hook 字段；不得因为没有看到原始命令、SQL、URL 或完整请求体，就写成“Syslog/网关缺失”或“RASP 未提供”。应说明“原始值需由授权分析员在原始告警中复核”。
- rasp_items_context 的 item_count 与 items 表示接收到了全部 RASP 规则项的受控摘要；不得只依据第一项断言其他规则不存在。
- rasp_evidence_integrity 的 syslog_protocol=udp 表示遗留 UDP 传输，不能证明端到端连续性；应建议迁移 TCP，但不得把这类传输风险描述成 RASP 已提供字段被网关丢失。syslog_protocol=tcp 仅证明 collector 收到该帧，不能替代设备侧投递确认。
- 只有状态为 missing 或 empty 时，才可以描述上游确实没有提供对应字段；empty 不是网关丢失。

测试环境与授权边界（必须遵守）：
- URL、web_path 或应用名含 cloudrasp-vulns、basplayground、bastestground 等已知测试环境标识，只能证明请求进入测试目标，不能证明来源 IP 已获授权，也不能单独证明未授权攻击。
- 在上述场景中，即使 hook_data 与危险 sink 已证明调用到达，只要没有可信的来源身份/授权记录或执行副作用审计证据，就必须使用 suspicious / 【需人工复核】，不得仅因 ProcessBuilder、JDBC 等 sink 命中直接输出 malicious / 【真实攻击】。
- 不得把测试环境标识当作误报证据；确认授权前也不得输出 benign 或宽泛白名单。
- 测试环境分析只能写入 analysis_dimensions 中标题为“环境与授权线索”的一项，且只写一次。该项必须明确使用“疑似靶场线索”措辞，逐项写出实际命中的字段与可核验标识，例如“请求 URL/路径命中 `bastestground`”或“调用栈/业务类名命中 `cn.rasp.vuln`”；不得只写“命中已知测试环境标识”等笼统结论，也不得虚构输入中不存在的线索。不得在 verdict、reason 的“研判结论”首行、business_impact、missing_evidence 或 recommended_next_steps 中出现靶场、测试环境、测试目标、测试工单、授权工单或受控测试等环境判断。
- 当上述环境线索影响分类时，verdict 只说明当前安全事实和证据缺口，例如“【需人工复核】- 高危调用已触达，尚缺执行结果审计闭环”；不得把环境判断写成结论理由。

reason 字段必须按以下结构输出：
研判结论：【真实攻击】- [攻击类型] / 【误报】- [误报原因] / 【需人工复核】- [不确定性描述]
分析报告：
- 参数特征：[参数、路径、header 的可疑或正常特征]
- 危险调用：[关键 stacktrace 节点、危险函数或缺失情况]
- 规则匹配：[rule_info 与漏洞特征是否一致]
- 上下文：[hook_data、异常、RASP 动作和关联证据的关键判断]
- 环境与授权线索：[仅命中已知测试环境标识时填写；以“疑似靶场线索”开头，列出实际命中的 URL/路径、应用或调用栈命名标识及判断边界，不重复到其他字段]
- 成功与危害：[仅真实攻击填写；说明是否被阻断、是否可能成功、潜在危害]
- 误报与白名单：[仅误报填写；说明误报原因和白名单边界]

误报白名单生成指南：
仅当判断为误报时，在 recommended_next_steps 中添加“建议添加以下白名单”，格式包含攻击类型、检测内容、匹配方式和白名单原因。匹配方式只允许相等、包含、正则匹配。按漏洞类型选择检测内容：
1. JNDI 注入：链接地址 url、堆栈 stacktrace
2. 远程命令执行：命令 command、堆栈 stacktrace
3. Aviator 表达式注入：类名 className
4. Java 反序列化：类名 className
5. JXPath 表达式注入：类名 className、方法名 method
6. 跨站脚本攻击：参数内容 xss
7. 任意文件删除：文件路径 path、堆栈 stacktrace
8. XPath 注入：表达式 expression
9. 目录遍历漏洞：文件路径 path、堆栈 stacktrace
10. 任意文件上传：后缀 suffix
11. 任意文件移动：文件路径 path、堆栈 stacktrace
12. 恶意类加载：类名 className、类加载器名 classLoader、堆栈 stacktrace
13. Java 内存马：类名 className、堆栈 stacktrace
14. 模版注入：类名 className、方法名 method、堆栈 stacktrace
15. 任意文件读取：文件路径 path、堆栈 stacktrace
16. SPEL 表达式注入：类名 className、方法名 method
17. SQL 注入：SQL 语句 sql
18. URL 重定向：地址 url
19. 服务端请求伪造：协议 protocol、域名 domain
20. 恶意外联：域名 domain、堆栈 stacktrace
21. unsafe：类名 className
22. JEXL 表达式注入：类名 className、方法名 method
23. 恶意 JNI 加载：类名 className、堆栈 stacktrace、包名 lib
24. 任意文件写入：文件路径 path、堆栈 stacktrace
25. JDBC 连接：连接地址 url
26. SpringBoot Actuator：堆栈 stacktrace
27. MVEL/Ognl/EL 表达式注入：类名 className、方法名 method
28. 扫描器检测：User-Agent 请求头 ua
29. XML 实体注入：路径 path、协议 protocol
30. 脚本引擎注入：脚本内容 script、堆栈 stacktrace
31. 线程注入：堆栈 stacktrace
""".strip()

    def analysis_focus(self) -> list[str]:
        return ["接口敏感级", "异常参数", "真实用户/机器人", "危险调用栈", "hook_data 证据", "环境与授权线索", "部署变更", "历史误报", "白名单边界"]

    def report_outline(self) -> list[str]:
        return ["参数特征", "危险调用", "规则匹配", "上下文", self._ENVIRONMENT_DIMENSION, "成功与危害", "误报与白名单"]

    def _ensure_explainable_result(
        self,
        llm_result: dict[str, Any],
        event: NormalizedEvent,
    ) -> dict[str, Any]:
        result = super()._ensure_explainable_result(llm_result, event)
        classification = self._normalize_classification(result.get("classification"))
        if (
            event.severity.lower() in {"critical", "high"}
            and self._is_explicit_lab_target(event)
            and classification != "insufficient_evidence"
        ):
            return self._require_authorization_review(result, event)
        return result

    @classmethod
    def _is_explicit_lab_target(cls, event: NormalizedEvent) -> bool:
        values: list[str] = []

        def collect(value: Any, depth: int = 0) -> None:
            if depth > 4:
                return
            if isinstance(value, dict):
                for item in value.values():
                    collect(item, depth + 1)
            elif isinstance(value, list):
                for item in value[:32]:
                    collect(item, depth + 1)
            elif isinstance(value, str):
                values.append(value.casefold())

        collect(event.entities)
        for item in event.evidence or []:
            if isinstance(item, dict):
                collect(item.get("value"))
        return any(marker in value for marker in cls._LAB_TARGET_MARKERS for value in values)

    def _require_authorization_review(
        self,
        llm_result: dict[str, Any],
        event: NormalizedEvent,
    ) -> dict[str, Any]:
        """Keep high-risk test telemetry actionable without leaking it into the verdict.

        Environment identity is a confidence boundary, not the analyst-facing
        conclusion.  Produce the review result from normalized evidence so a
        model cannot repeat that identity in the verdict, impact, or summary.
        """
        corrected = dict(llm_result)
        corrected["classification"] = "suspicious"
        corrected["confidence"] = min(
            self._normalize_confidence(corrected.get("confidence", 0.85)), 0.85
        )
        corrected["verdict"] = "【需人工复核】- 高危调用已触达，尚缺执行结果审计闭环"
        corrected["business_impact"] = (
            "尚未确认实际执行结果或影响范围；需结合应用和主机审计核实。"
        )
        corrected["analysis_dimensions"] = self._review_dimensions(
            event, corrected.get("analysis_dimensions")
        )
        corrected["reason"] = self._reason_from_dimensions(
            corrected["verdict"], corrected["analysis_dimensions"]
        )
        # A test-environment marker is never enough to tune away a high-risk
        # signal. Clear an overreaching model proposal before the result reaches
        # the action builder.
        corrected["whitelist_recommendation"] = {}
        missing = [
            str(item)
            for item in corrected.get("missing_evidence", []) or []
            if isinstance(item, str)
            and item.strip()
            and not self._contains_environment_reference(item)
        ]
        for item in (
            "来源身份与授权记录",
            "应用或主机审计中该请求的执行结果与副作用记录",
        ):
            if item not in missing:
                missing.append(item)
        corrected["missing_evidence"] = missing
        steps = [
            str(item)
            for item in corrected.get("recommended_next_steps", []) or []
            if isinstance(item, str)
            and item.strip()
            and not self._contains_environment_reference(item)
        ]
        review_step = "核对来源身份与授权记录，并关联应用/主机审计确认执行结果。"
        if review_step not in steps:
            steps.append(review_step)
        corrected["recommended_next_steps"] = steps
        return corrected

    def _review_dimensions(
        self,
        event: NormalizedEvent,
        source_dimensions: Any,
    ) -> list[dict[str, str]]:
        """Add one environment-boundary clue without discarding risk evidence."""
        if not isinstance(source_dimensions, list) or not source_dimensions:
            source_dimensions = self._synthesize_dimensions(event, "suspicious")
        dimensions: list[dict[str, str]] = []
        environment_added = False
        success_added = False
        for item in source_dimensions:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or "")
            if title == self._ENVIRONMENT_DIMENSION:
                continue
            if title == "成功与危害":
                dimensions.append(self._environment_dimension(event))
                environment_added = True
                success_added = True
                dimensions.append(
                    {
                        "title": "成功与危害",
                        "status": "review",
                        "evidence": "高危调用已触达；需以应用和主机审计确认实际执行结果及影响范围。",
                    }
                )
                continue
            dimensions.append(dict(item))
        if not environment_added:
            dimensions.append(self._environment_dimension(event))
        if not success_added:
            dimensions.append(
                {
                    "title": "成功与危害",
                    "status": "review",
                    "evidence": "高危调用已触达；需以应用和主机审计确认实际执行结果及影响范围。",
                }
            )
        return dimensions

    @classmethod
    def _lab_target_clues(cls, event: NormalizedEvent) -> list[str]:
        """Return concrete, bounded marker evidence for a suspected lab target."""
        values: list[tuple[str, str]] = []

        def collect(value: Any, source: str, depth: int = 0) -> None:
            if depth > 5:
                return
            if isinstance(value, dict):
                for key, item in value.items():
                    collect(item, f"{source}.{key}" if source else str(key), depth + 1)
            elif isinstance(value, list):
                for item in value[:32]:
                    collect(item, source, depth + 1)
            elif isinstance(value, str):
                values.append((source.casefold(), value.casefold()))

        collect(event.entities, "entities")
        for item in event.evidence or []:
            if not isinstance(item, dict):
                continue
            evidence_type = str(item.get("type") or "evidence")
            collect(item.get("value"), f"evidence.{evidence_type}")

        clues: list[str] = []
        for marker in cls._LAB_TARGET_MARKERS:
            matches = [source for source, value in values if marker in value]
            if not matches:
                continue
            is_request_location = any(
                token in source for source in matches for token in ("url", "path", "route")
            )
            location = "请求 URL/路径字段" if is_request_location else "应用或事件字段"
            clues.append(f"{location}命中 `{marker}`")
        for marker in cls._LAB_CODE_MARKERS:
            if any(marker in value for _, value in values):
                clues.append(f"调用栈或业务类名命中 `{marker}`")
        return clues

    def _environment_dimension(self, event: NormalizedEvent) -> dict[str, str]:
        clues = self._lab_target_clues(event)
        concrete = "；".join(clues) or "输入证据命中疑似测试目标命名"
        return {
            "title": self._ENVIRONMENT_DIMENSION,
            "status": "review",
            "evidence": (
                f"疑似靶场线索：{concrete}。上述命名与漏洞测试目标特征相符，"
                "因此仅作为疑似靶场判断依据；不能证明来源身份已获授权，"
                "也不能单独作为误报或真实攻击依据。"
            ),
        }

    def _contains_environment_reference(self, value: Any) -> bool:
        text = str(value or "").casefold()
        return any(term in text for term in self._ENVIRONMENT_REFERENCE_TERMS)

    def _summary(
        self,
        event: NormalizedEvent,
        classification: str,
        confidence: float,
        llm_result: dict[str, Any],
        explanation: dict[str, Any],
    ) -> str:
        """Keep environment-boundary reasoning in the detailed dimensions only."""
        compact_explanation = dict(explanation)
        compact_explanation["dimensions"] = [
            item
            for item in explanation.get("dimensions", []) or []
            if isinstance(item, dict)
            and str(item.get("title") or "") != self._ENVIRONMENT_DIMENSION
            and not self._contains_environment_reference(item.get("evidence"))
        ]
        return super()._summary(
            event, classification, confidence, llm_result, compact_explanation
        )
