from __future__ import annotations

import unittest
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "defensive_ai_gateway" / "static" / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "defensive_ai_gateway" / "static" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "defensive_ai_gateway" / "static" / "style.css").read_text(encoding="utf-8")
THEME_JS = (ROOT / "defensive_ai_gateway" / "static" / "theme-init.js").read_text(encoding="utf-8")
DETAIL_HTML = (ROOT / "defensive_ai_gateway" / "static" / "case-details.html").read_text(encoding="utf-8")
DETAIL_JS = (ROOT / "defensive_ai_gateway" / "static" / "case-details.js").read_text(encoding="utf-8")
LOGO_SVG = (ROOT / "defensive_ai_gateway" / "static" / "logo-mark.svg").read_text(encoding="utf-8")


class _ElementCollector(HTMLParser):
    VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[tuple[str, str]] = []
        self.elements: dict[str, dict] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        element_id = attributes.get("id") or ""
        if element_id:
            self.elements[element_id] = {
                "tag": tag,
                "attrs": attributes,
                "ancestors": [ancestor_id for _tag, ancestor_id in self.stack if ancestor_id],
            }
        if tag not in self.VOID_TAGS:
            self.stack.append((tag, element_id))

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                return


class DashboardQueueMetricTest(unittest.TestCase):
    def test_dashboard_uses_all_unfinished_alerts_and_refreshes_during_demo(self):
        self.assertIn("processing.unfinished", JS)
        self.assertIn('unfinishedAlertCount(processing)', JS)
        self.assertIn("const DASHBOARD_REFRESH_MS = 5000;", JS)
        self.assertIn("{queued} 等待，{inflight} 分析中", JS)
        self.assertIn('llmProvider === "gateway" && !Boolean(llmConfig?.api_key_set)', JS)
        self.assertIn("modelCredentialMissing", JS)
        self.assertIn("modelDurableRetry", JS)
        self.assertIn("processing?.llm_deferred?.total", JS)
        self.assertIn("modelDeferredBacklog", JS)
        self.assertEqual(JS.count("modelDeferredBacklog:"), 2)

    def test_dashboard_distributions_use_all_case_summary_not_the_list_page(self):
        dashboard = JS.split("async function loadDashboardRuntime(section = activeDashboardSection)", 1)[1].split(
            "async function loadCases", 1
        )[0]
        rendering = JS.split("function renderDashboard(", 1)[1].split("function statusLabel", 1)[0]
        self.assertIn('json("/api/cases/summary")', dashboard)
        self.assertIn("caseSummary", dashboard)
        self.assertIn("caseSummary?.total", rendering)
        self.assertIn("caseSummary?.products", rendering)
        self.assertIn("caseSummary?.classifications", rendering)
        self.assertNotIn("countBy(cases", rendering)


class ProductBrandingTest(unittest.TestCase):
    def test_dashboard_and_detail_page_publish_consistent_favicons(self):
        for document in (HTML, DETAIL_HTML):
            self.assertIn('rel="icon" href="/logo-mark.svg" type="image/svg+xml"', document)
            self.assertIn('rel="icon" href="/favicon.ico" sizes="any"', document)
            self.assertIn('href="/apple-touch-icon.png"', document)
        self.assertIn('class="brand-mark" src="/logo-mark.svg"', HTML)
        self.assertIn('viewBox="0 0 96 96"', LOGO_SVG)
        self.assertNotIn(">DG<", HTML)


class DeferredLlmReplayRenderingTest(unittest.TestCase):
    def test_operator_can_resume_only_durable_remote_model_work(self):
        self.assertIn('id="resume-llm-deferred"', HTML)
        self.assertIn("async function resumeDeferredLlmAlerts", JS)
        self.assertIn("/api/alerts/inbox/release-llm-deferred", JS)
        self.assertIn('applyPermission("#resume-llm-deferred", ["analyst"])', JS)
        self.assertEqual(JS.count("resumeDeferredAlerts:"), 2)
        self.assertEqual(JS.count("resumingDeferredAlerts:"), 2)
        self.assertEqual(JS.count("deferredAlertsReleased:"), 2)
        self.assertEqual(JS.count("deferredAlertsNeedRemoteModel:"), 2)


class GatewayModelDefaultRenderingTest(unittest.TestCase):
    def test_gateway_form_defaults_use_the_supported_http_responses_api(self):
        self.assertIn('gateway: "例如 gpt-5.5"', JS)
        self.assertIn('endpoint.value = "https://kkcoder.com/v1/responses";', JS)
        self.assertIn('model.value = "gpt-5.5";', JS)
        self.assertNotIn('endpoint.value = "https://kkcoder.com/v1/messages";', JS)


class WhitelistRecommendationRenderingTest(unittest.TestCase):
    def test_blank_recommendation_object_is_rendered_as_empty_state(self):
        self.assertIn("function hasMeaningfulWhitelistRecommendation", JS)
        self.assertIn("Object.values(value).some", JS)
        self.assertIn("hasMeaningfulWhitelistRecommendation(whitelist)", JS)
        self.assertNotIn("whitelist && Object.keys(whitelist).length", JS)


class FalsePositiveMemoryActionRenderingTest(unittest.TestCase):
    def test_triage_detail_groups_repeated_alerts_for_one_memory_confirmation(self):
        self.assertIn("function linkedAlertsBlock", JS)
        self.assertIn("${linkedAlertsBlock(linked, detail.alert_clusters || [])}", JS)
        self.assertIn("function alertClusterReviewCard", JS)
        self.assertIn("function confirmAlertClusterFalsePositive", JS)
        self.assertIn("/alert-clusters/${encodeURIComponent(clusterId)}/confirm-false-positive", JS)
        self.assertIn("确认该组为误报并写入一条长期记忆", JS)
        self.assertIn(".alert-cluster-item", CSS)


class ManualValidationReviewRenderingTest(unittest.TestCase):
    def test_prompt_injection_review_has_a_separate_audited_continuation_control(self):
        self.assertIn("function canContinueValidationReview", JS)
        self.assertIn("function manualReviewContinuation", JS)
        self.assertIn("prompt_injection_detected", JS)
        self.assertIn("manual_review_resolution", JS)
        self.assertIn("validation-review-continue", JS)
        self.assertIn(
            "/validation-reviews/${encodeURIComponent(validationId)}/continue",
            JS,
        )
        self.assertIn("function continueValidationReview", JS)
        self.assertIn("async function submitManualReviewContinuation", JS)
        self.assertIn("#manual-review-dialog", JS)
        self.assertIn('id="manual-review-dialog"', HTML)
        self.assertIn('id="manual-review-form"', HTML)
        manual_review_flow = JS[
            JS.index("function continueValidationReview") : JS.index("async function decideApproval")
        ]
        self.assertNotIn("window.prompt", manual_review_flow)
        self.assertIn("submitManualReviewContinuation", manual_review_flow)
        self.assertIn("manualReviewReasonPrompt:", JS)
        self.assertEqual(JS.count("manualReviewReasonPrompt:"), 2)
        self.assertIn(".manual-review-continuation", CSS)
        self.assertIn(".manual-review-resolution", CSS)
        self.assertIn(".manual-review-dialog", CSS)


class CaseApprovalPlanRenderingTest(unittest.TestCase):
    def test_only_latest_approval_round_is_expanded_and_history_is_collapsed(self):
        self.assertIn('function approvalBlock(approvals, caseId, latestEventId = "")', JS)
        self.assertIn("item.event_id === currentEventId", JS)
        self.assertIn("item.event_id !== currentEventId", JS)
        self.assertIn('<details class="approval-history">', JS)
        self.assertIn("approvalHistorySummary", JS)
        self.assertIn("latestRunRecord.event_id", JS)
        self.assertIn("function actionStageLabel", JS)
        self.assertIn('<ol class="action-list">', JS)
        self.assertIn(".approval-item.compact", CSS)
        self.assertIn(".action-step-head", CSS)


class PromptInjectionEvidenceRenderingTest(unittest.TestCase):
    def test_prompt_injection_finding_exposes_structured_clues_in_both_detail_surfaces(self):
        self.assertIn("function promptInjectionCluesBlock", JS)
        self.assertIn("evidence_clues", JS)
        self.assertIn("promptInjectionUntrustedInput", JS)
        self.assertIn("section=normalized-evidence", JS)
        self.assertIn("function promptInjectionCluesBlock", DETAIL_JS)
        self.assertIn("evidence_clues", DETAIL_JS)
        self.assertIn("injectionUntrustedInput", DETAIL_JS)
        self.assertIn(".prompt-injection-clues", CSS)
        self.assertIn(".prompt-injection-clue-list", CSS)


class FrontendSecondaryNavigationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        parser = _ElementCollector()
        parser.feed(HTML)
        cls.elements = parser.elements

    def test_memory_and_adapter_content_are_partitioned_into_requested_sections(self):
        expected_tabs = {
            "dashboard-tab-pending": ("dashboard", "pending", "dashboard-pending-panel", "dashboard-submenu"),
            "dashboard-tab-history": ("dashboard", "history", "dashboard-history-panel", "dashboard-submenu"),
            "memory-tab-inventory": ("memory", "inventory", "memory-inventory-panel", "memory-submenu"),
            "memory-tab-audit": ("memory", "audit", "memory-audit-panel", "memory-submenu"),
            "adapter-tab-intake": ("adapter", "intake", "adapter-intake-panel", "adapter-submenu"),
            "adapter-tab-config": ("adapter", "config", "adapter-config-panel", "adapter-submenu"),
            "automation-tab-tasks": ("automation", "tasks", "automation-tasks-panel", "automation-submenu"),
            "automation-tab-connectors": ("automation", "connectors", "automation-connectors-panel", "automation-submenu"),
            "automation-tab-policy": ("automation", "policy", "automation-policy-panel", "automation-submenu"),
        }
        for tab_id, (group, target, panel_id, submenu_id) in expected_tabs.items():
            with self.subTest(tab=tab_id):
                attrs = self.elements[tab_id]["attrs"]
                self.assertIn("nav-subbutton", attrs["class"])
                self.assertEqual(attrs["data-view"], group)
                self.assertEqual(attrs["data-secondary-group"], group)
                self.assertEqual(attrs["data-secondary-target"], target)
                self.assertEqual(attrs["aria-controls"], panel_id)
                self.assertIn(submenu_id, self.elements[tab_id]["ancestors"])
                self.assertIn("primary-navigation", self.elements[tab_id]["ancestors"])
                self.assertEqual(self.elements[panel_id]["attrs"]["aria-labelledby"], tab_id)

        self.assertEqual(self.elements["memory-submenu"]["attrs"]["role"], "group")
        self.assertEqual(self.elements["adapter-submenu"]["attrs"]["role"], "group")
        self.assertEqual(self.elements["dashboard-submenu"]["attrs"]["role"], "group")
        self.assertEqual(self.elements["automation-submenu"]["attrs"]["role"], "group")
        self.assertEqual(self.elements["dashboard-nav-parent"]["attrs"]["data-default-secondary"], "pending")
        self.assertEqual(self.elements["memory-nav-parent"]["attrs"]["data-default-secondary"], "inventory")
        self.assertEqual(self.elements["adapter-nav-parent"]["attrs"]["data-default-secondary"], "intake")
        self.assertEqual(self.elements["automation-nav-parent"]["attrs"]["data-default-secondary"], "tasks")
        self.assertNotIn("hidden", self.elements["memory-inventory-panel"]["attrs"])
        self.assertIn("hidden", self.elements["memory-audit-panel"]["attrs"])
        self.assertNotIn("hidden", self.elements["adapter-intake-panel"]["attrs"])
        self.assertIn("hidden", self.elements["adapter-config-panel"]["attrs"])
        self.assertNotIn("hidden", self.elements["automation-tasks-panel"]["attrs"])
        self.assertIn("hidden", self.elements["automation-connectors-panel"]["attrs"])
        self.assertIn("hidden", self.elements["automation-policy-panel"]["attrs"])
        self.assertNotIn('class="secondary-nav"', HTML)

        containment = {
            "case-search-form": "dashboard-pending-panel",
            "case-history-search-form": "dashboard-history-panel",
            "memory-total": "memory-inventory-panel",
            "memory-list": "memory-inventory-panel",
            "memory-detail": "memory-inventory-panel",
            "memory-audit-list": "memory-audit-panel",
            "syslog-config-table": "adapter-intake-panel",
            "syslog-deployment-form": "adapter-intake-panel",
            "syslog-deployment-targets": "adapter-intake-panel",
            "infer-form": "adapter-config-panel",
            "dry-run-form": "adapter-config-panel",
            "automation-task-list": "automation-tasks-panel",
            "automation-connector-form": "automation-connectors-panel",
            "automation-policy-form": "automation-policy-panel",
        }
        for element_id, panel_id in containment.items():
            with self.subTest(element=element_id):
                self.assertIn(panel_id, self.elements[element_id]["ancestors"])

    def test_navigation_supports_language_active_state_and_responsive_layout(self):
        for key in (
            "dashboardSecondaryNav",
            "dashboardSubPending",
            "dashboardSubHistory",
            "memorySecondaryNav",
            "memorySubInventory",
            "memorySubAudit",
            "adapterSecondaryNav",
            "adapterSubIntake",
            "adapterSubConfig",
            "automationSecondaryNav",
            "automationSubTasks",
            "automationSubConnectors",
            "automationSubPolicy",
        ):
            self.assertEqual(JS.count(f"{key}:"), 2)
        self.assertIn("function setSecondaryView", JS)
        self.assertIn("function loadViewData", JS)
        self.assertIn("function toggleLanguage()", JS)
        self.assertIn('saveLanguagePreference(currentLanguage === "en" ? "zh" : "en")', JS)
        self.assertIn('document.querySelector("#language-switch").addEventListener("click", () => {', JS)
        self.assertNotIn("event.currentTarget.dataset.languageValue", JS)
        self.assertIn('.nav-subbutton[data-secondary-group=', JS)
        self.assertIn('btn.setAttribute("aria-current", "page")', JS)
        self.assertIn(".nav-group.active .nav-subbutton.active", CSS)
        self.assertIn("grid-template-columns: repeat(2, minmax(0, 1fr))", CSS)

    def test_response_workbench_keeps_secrets_out_of_forms_and_separates_roles(self):
        self.assertIn('id="automation-view"', HTML)
        self.assertIn('id="automation-pagination"', HTML)
        self.assertIn('id="response-connector-secret-env"', HTML)
        connector_panel = HTML.split('id="automation-connectors-panel"', 1)[1].split(
            'id="automation-policy-panel"', 1
        )[0]
        self.assertNotIn('type="password"', connector_panel)
        self.assertIn("async function saveResponseConnector", JS)
        self.assertIn("async function runResponseTaskAction", JS)
        self.assertIn('applyPermission("[data-response-action]", ["responder"])', JS)
        self.assertIn('applyPermission("#automation-connector-form input', JS)
        self.assertIn("approvalAutomationPlan", JS)
        self.assertIn("result.response_task || result.approval.response_task", JS)
        self.assertIn("refreshCurrentView().catch", JS)
        self.assertIn(".approval-automation-plan", CSS)
        self.assertIn(".automation-task-item", CSS)

    def test_response_workbench_constrains_long_content_and_keeps_forms_aligned(self):
        for field_id in (
            "response-connector-name",
            "response-connector-endpoint",
            "response-connector-secret-env",
            "response-connector-mode",
        ):
            with self.subTest(field=field_id):
                label_markup = HTML.split(f'id="{field_id}"', 1)[0].rsplit("<label", 1)[-1]
                self.assertIn('class="automation-field-wide"', label_markup)
        self.assertIn(".automation-config-grid > .panel {\n  margin-top: 0;", CSS)
        self.assertIn(".automation-task-head > .field-status {", CSS)
        self.assertIn("max-width: min(42%, 180px);", CSS)
        self.assertIn(".automation-mono {", CSS)
        self.assertIn("word-break: break-word;", CSS)
        self.assertIn("@media (max-width: 900px)", CSS)
        self.assertIn("function connectorHealthLabel(status)", JS)
        self.assertIn("function responseActionLabel(actionType)", JS)
        self.assertIn('{ "network.block_ip": "responseActionBlockSourceIp" }', JS)
        self.assertIn("grid-template-columns: minmax(220px, 280px) max-content;", CSS)
        self.assertIn(".automation-filter-form > button {\n  align-self: end;", CSS)
        self.assertIn("height: 38px;\n  min-height: 38px;", CSS)

    def test_mapping_confirmation_uses_a_full_width_workspace_row(self):
        self.assertIn("mapping-result-panel", self.elements["field-mapping-table"]["ancestors"])
        self.assertIn("adapter-config-panel", self.elements["field-mapping-table"]["ancestors"])
        self.assertIn('id="mapping-result-panel" class="panel mapping-result-panel"', HTML)
        self.assertIn(".mapping-result-panel {\n  grid-column: 1 / -1;", CSS)
        self.assertIn(".field-mapping-table table {\n  width: 100%;\n  min-width: 0;", CSS)
        self.assertIn("fieldConfirmation:", JS)
        self.assertEqual(JS.count("fieldConfirmationHint:"), 2)

    def test_syslog_deployment_module_keeps_credentials_out_of_the_browser(self):
        self.assertIn('id="syslog-deployment-form"', HTML)
        self.assertIn('id="syslog-collector-address"', HTML)
        self.assertIn('id="syslog-source-cidrs"', HTML)
        self.assertIn('id="export-syslog-deployment"', HTML)
        self.assertIn("async function loadSyslogDeployment", JS)
        self.assertIn('json("/api/config/syslog/deployment")', JS)
        self.assertIn('json("/api/config/syslog/deployment", {', JS)
        self.assertIn("DEFENSIVE_AI_SYSLOG_SOURCE_CIDRS=${sourceCidrs.join(\",\")}", JS)
        self.assertIn('anchor.download = "defensive-ai-syslog-console.env"', JS)
        self.assertNotIn("ingest_token", JS)
        self.assertIn(".syslog-deployment-panel", CSS)
        self.assertIn(".syslog-deployment-targets", CSS)

    def test_frontend_operability_guards_are_present(self):
        self.assertIn("const pagination = casePagination[section]", JS)
        self.assertIn('offset: String((pagination.page - 1) * pagination.size)', JS)
        self.assertIn('if (section === "pending") params.set("active_only", "1");', JS)
        self.assertIn('else params.set("terminal_only", "1");', JS)
        self.assertIn("case-filter-from", HTML)
        self.assertIn("history-case-filter-from", HTML)
        self.assertIn("function setPendingCaseSearchCurrentMonth(now = new Date())", JS)
        self.assertIn("new Date(now.getFullYear(), now.getMonth(), 1, 0, 0, 0, 0)", JS)
        self.assertIn("new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 0, 0)", JS)
        self.assertEqual(JS.count("setPendingCaseSearchCurrentMonth();"), 2)
        self.assertIn("async function loadMemoryInventory", JS)
        self.assertIn("async function loadMemoryAudit", JS)
        self.assertIn("Promise.allSettled", JS)
        self.assertIn('setSecondaryView("memory", "inventory")', JS)
        self.assertIn("await loadMemoryInventory({ skipSelection: true })", JS)
        self.assertIn('json("/api/health", { acceptStatuses: [503] })', JS)
        self.assertIn("function refreshCurrentView", JS)
        self.assertIn("const controller = new AbortController()", JS)
        self.assertIn("controller.abort()", JS)
        self.assertIn('currentSession = { actor: "", roles: [] }', JS)
        self.assertIn("await loadSession()", JS)
        self.assertIn('applyPermission(".case-disposition-button", ["analyst"])', JS)
        self.assertIn('applyPermission(".approval-decision", ["approver"])', JS)
        self.assertIn('applyPermission("[data-memory-action]", ["memory"])', JS)
        self.assertIn('applyPermission("#llm-form input, #llm-form select, #llm-form button", ["config"])', JS)
        self.assertIn("let memorySelectionRequestId = 0", JS)
        self.assertIn("requestId !== memorySelectionRequestId", JS)
        self.assertIn("const memoryId = button.dataset.memoryId", JS)
        self.assertIn("encodeURIComponent(memoryId)", JS)
        self.assertIn("填入默认值", HTML)
        self.assertIn("后端配置尚未改变", JS)
        for product in ("waf", "hips", "ndr", "rasp", "siem"):
            self.assertIn(f'profile: "auto-{product}-json"', JS)

    def test_role_scoped_loading_keeps_dashboard_independent_of_config_access(self):
        self.assertIn('return hasAnyRole("read", "analyst", "approver")', JS)
        self.assertIn('return hasAnyRole("config")', JS)
        self.assertIn('return hasAnyRole("read", "config", "analyst")', JS)

        dashboard = JS.split("async function loadDashboardRuntime(section = activeDashboardSection)", 1)[1].split(
            "async function loadCases", 1
        )[0]
        self.assertIn("canReadCases() ? json(`/api/cases?${caseQuery}`)", dashboard)
        self.assertIn("Promise.resolve({ cases: [] })", dashboard)
        self.assertIn('json("/api/config/llm").catch(() => llmFallback)', dashboard)
        self.assertIn('json("/api/config/syslog").catch(() => syslogFallback)', dashboard)
        self.assertIn("Promise.resolve(llmFallback)", dashboard)
        self.assertIn("Promise.resolve(syslogFallback)", dashboard)

        bootstrap = JS.split("async function loadApplicationData()", 1)[1].split(
            'document.querySelector("#auth-session")', 1
        )[0]
        self.assertIn("await loadSession()", bootstrap)
        self.assertIn("if (canReadRuntimeConfig())", bootstrap)
        self.assertIn("tasks.push(loadLlmConfig(), loadSyslogConfig(), loadSyslogDeployment())", bootstrap)
        self.assertIn("if (canReadMappingProfiles())", bootstrap)
        self.assertIn("tasks.push(loadMappingProfiles())", bootstrap)
        self.assertNotIn("return Promise.all([", bootstrap)

        view_loader = JS.split("function loadViewData(name)", 1)[1].split(
            "function refreshCurrentView", 1
        )[0]
        self.assertIn('if (!canReadRuntimeConfig()) return Promise.resolve();', view_loader)
        self.assertIn('const tasks = [];', view_loader)

    def test_theme_bootstrap_is_external_for_strict_csp(self):
        self.assertIn('<script src="/theme-init.js"></script>', HTML)
        self.assertNotIn("localStorage.getItem(key)", HTML)
        self.assertIn('localStorage.getItem(key)', THEME_JS)
        self.assertIn('document.documentElement.dataset.theme = theme', THEME_JS)

    def test_alert_triage_drills_from_queue_to_vertical_disposition_page(self):
        self.assertIn("cases-list", self.elements)
        self.assertIn("dashboard-view", self.elements["cases-list"]["ancestors"])
        self.assertIn("dashboard-view", self.elements["processed-cases-list"]["ancestors"])
        self.assertIn("case-detail", self.elements)
        self.assertIn("triage-view", self.elements["case-detail"]["ancestors"])
        self.assertIn("triage-back", self.elements)

        dashboard = HTML.split('<section id="dashboard-view"', 1)[1].split(
            '<section id="triage-view"', 1
        )[0]
        self.assertNotIn('id="case-detail"', dashboard)
        self.assertNotIn('class="triage-workbench"', HTML)
        self.assertNotIn('class="queue-filter-tabs"', HTML)
        self.assertIn('id="case-search-form"', HTML)
        self.assertIn('id="case-history-search-form"', HTML)
        for pagination_id in (
            "cases-pagination",
            "processed-cases-pagination",
            "memory-pagination",
            "memory-audit-pagination",
        ):
            self.assertIn(f'id="{pagination_id}"', HTML)
        self.assertIn('data-case-search-section="pending"', HTML)
        self.assertIn('data-case-search-section="history"', HTML)
        self.assertIn("function openCaseTriage", JS)
        self.assertIn("function loadTriageCase", JS)
        self.assertIn("function pendingQueueCases", JS)
        self.assertIn("function processedQueueCases", JS)
        self.assertIn("function renderProcessedList", JS)
        self.assertIn("function renderPagination", JS)
        self.assertIn("PAGE_SIZE_OPTIONS = [10, 20, 50, 100]", JS)
        self.assertIn('id="memory-associations-view"', HTML)
        self.assertIn('id="memory-associations-page-list"', HTML)
        self.assertIn('id="memory-associations-page-pagination"', HTML)
        self.assertIn('if (key === "memory-associations")', JS)
        self.assertIn("/api/memory/matches?", JS)
        self.assertIn('setView("memory-associations")', JS)
        self.assertIn("function openMemoryAssociations", JS)
        self.assertIn('data-memory-associations-id=', JS)
        self.assertNotIn('id="memory-association-results"', JS)
        self.assertNotIn("matches.slice(0, 50)", JS)
        self.assertIn('params.set("terminal_only", "1")', JS)
        self.assertIn('data-pagination-size=', JS)
        self.assertIn('data-pagination-action="previous"', JS)
        self.assertIn('data-pagination-action="next"', JS)
        self.assertIn("function caseFocusSummary", JS)
        self.assertIn("RASP_RISK_LABELS", JS)
        self.assertIn("OGNL 表达式注入", JS)
        self.assertIn('join(" → ")', JS)
        self.assertNotIn("敏感调用已触达，执行结果待确认", JS)
        self.assertIn("caseFocusSummary(item)", JS)
        self.assertIn("caseFocusSummary(detail)", JS)
        self.assertIn("let activeDashboardSection =", JS)
        self.assertIn('setView("triage")', JS)
        self.assertIn('data-detail-section="${escapeHtml(section)}"', JS)
        self.assertNotIn(".triage-workbench", CSS)
        self.assertNotIn(".triage-detail-panel", CSS)
        self.assertIn(".detail-stack", CSS)
        self.assertIn("grid-template-columns: 1fr", CSS)

    def test_detailed_information_uses_dedicated_page_and_scoped_api(self):
        self.assertIn('src="/case-details.js"', DETAIL_HTML)
        self.assertIn('id="case-details-content"', DETAIL_HTML)
        for section in ("raw-alerts", "normalized-evidence", "analysis-runs"):
            self.assertIn(section, JS)
            self.assertIn(section, DETAIL_JS)
        self.assertIn("/api/cases/${encodeURIComponent(caseId)}/details/${encodeURIComponent(section)}", DETAIL_JS)
        self.assertIn("sessionStorage.getItem(API_TOKEN_KEY)", DETAIL_JS)
        self.assertIn("const DETAIL_PAGE_SIZE = 5;", DETAIL_JS)
        self.assertIn("bindLazyRecordPayloads(records)", DETAIL_JS)
        self.assertIn("data-json-payload", DETAIL_JS)
        self.assertNotIn('class="json-details" open', DETAIL_JS)

    def test_memory_associations_use_contextual_page_without_resetting_governance_form(self):
        detail_renderer = JS.split("function renderMemoryDetail(memory)", 1)[1].split(
            "function renderMemoryAudit", 1
        )[0]
        self.assertIn("governance.association_count", detail_renderer)
        self.assertIn("data-memory-associations-id", detail_renderer)
        self.assertNotIn("renderMemoryAssociations(", detail_renderer)

        association_loader = JS.split("async function loadMemoryAssociations", 1)[1].split(
            "async function openMemoryAssociations", 1
        )[0]
        self.assertIn("memory_id: memoryId", association_loader)
        self.assertIn("limit: String(memoryAssociationPagination.size)", association_loader)
        self.assertIn("offset: String((memoryAssociationPagination.page - 1)", association_loader)
        self.assertIn("page.pagination", association_loader)

        back_handler = JS.split(
            'document.querySelector("#memory-associations-back").addEventListener', 1
        )[1].split(
            'document.querySelector("#memory-associations-refresh")', 1
        )[0]
        self.assertIn('setView("memory")', back_handler)
        self.assertIn('setSecondaryView("memory", "inventory")', back_handler)
        self.assertNotIn("selectMemory", back_handler)
        self.assertNotIn("loadMemory", back_handler)
        self.assertIn("case-details-pagination", DETAIL_JS)
        self.assertIn(".case-details-pagination", CSS)

    def test_ollama_model_picker_refreshes_current_model_list(self):
        self.assertNotIn("gemma3", HTML)
        self.assertNotIn("gemma3", JS)
        self.assertIn("请选择已同步的 Ollama 模型", HTML)
        self.assertIn("const OLLAMA_MODEL_REFRESH_MS = 15000;", JS)
        self.assertIn("function startOllamaModelRefresh()", JS)
        self.assertIn("function stopOllamaModelRefresh()", JS)
        self.assertIn('document.querySelector("#llm-model").addEventListener("focus"', JS)
        self.assertIn('cache: "no-store"', JS)
        self.assertIn("ollamaModelLoadRequestId", JS)
        self.assertIn("startOllamaModelRefresh();", JS)
        self.assertIn("stopOllamaModelRefresh();", JS)


if __name__ == "__main__":
    unittest.main()
