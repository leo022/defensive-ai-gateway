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
    def test_dashboard_status_panels_share_an_alignment_contract(self):
        self.assertEqual(HTML.count("dashboard-status-panel"), 2)
        self.assertIn("dashboard-status-panel health-panel", HTML)
        self.assertIn("dashboard-status-panel intake-panel", HTML)
        self.assertIn("grid-template-rows: 88px minmax(0, 1fr);", CSS)
        self.assertIn(".dashboard-status-panel .panel-heading {", CSS)
        self.assertIn("white-space: nowrap;", CSS)
        self.assertGreater(CSS.rfind(".dashboard-grid > .panel {"), CSS.rfind(".panel + .panel,"))
        self.assertIn(".dashboard-status-panel .health-checks", CSS)
        self.assertIn(".dashboard-status-panel .intake-health", CSS)

    def test_dashboard_uses_all_unfinished_alerts_and_refreshes_during_demo(self):
        self.assertIn("processing.unfinished", JS)
        self.assertIn('unfinishedAlertCount(processing)', JS)
        self.assertIn("const DASHBOARD_REFRESH_MS = 10_000;", JS)
        self.assertIn("{queued} 等待，{inflight} 分析中", JS)
        self.assertIn('llmProvider === "gateway" && !Boolean(llmConfig?.api_key_set)', JS)
        self.assertIn("modelCredentialMissing", JS)
        self.assertIn("modelDurableRetry", JS)
        self.assertIn("processing?.llm_deferred?.total", JS)
        self.assertIn("modelDeferredBacklog", JS)
        self.assertEqual(JS.count("modelDeferredBacklog:"), 2)

    def test_dashboard_distributions_use_all_case_summary_not_the_list_page(self):
        dashboard = JS.split("async function loadDashboardRuntime({ refreshConfig = true } = {})", 1)[1].split(
            "async function loadCases", 1
        )[0]
        rendering = JS.split("function renderDashboard(", 1)[1].split("function statusLabel", 1)[0]
        self.assertIn('json("/api/dashboard/snapshot", { acceptStatuses: [503] })', dashboard)
        self.assertIn("snapshot.case_summary", dashboard)
        self.assertIn("caseSummary", dashboard)
        self.assertIn("caseSummary?.total", rendering)
        self.assertIn("caseSummary?.products", rendering)
        self.assertIn("caseSummary?.classifications", rendering)
        self.assertNotIn("countBy(cases", rendering)

    def test_dashboard_refresh_is_completion_scheduled_hidden_aware_and_single_flight(self):
        scheduler = JS.split("function scheduleDashboardRefresh", 1)[1].split(
            "function distributionRows", 1
        )[0]
        monitor_loader = JS.split("async function loadMonitorDashboard", 1)[1].split(
            "async function loadCases", 1
        )[0]
        self.assertIn("window.setTimeout", scheduler)
        self.assertNotIn("window.setInterval", scheduler)
        self.assertIn("document.hidden", scheduler)
        self.assertIn("loadMonitorDashboard({ refreshConfig: false })", scheduler)
        self.assertNotIn("loadCases", scheduler)
        self.assertIn("if (dashboardRefreshPromise) return dashboardRefreshPromise", monitor_loader)
        self.assertIn("dashboardRefreshPromise = request", monitor_loader)
        self.assertIn("if (dashboardRefreshPromise === request) dashboardRefreshPromise = null", monitor_loader)

    def test_unchanged_dashboard_and_case_content_does_not_replace_dom(self):
        self.assertIn("const renderedMarkup = new WeakMap();", JS)
        self.assertIn("renderedMarkup.get(node) === markup", JS)
        self.assertIn("const caseListRenderKeys = { pending: \"\", history: \"\" };", JS)
        self.assertIn("if (caseListRenderKeys[section] === renderKey) return;", JS)

    def test_page_loading_is_single_flight_and_preserves_rendered_content(self):
        request_layer = JS.split("function json(url, options)", 1)[1].split(
            "function showAuthDialog", 1
        )[0]
        self.assertIn("const inflightGetRequests = new Map();", JS)
        self.assertIn('method === "GET"', request_layer)
        self.assertIn("if (inflightGetRequests.has(key)) return inflightGetRequests.get(key)", request_layer)
        self.assertIn("inflightGetRequests.delete(key)", request_layer)
        self.assertIn("function executeJsonRequest", request_layer)

        view_loader = JS.split("function loadViewData(name)", 1)[1].split(
            "function loadViewDataOnce", 1
        )[0]
        self.assertIn("const viewLoadPromises = new Map();", JS)
        self.assertIn("if (viewLoadPromises.has(key)) return viewLoadPromises.get(key)", view_loader)
        self.assertIn("viewLoadPromises.delete(key)", view_loader)

        self.assertIn("!memoryInventoryLoaded", JS)
        self.assertIn("!memoryAuditLoaded", JS)
        self.assertIn("!responseTasksLoaded", JS)
        self.assertIn("!playbookWorkspaceLoaded", JS)
        self.assertIn("requestId !== memoryInventoryRequestId", JS)
        self.assertIn("requestId !== memoryAuditRequestId", JS)
        self.assertIn("requestId !== responseTasksRequestId", JS)
        self.assertIn("requestId !== playbookWorkspaceRequestId", JS)

    def test_case_detail_uses_prefetch_single_flight_and_precise_invalidation(self):
        case_loader = JS.split("function renderCasePreview", 1)[1].split(
            "function requestedCaseNavigation", 1
        )[0]
        cases_loader = JS.split("async function loadCases(options = {})", 1)[1].split(
            "function setConfigStatus", 1
        )[0]
        self.assertIn("const caseDetailRequests = new Map();", JS)
        self.assertIn("const caseDetailVersions = new Map();", JS)
        self.assertIn("function requestCaseDetail", case_loader)
        self.assertIn("active?.version === version", case_loader)
        self.assertIn("function invalidateChangedCaseDetails", case_loader)
        self.assertIn("item.updated_at_ms", case_loader)
        self.assertIn("renderCasePreview(preview)", case_loader)
        self.assertIn('addEventListener("pointerenter"', JS)
        self.assertIn('addEventListener("pointerleave"', JS)
        self.assertIn("window.setTimeout(() => prefetchCaseTriage(item.case_id), 120)", JS)
        self.assertIn('addEventListener("focus"', JS)
        self.assertIn("function refreshCaseWorkspace", case_loader)
        self.assertIn("await Promise.all", case_loader)
        self.assertIn("invalidateChangedCaseDetails(cases)", cases_loader)
        self.assertIn("requestId !== caseListRequestIds[section]", cases_loader)
        self.assertNotIn("detailCache.clear()", JS)
        self.assertNotIn("await loadCases();\n    await loadTriageCase(caseId);", JS)


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

    def test_provisional_case_states_are_explicit_and_not_disposable(self):
        self.assertEqual(JS.count("caseStatusAnalyzing:"), 2)
        self.assertEqual(JS.count("caseStatusAnalysisDeferred:"), 2)
        self.assertEqual(JS.count("caseStatusAnalysisFailed:"), 2)
        self.assertIn("function isProvisionalCaseStatus", JS)
        self.assertIn("function caseAnalysisStateText", JS)
        self.assertIn("if (isProvisionalCaseStatus(status))", JS)
        self.assertIn("classificationPendingAnalysis", JS)
        self.assertIn(".case-status.analyzing", CSS)
        self.assertIn(".case-status.analysis-deferred", CSS)
        self.assertIn(".case-status.analysis-failed", CSS)


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
        self.assertIn("function uniqueLinkedAlerts", JS)
        self.assertIn("function uniqueLinkedAlertCount", JS)
        self.assertIn("uniqueLinkedAlerts(linked).map(linkedAlertReviewCard)", JS)
        self.assertIn("const linkedAlertCount = uniqueLinkedAlertCount(linked);", JS)
        self.assertIn("function confirmAlertClusterFalsePositive", JS)
        self.assertIn("/alert-clusters/${encodeURIComponent(clusterId)}/confirm-false-positive", JS)
        self.assertIn("确认该组为误报并写入一条长期记忆", JS)
        self.assertIn(".alert-cluster-item", CSS)
        self.assertIn('clusterRepeatedAlerts: "同类告警 {count} 条"', JS)
        self.assertNotIn("同类重复", JS)
        self.assertNotIn("similar repeated", JS)


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
        self.assertIn(".approval-item.compact", CSS)


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
            "automation-tab-playbooks": ("automation", "playbooks", "automation-playbooks-panel", "automation-submenu"),
            "automation-tab-connectors": ("automation", "connectors", "automation-connectors-panel", "automation-submenu"),
            "automation-tab-policy": ("automation", "policy", "automation-policy-panel", "automation-submenu"),
            "settings-tab-model": ("settings", "model", "settings-model-panel", "settings-submenu"),
            "settings-tab-harness": ("settings", "harness", "settings-harness-panel", "settings-submenu"),
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
        self.assertEqual(self.elements["settings-submenu"]["attrs"]["role"], "group")
        self.assertEqual(self.elements["dashboard-nav-parent"]["attrs"]["data-default-secondary"], "pending")
        self.assertEqual(self.elements["memory-nav-parent"]["attrs"]["data-default-secondary"], "inventory")
        self.assertEqual(self.elements["adapter-nav-parent"]["attrs"]["data-default-secondary"], "intake")
        self.assertEqual(self.elements["automation-nav-parent"]["attrs"]["data-default-secondary"], "tasks")
        self.assertEqual(self.elements["settings-nav-parent"]["attrs"]["data-default-secondary"], "model")
        self.assertNotIn("hidden", self.elements["memory-inventory-panel"]["attrs"])
        self.assertIn("hidden", self.elements["memory-audit-panel"]["attrs"])
        self.assertNotIn("hidden", self.elements["adapter-intake-panel"]["attrs"])
        self.assertIn("hidden", self.elements["adapter-config-panel"]["attrs"])
        self.assertNotIn("hidden", self.elements["automation-tasks-panel"]["attrs"])
        self.assertIn("hidden", self.elements["automation-playbooks-panel"]["attrs"])
        self.assertIn("hidden", self.elements["automation-connectors-panel"]["attrs"])
        self.assertIn("hidden", self.elements["automation-policy-panel"]["attrs"])
        self.assertNotIn("hidden", self.elements["settings-model-panel"]["attrs"])
        self.assertIn("hidden", self.elements["settings-harness-panel"]["attrs"])
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
            "automation-playbook-form": "automation-playbooks-panel",
            "automation-playbook-list": "automation-playbooks-panel",
            "automation-shadow-list": "automation-playbooks-panel",
            "automation-connector-form": "automation-connectors-panel",
            "automation-policy-form": "automation-policy-panel",
            "llm-form": "settings-model-panel",
            "harness-profile-form": "settings-harness-panel",
            "harness-version-list": "settings-harness-panel",
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
            "automationSubPlaybooks",
            "automationSubConnectors",
            "automationSubPolicy",
            "settingsSecondaryNav",
            "settingsSubModel",
            "settingsSubHarness",
        ):
            self.assertEqual(JS.count(f"{key}:"), 2)
        self.assertIn("function setSecondaryView", JS)
        self.assertIn("function keepActiveNavigationVisible()", JS)
        self.assertIn("function loadViewData", JS)
        self.assertIn("function toggleLanguage()", JS)
        self.assertIn('saveLanguagePreference(currentLanguage === "en" ? "zh" : "en")', JS)
        self.assertIn('document.querySelector("#language-switch").addEventListener("click", () => {', JS)
        self.assertNotIn("event.currentTarget.dataset.languageValue", JS)
        self.assertIn('.nav-subbutton[data-secondary-group=', JS)
        self.assertIn('btn.setAttribute("aria-current", "page")', JS)
        navigation_visibility = JS.split(
            "function keepActiveNavigationVisible()", 1
        )[1].split("function applyLanguage()", 1)[0]
        for rule in (
            'document.querySelector(\'.nav-subbutton[aria-current="page"]\')',
            "window.requestAnimationFrame",
            "navigation.scrollWidth <= navigation.clientWidth",
            "navigation.scrollLeft -=",
            "navigation.scrollLeft +=",
        ):
            with self.subTest(navigation_rule=rule):
                self.assertIn(rule, navigation_visibility)
        self.assertIn(
            'window.addEventListener("resize", keepActiveNavigationVisible);',
            JS,
        )
        self.assertIn(".nav-group.active .nav-subbutton.active", CSS)
        self.assertIn("grid-template-columns: repeat(2, minmax(0, 1fr))", CSS)
        self.assertIn('workspaceEyebrow: "安全运营"', JS)
        self.assertIn('dashboardEyebrow: "安全运营实时概览"', JS)
        self.assertIn('languageAria: "切换到英文"', JS)
        self.assertIn('languageAria: "Switch to Chinese"', JS)
        self.assertEqual(JS.count("footer:"), 2)
        self.assertIn('data-i18n="footer"', HTML)

    def test_agent_harness_uses_versioned_governed_configuration(self):
        for field_id in (
            "harness-max-turns",
            "harness-max-tool-calls",
            "harness-max-wall-seconds",
            "harness-tool-result-bytes",
            "harness-correlation-window",
            "harness-scan-limit",
            "harness-scan-bytes",
            "harness-raw-chunk-bytes",
            "harness-approval-quorum",
        ):
            self.assertIn(field_id, self.elements)
        self.assertIn('json("/api/config/agent-harness")', JS)
        self.assertIn('json("/api/config/agent-harness", {', JS)
        self.assertIn("/api/config/agent-harness/${encodeURIComponent(version)}/publish", JS)
        self.assertIn("function renderAgentHarness", JS)
        self.assertEqual(JS.count("harnessActiveScope:"), 2)
        self.assertIn('applyPermission("[data-harness-publish]", ["config"])', JS)
        self.assertEqual(JS.count("harnessControlNoExecution:"), 2)
        self.assertIn(".harness-governance-layout", CSS)

    def test_triage_mobile_layout_compacts_navigation_and_prevents_control_overflow(self):
        set_view = JS.split("function setView(name)", 1)[1].split(
            "function updateTriageBackLabel", 1
        )[0]
        self.assertIn("document.body.dataset.activeView = name", set_view)

        mobile = CSS.split("@media (max-width: 720px)", 1)[1].split(
            "@media (max-width: 900px)", 1
        )[0]
        for rule in (
            ".nav-group:not(.active) .nav-submenu",
            "overflow-x: auto;",
            "min-width: 0;",
            'body[data-active-view="triage"] .workspace-header > div:first-child',
            ".case-detail-heading h3",
            "overflow-wrap: anywhere;",
            ".case-disposition-actions,",
            ".approval-actions",
            "grid-template-columns: repeat(2, minmax(0, 1fr));",
            "min-height: 44px;",
            ".prompt-injection-clue dl > div",
            ".validation-gate .plain-list li",
            ".linked-alert-item > .section-title",
        ):
            with self.subTest(rule=rule):
                self.assertIn(rule, mobile)
        self.assertIn("width: fit-content;", mobile)

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
        self.assertIn("grid-template-columns: repeat(4, minmax(150px, 1fr)) max-content;", CSS)
        self.assertIn(".automation-filter-form > button {\n  align-self: end;", CSS)
        self.assertIn("height: 38px;\n  min-height: 38px;", CSS)

    def test_grid_managed_panels_share_the_final_alignment_contract(self):
        for layout_class in (
            "dashboard-grid",
            "memory-workbench",
            "automation-playbook-grid",
            "automation-config-grid",
            "adapter-grid",
        ):
            with self.subTest(layout=layout_class):
                self.assertIn(f'class="{layout_class} panel-grid"', HTML)

        self.assertIn(
            'class="harness-governance-layout panel-grid panel-grid-offset"',
            HTML,
        )
        self.assertIn(
            ".panel-grid > .panel {\n  min-width: 0;\n  margin-top: 0;",
            CSS,
        )
        self.assertIn(
            ".panel-grid.panel-grid-offset > .panel {\n  margin-top: 12px;",
            CSS,
        )
        self.assertGreater(
            CSS.rfind(".panel-grid > .panel {"),
            CSS.rfind(".panel + .panel,\n.panel {"),
        )

    def test_response_p0_operations_playbook_and_shadow_contract(self):
        for field_id in (
            "automation-priority-filter",
            "automation-assignee-filter",
            "automation-sla-filter",
            "response-playbook-name",
            "response-playbook-owner",
            "response-playbook-products",
            "response-playbook-risk",
            "response-playbook-sla",
        ):
            with self.subTest(field=field_id):
                self.assertIn(field_id, self.elements)
        for function_name in (
            "saveTaskOperations",
            "renderResponsePlaybooks",
            "saveResponsePlaybook",
            "renderShadowEvaluations",
            "decideShadowEvaluation",
            "loadPlaybookWorkspace",
        ):
            self.assertIn(f"function {function_name}", JS)
        self.assertIn('applyPermission("[data-task-operations]", ["responder"])', JS)
        self.assertIn('applyPermission("[data-playbook-action]", ["config"])', JS)
        self.assertIn('applyPermission("[data-shadow-decision]", ["analyst", "responder"])', JS)
        self.assertIn('data-i18n="playbookResetForm"', HTML)
        self.assertIn('playbookResetForm: "重置表单"', JS)
        self.assertIn('playbookResetForm: "Reset form"', JS)
        self.assertIn(".automation-operations-form", CSS)
        self.assertIn(".automation-playbook-grid", CSS)
        self.assertIn(".automation-shadow-decision", CSS)

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
        self.assertIn("const PENDING_CASE_DEFAULT_WINDOW_MS = 14 * 24 * 60 * 60 * 1000", JS)
        self.assertIn("function setPendingCaseSearchRecentTwoWeeks(now = new Date())", JS)
        self.assertIn("const rangeEnd = new Date(now.getTime())", JS)
        self.assertIn("rangeEnd.setSeconds(0, 0)", JS)
        self.assertIn(
            "const rangeStart = new Date(rangeEnd.getTime() - PENDING_CASE_DEFAULT_WINDOW_MS)",
            JS,
        )
        self.assertEqual(JS.count("setPendingCaseSearchRecentTwoWeeks();"), 2)
        self.assertNotIn("setPendingCaseSearchCurrentMonth", JS)
        self.assertIn("async function loadMemoryInventory", JS)
        self.assertIn("async function loadMemoryAudit", JS)
        self.assertIn("Promise.allSettled", JS)
        self.assertIn('setSecondaryView("memory", "inventory")', JS)
        self.assertIn("await loadMemoryInventory({ skipSelection: true })", JS)
        self.assertIn('json("/api/dashboard/snapshot", { acceptStatuses: [503] })', JS)
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

        dashboard = JS.split("async function loadDashboardRuntime({ refreshConfig = true } = {})", 1)[1].split(
            "async function loadCases", 1
        )[0]
        self.assertIn('json("/api/dashboard/snapshot", { acceptStatuses: [503] })', dashboard)
        self.assertNotIn('json("/api/cases/summary")', dashboard)
        self.assertIn('json("/api/config/llm").catch(() => dashboardLlmConfig)', dashboard)
        self.assertIn('json("/api/config/syslog").catch(() => dashboardSyslogPayload)', dashboard)
        self.assertIn("Promise.resolve(llmFallback)", dashboard)
        self.assertIn("Promise.resolve(syslogFallback)", dashboard)

        cases_loader = JS.split("async function loadCases(options = {})", 1)[1].split(
            "function setConfigStatus", 1
        )[0]
        self.assertIn("await json(`/api/cases?${caseQuery}`)", cases_loader)
        self.assertIn("{ cases: [], pagination: {} }", cases_loader)
        self.assertNotIn('json("/api/health"', cases_loader)
        self.assertNotIn('json("/api/cases/summary")', cases_loader)

        bootstrap = JS.split("async function loadApplicationData()", 1)[1].split(
            'document.querySelector("#auth-session")', 1
        )[0]
        self.assertIn("await loadSession()", bootstrap)
        self.assertIn("loadMonitorDashboard({ refreshConfig: true })", bootstrap)
        self.assertNotIn("loadSampleLog", bootstrap)
        self.assertNotIn("loadLlmConfig", bootstrap)
        self.assertNotIn("loadSyslogDeployment", bootstrap)
        self.assertNotIn("loadMappingProfiles", bootstrap)

        view_loader = JS.split("function loadViewDataOnce(name)", 1)[1].split(
            "function refreshCurrentView", 1
        )[0]
        self.assertIn('if (!canReadRuntimeConfig()) return Promise.resolve();', view_loader)
        self.assertIn('const tasks = [];', view_loader)

    def test_theme_bootstrap_is_external_for_strict_csp(self):
        self.assertIn('<script src="/theme-init.js"></script>', HTML)
        self.assertNotIn("localStorage.getItem(key)", HTML)
        self.assertIn('localStorage.getItem(key)', THEME_JS)
        self.assertIn('const theme = stored === "dark" ? "dark" : "light"', THEME_JS)
        self.assertIn('document.documentElement.dataset.theme = theme', THEME_JS)
        self.assertIn('const initial = stored === "dark" ? "dark" : "light"', JS)
        self.assertNotIn("prefers-color-scheme", THEME_JS)
        self.assertNotIn("prefers-color-scheme", JS)

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
        triage_header_css = CSS.split(".triage-page-header {", 1)[1].split(
            "}", 1
        )[0]
        triage_content_css = CSS.split(".triage-page-content {", 1)[1].split(
            "}", 1
        )[0]
        for rule in (
            "width: min(1120px, 100%);",
            "margin-right: auto;",
            "margin-left: auto;",
        ):
            self.assertIn(rule, triage_header_css)
            self.assertIn(rule, triage_content_css)

    def test_disposition_desk_keeps_triage_summary_without_duplicate_guidance(self):
        detail_renderer = JS.split("function renderDetail(detail)", 1)[1].split(
            "function responsePackLink", 1
        )[0]

        self.assertIn('class="detail-card triage-analysis-summary"', detail_renderer)
        self.assertIn("explanationBlock(latestRun.explanation)", detail_renderer)
        self.assertNotIn("latestRun.recommended_actions", detail_renderer)
        self.assertNotIn("latestRun.missing_evidence", detail_renderer)
        self.assertNotIn('tr("recommendedActions")', detail_renderer)
        self.assertNotIn('tr("missingEvidence")', detail_renderer)

        explanation_renderer = JS.split("function explanationBlock(explanation)", 1)[
            1
        ].split("function actionStageLabel", 1)[0]
        self.assertIn('tr("verdict")', explanation_renderer)
        self.assertIn('tr("dimensions")', explanation_renderer)

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
        self.assertIn("function responsePackLink(caseId)", JS)
        self.assertIn("/case-response.html?", JS)
        self.assertEqual(JS.count("responsePackTitle:"), 2)

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
        associations_header_css = CSS.split(
            ".memory-associations-page-header {", 1
        )[1].split("}", 1)[0]
        associations_panel_css = CSS.split(
            ".memory-associations-page-panel {", 1
        )[1].split("}", 1)[0]
        for rule in (
            "width: min(1180px, 100%);",
            "margin-right: auto;",
            "margin-left: auto;",
        ):
            self.assertIn(rule, associations_header_css)
            self.assertIn(rule, associations_panel_css)

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
        self.assertIn('document.querySelector("#settings-view")?.classList.contains("active") === true', JS)
        self.assertIn("!document.hidden", JS)


if __name__ == "__main__":
    unittest.main()
