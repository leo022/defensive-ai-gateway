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


class WhitelistRecommendationRenderingTest(unittest.TestCase):
    def test_blank_recommendation_object_is_rendered_as_empty_state(self):
        self.assertIn("function hasMeaningfulWhitelistRecommendation", JS)
        self.assertIn("Object.values(value).some", JS)
        self.assertIn("hasMeaningfulWhitelistRecommendation(whitelist)", JS)
        self.assertNotIn("whitelist && Object.keys(whitelist).length", JS)


class FalsePositiveMemoryActionRenderingTest(unittest.TestCase):
    def test_triage_detail_exposes_alert_level_memory_confirmation(self):
        self.assertIn("function linkedAlertsBlock", JS)
        self.assertIn("${linkedAlertsBlock(linked)}", JS)
        self.assertIn("function linkedAlertReviewCard", JS)
        self.assertIn("reviewTools(raw, disposition)", JS)
        self.assertIn("/api/alerts/${encodeURIComponent(alertId)}/confirm-false-positive", JS)
        self.assertIn("disposition?.memory_confirmation?.memory_id", JS)
        self.assertIn("确认误报并写入长期记忆", JS)


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
        self.assertEqual(self.elements["dashboard-nav-parent"]["attrs"]["data-default-secondary"], "pending")
        self.assertEqual(self.elements["memory-nav-parent"]["attrs"]["data-default-secondary"], "inventory")
        self.assertEqual(self.elements["adapter-nav-parent"]["attrs"]["data-default-secondary"], "intake")
        self.assertNotIn("hidden", self.elements["memory-inventory-panel"]["attrs"])
        self.assertIn("hidden", self.elements["memory-audit-panel"]["attrs"])
        self.assertNotIn("hidden", self.elements["adapter-intake-panel"]["attrs"])
        self.assertIn("hidden", self.elements["adapter-config-panel"]["attrs"])
        self.assertNotIn('class="secondary-nav"', HTML)

        containment = {
            "case-search-form": "dashboard-pending-panel",
            "case-history-search-form": "dashboard-history-panel",
            "memory-total": "memory-inventory-panel",
            "memory-list": "memory-inventory-panel",
            "memory-detail": "memory-inventory-panel",
            "memory-audit-list": "memory-audit-panel",
            "syslog-config-table": "adapter-intake-panel",
            "infer-form": "adapter-config-panel",
            "dry-run-form": "adapter-config-panel",
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

    def test_mapping_confirmation_uses_a_full_width_workspace_row(self):
        self.assertIn("mapping-result-panel", self.elements["field-mapping-table"]["ancestors"])
        self.assertIn("adapter-config-panel", self.elements["field-mapping-table"]["ancestors"])
        self.assertIn('id="mapping-result-panel" class="panel mapping-result-panel"', HTML)
        self.assertIn(".mapping-result-panel {\n  grid-column: 1 / -1;", CSS)
        self.assertIn(".field-mapping-table table {\n  width: 100%;\n  min-width: 0;", CSS)
        self.assertIn("fieldConfirmation:", JS)
        self.assertEqual(JS.count("fieldConfirmationHint:"), 2)

    def test_frontend_operability_guards_are_present(self):
        self.assertIn('return new URLSearchParams({ limit: "50" }).toString();', JS)
        self.assertIn('if (section === "pending") params.set("active_only", "1");', JS)
        self.assertIn("case-filter-from", HTML)
        self.assertIn("history-case-filter-from", HTML)
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

        dashboard = JS.split("async function loadDashboardRuntime()", 1)[1].split(
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
        self.assertIn("tasks.push(loadLlmConfig(), loadSyslogConfig())", bootstrap)
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
        self.assertIn('data-case-search-section="pending"', HTML)
        self.assertIn('data-case-search-section="history"', HTML)
        self.assertIn("function openCaseTriage", JS)
        self.assertIn("function loadTriageCase", JS)
        self.assertIn("function pendingQueueCases", JS)
        self.assertIn("function processedQueueCases", JS)
        self.assertIn("function renderProcessedList", JS)
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
