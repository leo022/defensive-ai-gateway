const detailCache = new Map();
const THEME_KEY = "dashboard-theme";
const LANGUAGE_KEY = "dashboard-language";
const STRINGS = {
  zh: {
    appTitle: "AI 安全告警研判与处置中心",
    appSubtitle: "面向 HIPS / RASP / NDR / WAF / SIEM 的多源告警关联分析、风险定级与响应编排能力",
    navAdapter: "适配",
    navSettings: "配置",
    refresh: "刷新",
    alerts: "告警",
    highCritical: "高危/严重",
    latestCases: "最新 Case",
    llmConfig: "LLM 配置",
    apiKeyPlaceholder: "留空则保留现有 Key",
    keyEnv: "Key 环境变量",
    timeoutSeconds: "超时秒数",
    saveConfig: "保存配置",
    reload: "重新加载",
    logAdapter: "日志自动适配",
    raspJsonLog: "RASP JSON 日志",
    autoDetectFields: "自动识别字段",
    loadSample: "加载示例",
    saveTemplate: "保存模板",
    advancedConfig: "高级配置",
    profileJson: "Profile JSON（字段映射）",
    saveProfile: "保存 Profile",
    dryRunPreview: "Dry-run 预览",
    runDryRun: "运行 Dry-run",
    dryRunHint: "粘贴一条脱敏 RASP JSON 日志，自动识别字段后运行 dry-run。",
    themeAria: "切换深色或浅色模式",
    switchLight: "切换浅色模式",
    switchDark: "切换深色模式",
    languageButton: "English",
    languageAria: "Switch to English",
    statusRisk: "风险",
    statusNormal: "正常",
    statusReview: "复核",
    statusInfo: "信息",
    noWhitelist: "当前结论未建议添加白名单",
    verdict: "研判结论",
    noVerdict: "未提取到结构化结论",
    dimensions: "分维度判断依据",
    evidenceDimension: "证据维度",
    noExtraNotes: "无补充说明",
    noDimensions: "暂无结构化证据维度",
    tuning: "白名单/调优建议",
    noActions: "暂无建议动作",
    noEvidence: "暂无归一化证据",
    confirmFalsePositive: "确认为业务误报",
    aiAnalysis: "AI 分析结果",
    product: "产品",
    classification: "分类",
    confidence: "置信度",
    updatedAt: "更新时间",
    recommendedActions: "建议动作",
    missingEvidence: "缺失证据",
    none: "暂无",
    linkedRawAlerts: "关联原始告警",
    alertCount: "{count} 条",
    source: "来源",
    event: "事件",
    severity: "严重性",
    time: "时间",
    adapterProfile: "适配 Profile",
    adapterStatus: "适配状态",
    normalizedEvidence: "归一化证据",
    entities: "实体",
    sensitivityTags: "敏感标签",
    type: "类型",
    value: "值",
    weightSource: "权重/来源",
    agentRuns: "Agent 运行记录",
    runCount: "{count} 次",
    expandCase: "展开 Case {id}",
    alertCountLong: "{count} 条告警",
    loadingDetail: "加载关联告警与 AI 分析...",
    detailLoadFailed: "加载详情失败：{message}",
    extractingMemory: "正在抽取特征并写入记忆层...",
    falsePositiveReason: "Dashboard 人工确认：该告警符合业务场景下的误报模式",
    memoryWritten: "已写入产品长期记忆：{id}，后续同类高相似告警会降低置信。",
    falsePositiveDone: "已确认业务误报，并写入记忆层：{id}",
    confirmFailed: "确认失败：{message}",
    noCases: "暂无 Case，提交样例告警后会在这里展示。",
    refreshFailed: "刷新失败：{message}",
    enabled: "启用",
    disabled: "停用",
    profilesLoaded: "已加载 {count} 个 profile。",
    saved: "保存成功：{id}",
    mappingEmpty: "自动识别后会在这里显示字段确认结果。",
    requiredMissing: "缺少必填字段：{fields}",
    recommendedMissing: "必填字段已识别，建议补充：{fields}",
    mappingPassed: "必填字段与关键 RASP 字段已识别",
    standardField: "标准字段",
    detectedPath: "识别路径",
    sampleValue: "样例值",
    status: "状态",
    noMapping: "不映射",
    required: "必填",
    enhanced: "增强",
    inferOk: "自动识别完成，可以运行 dry-run。",
    inferNeedsRequired: "自动识别完成，但仍有必填字段需要补充。",
    selectProfileFirst: "请先自动识别字段或选择一个 profile",
    templateSaved: "模板已保存：{id}",
    dryRunOk: "Dry-run 通过，可以用于正式接入。",
    dryRunFailed: "Dry-run 未通过，缺失字段：{fields}",
    checkResult: "请查看结果",
    keySetKeep: "已设置，留空则保留",
    keyUnset: "未设置",
    configLoadedWithKey: "已加载配置，API Key 当前已设置。",
    configLoadedNoKey: "已加载配置，API Key 当前未设置。",
    configSaved: "保存成功：{provider} / {model}",
    sampleLoaded: "已加载 RASP 示例日志。",
    dryRunError: "Dry-run 失败：{message}",
    fieldRequired: "必填",
    fieldEnhanced: "增强",
  },
  en: {
    appTitle: "AI Security Alert Triage and Response Center",
    appSubtitle: "Correlation analysis, risk grading, and response orchestration for HIPS / RASP / NDR / WAF / SIEM alerts",
    navAdapter: "Adapter",
    navSettings: "Settings",
    refresh: "Refresh",
    alerts: "Alerts",
    highCritical: "High/Critical",
    latestCases: "Latest Cases",
    llmConfig: "LLM Configuration",
    apiKeyPlaceholder: "Leave blank to keep the existing key",
    keyEnv: "Key environment variable",
    timeoutSeconds: "Timeout seconds",
    saveConfig: "Save configuration",
    reload: "Reload",
    logAdapter: "Log Auto-Adapter",
    raspJsonLog: "RASP JSON log",
    autoDetectFields: "Auto-detect fields",
    loadSample: "Load sample",
    saveTemplate: "Save template",
    advancedConfig: "Advanced configuration",
    profileJson: "Profile JSON (field mapping)",
    saveProfile: "Save profile",
    dryRunPreview: "Dry-run Preview",
    runDryRun: "Run dry-run",
    dryRunHint: "Paste a sanitized RASP JSON log, auto-detect fields, then run a dry-run.",
    themeAria: "Toggle dark or light mode",
    switchLight: "Switch to light mode",
    switchDark: "Switch to dark mode",
    languageButton: "中文",
    languageAria: "切换到中文",
    statusRisk: "Risk",
    statusNormal: "Normal",
    statusReview: "Review",
    statusInfo: "Info",
    noWhitelist: "No whitelist recommendation for the current verdict",
    verdict: "Verdict",
    noVerdict: "No structured verdict extracted",
    dimensions: "Dimension evidence",
    evidenceDimension: "Evidence dimension",
    noExtraNotes: "No extra notes",
    noDimensions: "No structured evidence dimensions",
    tuning: "Whitelist / Tuning recommendation",
    noActions: "No recommended actions",
    noEvidence: "No normalized evidence",
    confirmFalsePositive: "Confirm business false positive",
    aiAnalysis: "AI Analysis Result",
    product: "Product",
    classification: "Classification",
    confidence: "Confidence",
    updatedAt: "Updated at",
    recommendedActions: "Recommended actions",
    missingEvidence: "Missing evidence",
    none: "None",
    linkedRawAlerts: "Linked Raw Alerts",
    alertCount: "{count} items",
    source: "Source",
    event: "Event",
    severity: "Severity",
    time: "Time",
    adapterProfile: "Adapter profile",
    adapterStatus: "Adapter status",
    normalizedEvidence: "Normalized Evidence",
    entities: "Entities",
    sensitivityTags: "Sensitivity tags",
    type: "Type",
    value: "Value",
    weightSource: "Weight/Source",
    agentRuns: "Agent Runs",
    runCount: "{count} runs",
    expandCase: "Expand Case {id}",
    alertCountLong: "{count} alerts",
    loadingDetail: "Loading linked alerts and AI analysis...",
    detailLoadFailed: "Failed to load detail: {message}",
    extractingMemory: "Extracting features and writing to memory...",
    falsePositiveReason: "Dashboard analyst confirmation: this alert matches a business false-positive pattern",
    memoryWritten: "Written to product long-term memory: {id}. Similar future alerts will reduce confidence.",
    falsePositiveDone: "Business false positive confirmed and written to memory: {id}",
    confirmFailed: "Confirmation failed: {message}",
    noCases: "No cases yet. Submit sample alerts to populate this view.",
    refreshFailed: "Refresh failed: {message}",
    enabled: "Enabled",
    disabled: "Disabled",
    profilesLoaded: "Loaded {count} profiles.",
    saved: "Saved: {id}",
    mappingEmpty: "Field confirmation results will appear here after auto-detection.",
    requiredMissing: "Missing required fields: {fields}",
    recommendedMissing: "Required fields are mapped. Recommended additions: {fields}",
    mappingPassed: "Required fields and key RASP fields are mapped",
    standardField: "Standard field",
    detectedPath: "Detected path",
    sampleValue: "Sample value",
    status: "Status",
    noMapping: "Do not map",
    required: "Required",
    enhanced: "Enhanced",
    inferOk: "Auto-detection completed. You can run a dry-run.",
    inferNeedsRequired: "Auto-detection completed, but required fields still need mapping.",
    selectProfileFirst: "Auto-detect fields or select a profile first",
    templateSaved: "Template saved: {id}",
    dryRunOk: "Dry-run passed. Ready for production ingestion.",
    dryRunFailed: "Dry-run failed. Missing fields: {fields}",
    checkResult: "check the result",
    keySetKeep: "Set. Leave blank to keep it",
    keyUnset: "Not set",
    configLoadedWithKey: "Configuration loaded. API Key is currently set.",
    configLoadedNoKey: "Configuration loaded. API Key is not set.",
    configSaved: "Saved: {provider} / {model}",
    sampleLoaded: "Loaded RASP sample log.",
    dryRunError: "Dry-run failed: {message}",
    fieldRequired: "Required",
    fieldEnhanced: "Enhanced",
  },
};
let mappingProfiles = [];
let selectedProfileId = "";
let inferredProfile = null;
let inferredFields = [];
let currentLanguage = "zh";
let lastFieldMappingResult = null;
let sampleRaspLog = null;
async function loadSampleRaspLog() {
  if (sampleRaspLog) return sampleRaspLog;
  sampleRaspLog = await json("/api/samples/rasp-alert");
  return sampleRaspLog;
}

async function json(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function fmtTime(ms) {
  return ms ? new Date(ms).toLocaleString() : "-";
}

function text(value) {
  if (value === null || value === undefined || value === "") return "-";
  return String(value);
}

function tr(key, params = {}) {
  const template = STRINGS[currentLanguage]?.[key] || STRINGS.zh[key] || key;
  return template.replace(/\{(\w+)\}/g, (_, name) => text(params[name]));
}

function loadLanguagePreference() {
  try {
    currentLanguage = localStorage.getItem(LANGUAGE_KEY) === "en" ? "en" : "zh";
  } catch (err) {
    currentLanguage = "zh";
  }
  applyLanguage();
}

function saveLanguagePreference(language) {
  currentLanguage = language === "en" ? "en" : "zh";
  try {
    localStorage.setItem(LANGUAGE_KEY, currentLanguage);
  } catch (err) {
    // Language still applies for the current session when storage is unavailable.
  }
  applyLanguage();
}

function applyLanguage() {
  document.documentElement.lang = currentLanguage === "en" ? "en" : "zh-CN";
  document.title = tr("appTitle");
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    if (node.id === "dry-run-result") {
      const current = node.textContent.trim();
      const hints = [STRINGS.zh.dryRunHint, STRINGS.en.dryRunHint];
      if (!hints.includes(current)) return;
    }
    node.textContent = tr(node.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
    node.setAttribute("placeholder", tr(node.dataset.i18nPlaceholder));
  });
  document.querySelectorAll("[data-i18n-aria-label]").forEach((node) => {
    node.setAttribute("aria-label", tr(node.dataset.i18nAriaLabel));
  });
  applyTheme(document.documentElement.dataset.theme || "light");
  const languageButton = document.querySelector("#language-switch");
  if (languageButton) {
    const nextLanguage = currentLanguage === "en" ? "zh" : "en";
    languageButton.dataset.languageValue = nextLanguage;
    languageButton.textContent = tr("languageButton");
    languageButton.setAttribute("aria-label", tr("languageAria"));
  }
  if (lastFieldMappingResult) {
    renderFieldMappingTable(lastFieldMappingResult);
  }
  renderProfileList();
}

function escapeHtml(value) {
  return text(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function pretty(value) {
  return escapeHtml(JSON.stringify(value || {}, null, 2));
}

function formatSampleValue(value) {
  if (value === null || value === undefined || value === "") return "-";
  return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function localizedFieldLabel(label) {
  if (currentLanguage !== "en") return label;
  const labels = {
    "告警 ID": "Alert ID",
    产品类型: "Product",
    事件类型: "Event type",
    严重级别: "Severity",
    事件时间: "Event time",
    主机: "Host",
    "源 IP": "Source IP",
    URL: "URL",
    "HTTP 方法": "HTTP method",
    "规则 ID": "Rule ID",
    应用: "Application",
    处置动作: "Action",
    "Payload 时间": "Payload time",
    "Payload 主机": "Payload host",
    调用栈: "Stack trace",
    "危险 sink": "Dangerous sink",
    "Hook 数据": "Hook data",
    污染源: "Taint source",
    "Trace ID": "Trace ID",
    "Request ID": "Request ID",
  };
  return labels[label] || label;
}

function applyTheme(theme) {
  const normalized = theme === "dark" ? "dark" : "light";
  document.documentElement.dataset.theme = normalized;
  document.documentElement.style.colorScheme = normalized;
  const metaTheme = document.querySelector('meta[name="theme-color"]:not([media])');
  if (metaTheme) {
    metaTheme.setAttribute("content", normalized === "dark" ? "#101412" : "#f6f8f5");
  }
  const switchButton = document.querySelector("#theme-switch");
  if (switchButton) {
    const nextTheme = normalized === "dark" ? "light" : "dark";
    switchButton.dataset.themeValue = nextTheme;
    switchButton.textContent = normalized === "dark" ? tr("switchLight") : tr("switchDark");
    switchButton.setAttribute("aria-label", tr("themeAria"));
    switchButton.setAttribute("aria-pressed", String(normalized === "dark"));
  }
  return normalized;
}

function loadThemePreference() {
  let stored = "";
  try {
    stored = localStorage.getItem(THEME_KEY) || "";
  } catch (err) {
    stored = "";
  }
  const initial = stored || document.documentElement.dataset.theme || "light";
  applyTheme(initial);
}

function saveThemePreference(theme) {
  const normalized = applyTheme(theme);
  try {
    localStorage.setItem(THEME_KEY, normalized);
  } catch (err) {
    // Theme still applies for the current session when storage is unavailable.
  }
}

function showToast(message, type = "success") {
  let stack = document.querySelector(".toast-stack");
  if (!stack) {
    stack = document.createElement("div");
    stack.className = "toast-stack";
    document.body.appendChild(stack);
  }
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.setAttribute("role", "status");
  toast.innerHTML = `<span>${escapeHtml(message)}</span><i aria-hidden="true"></i>`;
  stack.appendChild(toast);
  window.setTimeout(() => {
    toast.classList.add("leaving");
    window.setTimeout(() => toast.remove(), 220);
  }, 4200);
}

function statusLabel(status) {
  const value = text(status).toLowerCase();
  if (["risk", "malicious", "blocked", "high"].includes(value)) return tr("statusRisk");
  if (["benign", "normal", "allow", "low"].includes(value)) return tr("statusNormal");
  if (["review", "suspicious", "medium"].includes(value)) return tr("statusReview");
  return tr("statusInfo");
}

function explanationBlock(explanation) {
  const data = explanation || {};
  const dimensions = Array.isArray(data.dimensions) ? data.dimensions : [];
  const whitelist = data.whitelist_recommendation;
  const whitelistHtml =
    whitelist && Object.keys(whitelist).length
      ? `<pre class="mini-json">${pretty(whitelist)}</pre>`
      : `<p class="empty">${escapeHtml(tr("noWhitelist"))}</p>`;

  return `
    <div class="verdict-box">
      <span>${escapeHtml(tr("verdict"))}</span>
      <strong>${escapeHtml(data.verdict || tr("noVerdict"))}</strong>
    </div>
    <h4>${escapeHtml(tr("dimensions"))}</h4>
    ${
      dimensions.length
        ? `<ol class="dimension-list">
            ${dimensions
              .map(
                (item) => `
                  <li>
                    <span class="status-dot ${escapeHtml(item.status || "info")}">${escapeHtml(statusLabel(item.status))}</span>
                    <div>
                      <strong>${escapeHtml(item.title || tr("evidenceDimension"))}</strong>
                      <p>${escapeHtml(item.evidence || tr("noExtraNotes"))}</p>
                    </div>
                  </li>
                `,
              )
              .join("")}
          </ol>`
        : `<p class="empty">${escapeHtml(tr("noDimensions"))}</p>`
    }
    <h4>${escapeHtml(tr("tuning"))}</h4>
    ${whitelistHtml}
  `;
}

function actionRows(actions) {
  if (!actions || !actions.length) return `<p class="empty">${escapeHtml(tr("noActions"))}</p>`;
  return actions
    .map(
      (item) => `
        <li>
          <strong>${escapeHtml(item.mode || "observe")}</strong>
          <span>${escapeHtml(item.action)}</span>
          <small>${escapeHtml(item.rationale || "")}</small>
        </li>
      `,
    )
    .join("");
}

function evidenceRows(evidence) {
  if (!evidence || !evidence.length) {
    return `<tr><td colspan="3" class="empty">${escapeHtml(tr("noEvidence"))}</td></tr>`;
  }
  return evidence
    .map(
      (item) => `
        <tr>
          <td>${escapeHtml(item.type || item.key || "evidence")}</td>
          <td>${escapeHtml(item.value ?? item.text ?? JSON.stringify(item))}</td>
          <td>${escapeHtml(item.weight || item.source || "-")}</td>
        </tr>
      `,
    )
    .join("");
}

function reviewTools(raw) {
  const alertId = raw.alert_id || "";
  if (!alertId) return "";
  return `
    <div class="review-tools">
      <button class="review-button" type="button" data-alert-id="${escapeHtml(alertId)}">
        ${escapeHtml(tr("confirmFalsePositive"))}
      </button>
      <p class="review-status" data-alert-status="${escapeHtml(alertId)}"></p>
    </div>
  `;
}

function renderDetail(detail) {
  const latestRun = detail.agent_runs?.[0]?.result || {};
  const linked = detail.linked_alerts || [];
  const firstLink = linked[0] || {};
  const raw = firstLink.raw_alert || {};
  const normalized = firstLink.normalized_event || {};
  const adapter = raw.payload?.adapter || {};
  const missing = latestRun.missing_evidence || [];

  return `
    <div class="detail-grid">
      <section class="detail-card analysis-card">
        <div class="section-title">
          <h3>${escapeHtml(tr("aiAnalysis"))}</h3>
          <span class="badge ${escapeHtml(detail.severity)}">${escapeHtml(detail.severity)}</span>
        </div>
        <dl class="kv">
          <dt>Case ID</dt><dd>${escapeHtml(detail.case_id)}</dd>
          <dt>${escapeHtml(tr("product"))}</dt><dd>${escapeHtml(detail.product).toUpperCase()}</dd>
          <dt>${escapeHtml(tr("classification"))}</dt><dd>${escapeHtml(detail.classification)}</dd>
          <dt>${escapeHtml(tr("confidence"))}</dt><dd>${Math.round((detail.confidence || 0) * 100)}%</dd>
          <dt>${escapeHtml(tr("updatedAt"))}</dt><dd>${fmtTime(detail.updated_at_ms)}</dd>
        </dl>
        <p class="summary">${escapeHtml(detail.summary)}</p>
        ${explanationBlock(latestRun.explanation)}
        <h4>${escapeHtml(tr("recommendedActions"))}</h4>
        <ul class="action-list">${actionRows(latestRun.recommended_actions)}</ul>
        <h4>${escapeHtml(tr("missingEvidence"))}</h4>
        <ul class="plain-list">
          ${
            missing.length
              ? missing.map((item) => `<li>${escapeHtml(item)}</li>`).join("")
              : `<li class="empty">${escapeHtml(tr("none"))}</li>`
          }
        </ul>
      </section>

      <section class="detail-card">
        <div class="section-title">
          <h3>${escapeHtml(tr("linkedRawAlerts"))}</h3>
          <span>${escapeHtml(tr("alertCount", { count: linked.length }))}</span>
        </div>
        <dl class="kv">
          <dt>Alert ID</dt><dd>${escapeHtml(raw.alert_id || firstLink.alert_id)}</dd>
          <dt>${escapeHtml(tr("source"))}</dt><dd>${escapeHtml(raw.source)}</dd>
          <dt>${escapeHtml(tr("product"))}</dt><dd>${escapeHtml(raw.product).toUpperCase()}</dd>
          <dt>${escapeHtml(tr("event"))}</dt><dd>${escapeHtml(raw.event_type)}</dd>
          <dt>${escapeHtml(tr("severity"))}</dt><dd>${escapeHtml(raw.severity)}</dd>
          <dt>${escapeHtml(tr("time"))}</dt><dd>${escapeHtml(raw.timestamp)}</dd>
          <dt>${escapeHtml(tr("adapterProfile"))}</dt><dd>${escapeHtml(adapter.profile_id ? `${adapter.profile_id} / ${adapter.profile_version}` : "direct")}</dd>
          <dt>${escapeHtml(tr("adapterStatus"))}</dt><dd>${escapeHtml(adapter.mapping_status || "passed")}</dd>
        </dl>
        ${reviewTools(raw)}
        <pre class="json-block">${pretty(raw.payload)}</pre>
      </section>

      <section class="detail-card">
        <div class="section-title">
          <h3>${escapeHtml(tr("normalizedEvidence"))}</h3>
          <span>${escapeHtml(normalized.event_id || firstLink.event_id)}</span>
        </div>
        <dl class="kv">
          <dt>${escapeHtml(tr("entities"))}</dt><dd>${escapeHtml(JSON.stringify(normalized.entities || {}))}</dd>
          <dt>${escapeHtml(tr("sensitivityTags"))}</dt><dd>${escapeHtml((normalized.sensitivity_tags || []).join(", ") || "-")}</dd>
        </dl>
        <table class="evidence-table">
          <thead>
            <tr><th>${escapeHtml(tr("type"))}</th><th>${escapeHtml(tr("value"))}</th><th>${escapeHtml(tr("weightSource"))}</th></tr>
          </thead>
          <tbody>${evidenceRows(normalized.evidence)}</tbody>
        </table>
      </section>

      <section class="detail-card">
        <div class="section-title">
          <h3>${escapeHtml(tr("agentRuns"))}</h3>
          <span>${escapeHtml(tr("runCount", { count: detail.agent_runs?.length || 0 }))}</span>
        </div>
        <pre class="json-block">${pretty(detail.agent_runs || [])}</pre>
      </section>
    </div>
  `;
}

function renderCase(item) {
  const wrapper = document.createElement("article");
  wrapper.className = "case-item";
  wrapper.dataset.caseId = item.case_id;
  wrapper.innerHTML = `
    <button class="case-toggle" type="button" aria-expanded="false" aria-label="${escapeHtml(tr("expandCase", { id: item.case_id }))}">
      <span class="case-chevron">›</span>
      <strong class="case-product">${escapeHtml(item.product).toUpperCase()}</strong>
      <span class="badge ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span>
      <span class="case-summary">${escapeHtml(item.summary)}</span>
      <span class="linked-count">${escapeHtml(tr("alertCountLong", { count: item.alert_count || 0 }))}</span>
      <small class="case-time">${fmtTime(item.updated_at_ms)}</small>
    </button>
    <div class="case-collapse" hidden></div>
  `;
  wrapper.querySelector(".case-toggle").addEventListener("click", () => toggleCase(wrapper, item.case_id));
  return wrapper;
}

async function toggleCase(wrapper, caseId) {
  const button = wrapper.querySelector(".case-toggle");
  const panel = wrapper.querySelector(".case-collapse");
  const expanded = button.getAttribute("aria-expanded") === "true";
  if (expanded) {
    button.setAttribute("aria-expanded", "false");
    panel.hidden = true;
    return;
  }

  button.setAttribute("aria-expanded", "true");
  panel.hidden = false;
  if (!detailCache.has(caseId)) {
    panel.innerHTML = `<div class="loading">${escapeHtml(tr("loadingDetail"))}</div>`;
    try {
      detailCache.set(caseId, await json(`/api/cases/${encodeURIComponent(caseId)}`));
    } catch (err) {
      const message = err.message || String(err);
      detailCache.delete(caseId);
      panel.innerHTML = `<div class="empty-state">${escapeHtml(tr("detailLoadFailed", { message }))}</div>`;
      showToast(tr("detailLoadFailed", { message }), "error");
      return;
    }
  }
  panel.innerHTML = renderDetail(detailCache.get(caseId));
  panel.querySelectorAll(".review-button").forEach((button) => {
    button.addEventListener("click", () => confirmBusinessFalsePositive(button, caseId));
  });
}

async function confirmBusinessFalsePositive(button, caseId) {
  const alertId = button.dataset.alertId;
  const status = document.querySelector(`[data-alert-status="${CSS.escape(alertId)}"]`);
  button.disabled = true;
  if (status) status.textContent = tr("extractingMemory");
  try {
    const result = await json(`/api/alerts/${encodeURIComponent(alertId)}/confirm-false-positive`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        analyst: "dashboard-analyst",
        reason: tr("falsePositiveReason"),
      }),
    });
    detailCache.delete(caseId);
    if (status) {
      status.textContent = tr("memoryWritten", { id: result.memory_id });
    }
    await loadCases();
    showToast(tr("falsePositiveDone", { id: result.memory_id }));
  } catch (err) {
    button.disabled = false;
    const message = err.message || String(err);
    if (status) status.textContent = message;
    showToast(tr("confirmFailed", { message }), "error");
  }
}

function setView(name) {
  document.querySelectorAll(".view").forEach((view) => view.classList.remove("active"));
  document.querySelector(`#${name}-view`).classList.add("active");
  document.querySelectorAll(".nav-button").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.view === name);
  });
}

async function loadCases() {
  const list = document.querySelector("#cases-list");
  try {
    const health = await json("/api/health");
    document.querySelector("#alerts").textContent = health.stats.alerts;
    document.querySelector("#cases").textContent = health.stats.cases;
    document.querySelector("#high").textContent = health.stats.high_or_critical_cases;

    const data = await json("/api/cases?limit=50");
    list.innerHTML = "";
    detailCache.clear();
    if (!data.cases.length) {
      list.innerHTML = `<div class="empty-state">${escapeHtml(tr("noCases"))}</div>`;
      return;
    }
    for (const item of data.cases) {
      list.appendChild(renderCase(item));
    }
  } catch (err) {
    list.innerHTML = `<div class="empty-state">${escapeHtml(err.stack || String(err))}</div>`;
    showToast(tr("refreshFailed", { message: err.message || String(err) }), "error");
  }
}

function setConfigStatus(message, isError = false) {
  const status = document.querySelector("#llm-config-status");
  status.textContent = message;
  status.classList.toggle("error", isError);
}

function setProfileStatus(message, isError = false) {
  const status = document.querySelector("#profile-status");
  status.textContent = message;
  status.classList.toggle("error", isError);
}

function selectedProfile() {
  return mappingProfiles.find((item) => item.profile.profile_id === selectedProfileId)?.profile || null;
}

function mappingFromSelectValue(value) {
  if (!value) return null;
  if (value.startsWith("__literal:")) return { literal: value.slice("__literal:".length) };
  if (value.startsWith("__transform:")) {
    const [, transform, path] = value.match(/^__transform:([^:]+):(.+)$/) || [];
    if (transform && path) return { path, transform };
  }
  return value;
}

function selectValueFromMapping(mapping) {
  if (!mapping) return "";
  if (typeof mapping === "object" && Object.prototype.hasOwnProperty.call(mapping, "literal")) {
    return `__literal:${mapping.literal}`;
  }
  if (typeof mapping === "object" && mapping.transform && mapping.path) {
    return `__transform:${mapping.transform}:${mapping.path}`;
  }
  return String(mapping);
}

function selectValueFromOption(option) {
  if (!option?.path) return "";
  if (option.transform) return `__transform:${option.transform}:${option.path}`;
  return option.path;
}

function currentLog() {
  return JSON.parse(document.querySelector("#source-log").value || "{}");
}

function currentProfileForDryRun() {
  if (inferredProfile) return inferredProfile;
  return JSON.parse(document.querySelector("#profile-json").value || "{}");
}

function setProfileJson(profile) {
  document.querySelector("#profile-json").value = JSON.stringify(profile || {}, null, 2);
}

function renderProfileList() {
  const list = document.querySelector("#profile-list");
  list.innerHTML = "";
  for (const item of mappingProfiles) {
    const profile = item.profile;
    const button = document.createElement("button");
    button.type = "button";
    button.className = `profile-item ${profile.profile_id === selectedProfileId ? "active" : ""}`;
    button.innerHTML = `
      <span>
        <strong>${escapeHtml(profile.name || profile.profile_id)}</strong>
        <span>${escapeHtml(profile.profile_id)} / ${escapeHtml(profile.version || "v1")}</span>
      </span>
      <span>${escapeHtml(profile.enabled ? tr("enabled") : tr("disabled"))}</span>
    `;
    button.addEventListener("click", () => selectProfile(profile.profile_id));
    list.appendChild(button);
  }
}

function selectProfile(profileId) {
  selectedProfileId = profileId;
  const profile = selectedProfile();
  inferredProfile = profile;
  setProfileJson(profile);
  const sourceLog = document.querySelector("#source-log");
  if (profile?.profile_id === "demo-rasp-json" && !sourceLog.value.trim() && sampleRaspLog) {
    sourceLog.value = JSON.stringify(sampleRaspLog, null, 2);
  }
  renderProfileList();
}

async function loadMappingProfiles() {
  const data = await json("/api/mapping-profiles");
  mappingProfiles = data.profiles || [];
  if (!selectedProfileId || !mappingProfiles.some((item) => item.profile.profile_id === selectedProfileId)) {
    selectedProfileId = mappingProfiles[0]?.profile?.profile_id || "";
  }
  renderProfileList();
  if (selectedProfileId) selectProfile(selectedProfileId);
  setProfileStatus(tr("profilesLoaded", { count: mappingProfiles.length }));
}

async function saveMappingProfile(event) {
  event.preventDefault();
  const profile = JSON.parse(document.querySelector("#profile-json").value || "{}");
  const result = await json("/api/mapping-profiles", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(profile),
  });
  selectedProfileId = result.profile.profile.profile_id;
  await loadMappingProfiles();
  setProfileStatus(tr("saved", { id: selectedProfileId }));
}

function renderFieldMappingTable(result) {
  const container = document.querySelector("#field-mapping-table");
  const fields = result?.fields || [];
  lastFieldMappingResult = result || null;
  if (!fields.length) {
    container.innerHTML = `<p class="empty">${escapeHtml(tr("mappingEmpty"))}</p>`;
    return;
  }
  const requiredMissing = result.required_missing || [];
  const recommendedMissing = result.recommended_missing || [];
  const summaryClass = requiredMissing.length ? "error" : recommendedMissing.length ? "warn" : "success";
  const summaryText = requiredMissing.length
    ? tr("requiredMissing", { fields: requiredMissing.join(", ") })
    : recommendedMissing.length
      ? tr("recommendedMissing", { fields: recommendedMissing.join(", ") })
      : tr("mappingPassed");
  container.innerHTML = `
    <div class="mapping-summary ${summaryClass}">${escapeHtml(summaryText)}</div>
    <table>
      <colgroup>
        <col class="mapping-field-col" />
        <col class="mapping-path-col" />
        <col class="mapping-sample-col" />
        <col class="mapping-status-col" />
      </colgroup>
      <thead>
        <tr><th>${escapeHtml(tr("standardField"))}</th><th>${escapeHtml(tr("detectedPath"))}</th><th>${escapeHtml(tr("sampleValue"))}</th><th>${escapeHtml(tr("status"))}</th></tr>
      </thead>
      <tbody>
        ${fields
          .map((field, idx) => {
            const selected = selectValueFromMapping(field.mapping);
            const options = [{ path: "", value: tr("noMapping"), confidence: 0 }, ...(field.candidates || [])];
            return `
              <tr>
                <td>
                  <strong>${escapeHtml(localizedFieldLabel(field.label))}</strong>
                  <span>${escapeHtml(field.required ? tr("required") : tr("enhanced"))}</span>
                </td>
                <td>
                  <select data-field-index="${idx}">
                    ${options
                      .map((option) => {
                        const value = selectValueFromOption(option);
                        const labelPath = option.path || "";
                        const suffix = option.transform ? ` / ${option.transform}` : "";
                        const label = labelPath ? `${labelPath}${suffix} (${Math.round((option.confidence || 0) * 100)}%)` : tr("noMapping");
                        return `<option value="${escapeHtml(value)}" ${value === selected ? "selected" : ""}>${escapeHtml(label)}</option>`;
                      })
                      .join("")}
                  </select>
                </td>
                <td>
                  <pre class="sample-value-preview">${escapeHtml(formatSampleValue(field.sample_value))}</pre>
                </td>
                <td><span class="field-status ${escapeHtml(field.status)}">${escapeHtml(field.status)}</span></td>
              </tr>
            `;
          })
          .join("")}
      </tbody>
    </table>
  `;
  container.querySelectorAll("select").forEach((select) => {
    select.addEventListener("change", updateInferredMapping);
  });
}

function updateInferredMapping(event) {
  const idx = Number(event.currentTarget.dataset.fieldIndex);
  const field = inferredFields[idx];
  if (!field || !inferredProfile) return;
  const mapping = mappingFromSelectValue(event.currentTarget.value);
  field.mapping = mapping;
  field.path = event.currentTarget.value || "";
  field.status = mapping ? "mapped" : "missing";
  if (mapping) {
    inferredProfile.mappings[field.target] = mapping;
  } else {
    delete inferredProfile.mappings[field.target];
  }
  setProfileJson(inferredProfile);
}

async function inferMappingProfile(event) {
  event.preventDefault();
  const log = currentLog();
  const result = await json("/api/mapping-profiles/infer", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ log, profile_id: "auto-rasp-json" }),
  });
  inferredProfile = result.profile;
  inferredFields = result.fields || [];
  setProfileJson(inferredProfile);
  renderFieldMappingTable(result);
  document.querySelector("#dry-run-result").textContent = JSON.stringify(result.quality || result, null, 2);
  setProfileStatus(result.ok ? tr("inferOk") : tr("inferNeedsRequired"), !result.ok);
}

async function saveCurrentProfile() {
  const profile = currentProfileForDryRun();
  if (!profile.profile_id) throw new Error(tr("selectProfileFirst"));
  const result = await json("/api/mapping-profiles", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(profile),
  });
  selectedProfileId = result.profile.profile.profile_id;
  await loadMappingProfiles();
  setProfileStatus(tr("templateSaved", { id: selectedProfileId }));
}

async function runDryRun(event) {
  event.preventDefault();
  const profile = currentProfileForDryRun();
  const log = currentLog();
  const result = await json("/api/mapping-profiles/dry-run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ profile, log }),
  });
  document.querySelector("#dry-run-result").textContent = JSON.stringify(result, null, 2);
  const missing = Array.isArray(result.missing_required_fields) ? result.missing_required_fields.join(", ") : "";
  showToast(result.ok ? tr("dryRunOk") : tr("dryRunFailed", { fields: missing || tr("checkResult") }), result.ok ? "success" : "error");
}

async function loadLlmConfig() {
  const cfg = await json("/api/config/llm");
  document.querySelector("#llm-provider").value = cfg.provider || "local";
  document.querySelector("#llm-endpoint").value = cfg.endpoint || "";
  document.querySelector("#llm-model").value = cfg.model || "";
  document.querySelector("#llm-api-key").value = "";
  document.querySelector("#llm-api-key").placeholder = cfg.api_key_set ? tr("keySetKeep") : tr("keyUnset");
  document.querySelector("#llm-api-key-env").value = cfg.api_key_env || "DEFENSIVE_AI_LLM_API_KEY";
  document.querySelector("#llm-timeout").value = cfg.timeout_seconds || 30;
  setConfigStatus(cfg.api_key_set ? tr("configLoadedWithKey") : tr("configLoadedNoKey"));
}

async function saveLlmConfig(event) {
  event.preventDefault();
  const payload = {
    provider: document.querySelector("#llm-provider").value,
    endpoint: document.querySelector("#llm-endpoint").value,
    model: document.querySelector("#llm-model").value,
    api_key: document.querySelector("#llm-api-key").value,
    api_key_env: document.querySelector("#llm-api-key-env").value,
    timeout_seconds: Number(document.querySelector("#llm-timeout").value || 30),
    keep_existing_key: true,
  };
  const result = await json("/api/config/llm", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  document.querySelector("#llm-api-key").value = "";
  document.querySelector("#llm-api-key").placeholder = result.llm.api_key_set ? tr("keySetKeep") : tr("keyUnset");
  setConfigStatus(tr("configSaved", { provider: result.llm.provider, model: result.llm.model }));
}

loadLanguagePreference();
loadThemePreference();

if (window.matchMedia) {
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  media.addEventListener("change", (event) => {
    try {
      if (!localStorage.getItem(THEME_KEY)) {
        applyTheme(event.matches ? "dark" : "light");
      }
    } catch (err) {
      applyTheme(event.matches ? "dark" : "light");
    }
  });
}

document.querySelector("#refresh").addEventListener("click", loadCases);
document.querySelector("#theme-switch").addEventListener("click", (event) => {
  saveThemePreference(event.currentTarget.dataset.themeValue);
});
document.querySelector("#language-switch").addEventListener("click", (event) => {
  saveLanguagePreference(event.currentTarget.dataset.languageValue);
  loadCases().catch((err) => showToast(err.message || String(err), "error"));
});
document.querySelector("#llm-form").addEventListener("submit", (event) => {
  saveLlmConfig(event).catch((err) => setConfigStatus(err.message || String(err), true));
});
document.querySelector("#reload-llm-config").addEventListener("click", () => {
  loadLlmConfig().catch((err) => setConfigStatus(err.message || String(err), true));
});
document.querySelector("#profile-form").addEventListener("submit", (event) => {
  saveMappingProfile(event).catch((err) => setProfileStatus(err.message || String(err), true));
});
document.querySelector("#infer-form").addEventListener("submit", (event) => {
  inferMappingProfile(event).catch((err) => setProfileStatus(err.message || String(err), true));
});
document.querySelector("#load-sample-log").addEventListener("click", () => {
  loadSampleRaspLog()
    .then((sample) => {
      document.querySelector("#source-log").value = JSON.stringify(sample, null, 2);
      setProfileStatus(tr("sampleLoaded"));
    })
    .catch((err) => setProfileStatus(err.message || String(err), true));
});
document.querySelector("#save-inferred-profile").addEventListener("click", () => {
  saveCurrentProfile().catch((err) => setProfileStatus(err.message || String(err), true));
});
document.querySelector("#reload-profiles").addEventListener("click", () => {
  loadMappingProfiles().catch((err) => setProfileStatus(err.message || String(err), true));
});
document.querySelector("#dry-run-form").addEventListener("submit", (event) => {
  runDryRun(event).catch((err) => {
    document.querySelector("#dry-run-result").textContent = err.message || String(err);
    showToast(tr("dryRunError", { message: err.message || String(err) }), "error");
  });
});
document.querySelectorAll(".nav-button").forEach((btn) => {
  btn.addEventListener("click", () => {
    setView(btn.dataset.view);
    if (btn.dataset.view === "settings") {
      loadLlmConfig().catch((err) => setConfigStatus(err.message || String(err), true));
    }
    if (btn.dataset.view === "adapter") {
      loadMappingProfiles().catch((err) => setProfileStatus(err.message || String(err), true));
    }
  });
});

Promise.all([loadSampleRaspLog(), loadCases(), loadLlmConfig(), loadMappingProfiles()]).catch((err) =>
  showToast(err.message || String(err), "error"),
);
