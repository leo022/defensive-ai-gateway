const detailCache = new Map();
const THEME_KEY = "dashboard-theme";
let mappingProfiles = [];
let selectedProfileId = "";
let inferredProfile = null;
let inferredFields = [];
const SAMPLE_RASP_LOG = {
  metadata: { id: "real-rasp-001" },
  device: { vendor: "bank-rasp", type: "runtime_app_protection" },
  risk: { level: "高" },
  time: "2026-06-25T10:00:00+08:00",
  rule: { id: "RASP-SQL-GUARD-221", name: "SQL Injection Runtime Guard" },
  host: { name: "pay-api-01" },
  http: {
    client_ip: "10.1.2.3",
    uri: "/openbanking/v2/payments/search",
    method: "POST",
    request_id: "req-001",
  },
  app: { name: "mobile-payment-api" },
  rasp: { action: "blocked_query_execution" },
  sink: "JdbcTemplate.query",
  taint: { source: "request.parameter.beneficiaryName" },
  stacktrace:
    "com.bank.PaymentSearchController.search(PaymentSearchController.java:88)\n" +
    "com.bank.payment.service.PaymentSearchService.searchBeneficiary(PaymentSearchService.java:143)\n" +
    "com.bank.payment.repository.BeneficiaryRepository.findByFilter(BeneficiaryRepository.java:211)\n" +
    "org.springframework.jdbc.core.JdbcTemplate.query(JdbcTemplate.java:752)\n" +
    "org.springframework.jdbc.core.JdbcTemplate.query(JdbcTemplate.java:779)\n" +
    "com.bank.security.rasp.sql.SqlGuardHook.beforeQuery(SqlGuardHook.java:57)\n" +
    "com.bank.security.rasp.taint.TaintTracker.assertUserInputReachedSink(TaintTracker.java:129)",
};

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
    switchButton.textContent = normalized === "dark" ? "切换浅色模式" : "切换深色模式";
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
  if (["risk", "malicious", "blocked", "high"].includes(value)) return "风险";
  if (["benign", "normal", "allow", "low"].includes(value)) return "正常";
  if (["review", "suspicious", "medium"].includes(value)) return "复核";
  return "信息";
}

function explanationBlock(explanation) {
  const data = explanation || {};
  const dimensions = Array.isArray(data.dimensions) ? data.dimensions : [];
  const whitelist = data.whitelist_recommendation;
  const whitelistHtml =
    whitelist && Object.keys(whitelist).length
      ? `<pre class="mini-json">${pretty(whitelist)}</pre>`
      : '<p class="empty">当前结论未建议添加白名单</p>';

  return `
    <div class="verdict-box">
      <span>研判结论</span>
      <strong>${escapeHtml(data.verdict || "未提取到结构化结论")}</strong>
    </div>
    <h4>分维度判断依据</h4>
    ${
      dimensions.length
        ? `<ol class="dimension-list">
            ${dimensions
              .map(
                (item) => `
                  <li>
                    <span class="status-dot ${escapeHtml(item.status || "info")}">${escapeHtml(statusLabel(item.status))}</span>
                    <div>
                      <strong>${escapeHtml(item.title || "证据维度")}</strong>
                      <p>${escapeHtml(item.evidence || "无补充说明")}</p>
                    </div>
                  </li>
                `,
              )
              .join("")}
          </ol>`
        : '<p class="empty">暂无结构化证据维度</p>'
    }
    <h4>白名单/调优建议</h4>
    ${whitelistHtml}
  `;
}

function actionRows(actions) {
  if (!actions || !actions.length) return '<p class="empty">暂无建议动作</p>';
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
    return '<tr><td colspan="3" class="empty">暂无归一化证据</td></tr>';
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
        确认为业务误报
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
          <h3>AI 分析结果</h3>
          <span class="badge ${escapeHtml(detail.severity)}">${escapeHtml(detail.severity)}</span>
        </div>
        <dl class="kv">
          <dt>Case ID</dt><dd>${escapeHtml(detail.case_id)}</dd>
          <dt>产品</dt><dd>${escapeHtml(detail.product).toUpperCase()}</dd>
          <dt>分类</dt><dd>${escapeHtml(detail.classification)}</dd>
          <dt>置信度</dt><dd>${Math.round((detail.confidence || 0) * 100)}%</dd>
          <dt>更新时间</dt><dd>${fmtTime(detail.updated_at_ms)}</dd>
        </dl>
        <p class="summary">${escapeHtml(detail.summary)}</p>
        ${explanationBlock(latestRun.explanation)}
        <h4>建议动作</h4>
        <ul class="action-list">${actionRows(latestRun.recommended_actions)}</ul>
        <h4>缺失证据</h4>
        <ul class="plain-list">
          ${
            missing.length
              ? missing.map((item) => `<li>${escapeHtml(item)}</li>`).join("")
              : '<li class="empty">暂无</li>'
          }
        </ul>
      </section>

      <section class="detail-card">
        <div class="section-title">
          <h3>关联原始告警</h3>
          <span>${linked.length} 条</span>
        </div>
        <dl class="kv">
          <dt>Alert ID</dt><dd>${escapeHtml(raw.alert_id || firstLink.alert_id)}</dd>
          <dt>来源</dt><dd>${escapeHtml(raw.source)}</dd>
          <dt>产品</dt><dd>${escapeHtml(raw.product).toUpperCase()}</dd>
          <dt>事件</dt><dd>${escapeHtml(raw.event_type)}</dd>
          <dt>严重性</dt><dd>${escapeHtml(raw.severity)}</dd>
          <dt>时间</dt><dd>${escapeHtml(raw.timestamp)}</dd>
          <dt>适配 Profile</dt><dd>${escapeHtml(adapter.profile_id ? `${adapter.profile_id} / ${adapter.profile_version}` : "direct")}</dd>
          <dt>适配状态</dt><dd>${escapeHtml(adapter.mapping_status || "passed")}</dd>
        </dl>
        ${reviewTools(raw)}
        <pre class="json-block">${pretty(raw.payload)}</pre>
      </section>

      <section class="detail-card">
        <div class="section-title">
          <h3>归一化证据</h3>
          <span>${escapeHtml(normalized.event_id || firstLink.event_id)}</span>
        </div>
        <dl class="kv">
          <dt>实体</dt><dd>${escapeHtml(JSON.stringify(normalized.entities || {}))}</dd>
          <dt>敏感标签</dt><dd>${escapeHtml((normalized.sensitivity_tags || []).join(", ") || "-")}</dd>
        </dl>
        <table class="evidence-table">
          <thead>
            <tr><th>类型</th><th>值</th><th>权重/来源</th></tr>
          </thead>
          <tbody>${evidenceRows(normalized.evidence)}</tbody>
        </table>
      </section>

      <section class="detail-card">
        <div class="section-title">
          <h3>Agent 运行记录</h3>
          <span>${detail.agent_runs?.length || 0} 次</span>
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
    <button class="case-toggle" type="button" aria-expanded="false" aria-label="展开 Case ${escapeHtml(item.case_id)}">
      <span class="case-chevron">›</span>
      <strong class="case-product">${escapeHtml(item.product).toUpperCase()}</strong>
      <span class="badge ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span>
      <span class="case-summary">${escapeHtml(item.summary)}</span>
      <span class="linked-count">${item.alert_count || 0} 条告警</span>
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
    panel.innerHTML = '<div class="loading">加载关联告警与 AI 分析...</div>';
    detailCache.set(caseId, await json(`/api/cases/${encodeURIComponent(caseId)}`));
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
  if (status) status.textContent = "正在抽取特征并写入记忆层...";
  try {
    const result = await json(`/api/alerts/${encodeURIComponent(alertId)}/confirm-false-positive`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        analyst: "dashboard-analyst",
        reason: "Dashboard 人工确认：该告警符合业务场景下的误报模式",
      }),
    });
    detailCache.delete(caseId);
    if (status) {
      status.textContent = `已写入产品长期记忆：${result.memory_id}，后续同类高相似告警会降低置信。`;
    }
    await loadCases();
    showToast(`已确认业务误报，并写入记忆层：${result.memory_id}`);
  } catch (err) {
    button.disabled = false;
    const message = err.message || String(err);
    if (status) status.textContent = message;
    showToast(`确认失败：${message}`, "error");
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
      list.innerHTML = '<div class="empty-state">暂无 Case，提交样例告警后会在这里展示。</div>';
      return;
    }
    for (const item of data.cases) {
      list.appendChild(renderCase(item));
    }
  } catch (err) {
    list.innerHTML = `<div class="empty-state">${escapeHtml(err.stack || String(err))}</div>`;
    showToast(`刷新失败：${err.message || String(err)}`, "error");
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
  return value;
}

function selectValueFromMapping(mapping) {
  if (!mapping) return "";
  if (typeof mapping === "object" && Object.prototype.hasOwnProperty.call(mapping, "literal")) {
    return `__literal:${mapping.literal}`;
  }
  return String(mapping);
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
      <span>${profile.enabled ? "启用" : "停用"}</span>
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
  if (profile?.profile_id === "demo-rasp-json" && !sourceLog.value.trim()) {
    sourceLog.value = JSON.stringify(SAMPLE_RASP_LOG, null, 2);
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
  setProfileStatus(`已加载 ${mappingProfiles.length} 个 profile。`);
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
  setProfileStatus(`保存成功：${selectedProfileId}`);
}

function renderFieldMappingTable(result) {
  const container = document.querySelector("#field-mapping-table");
  const fields = result?.fields || [];
  if (!fields.length) {
    container.innerHTML = '<p class="empty">自动识别后会在这里显示字段确认结果。</p>';
    return;
  }
  const requiredMissing = result.required_missing || [];
  const recommendedMissing = result.recommended_missing || [];
  const summaryClass = requiredMissing.length ? "error" : recommendedMissing.length ? "warn" : "success";
  const summaryText = requiredMissing.length
    ? `缺少必填字段：${requiredMissing.join(", ")}`
    : recommendedMissing.length
      ? `必填字段已识别，建议补充：${recommendedMissing.join(", ")}`
      : "必填字段与关键 RASP 字段已识别";
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
        <tr><th>标准字段</th><th>识别路径</th><th>样例值</th><th>状态</th></tr>
      </thead>
      <tbody>
        ${fields
          .map((field, idx) => {
            const selected = selectValueFromMapping(field.mapping);
            const options = [{ path: "", value: "不映射", confidence: 0 }, ...(field.candidates || [])];
            return `
              <tr>
                <td>
                  <strong>${escapeHtml(field.label)}</strong>
                  <span>${field.required ? "必填" : "增强"}</span>
                </td>
                <td>
                  <select data-field-index="${idx}">
                    ${options
                      .map((option) => {
                        const value = option.path || "";
                        const label = value ? `${value} (${Math.round((option.confidence || 0) * 100)}%)` : "不映射";
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
  setProfileStatus(result.ok ? "自动识别完成，可以运行 dry-run。" : "自动识别完成，但仍有必填字段需要补充。", !result.ok);
}

async function saveCurrentProfile() {
  const profile = currentProfileForDryRun();
  if (!profile.profile_id) throw new Error("请先自动识别字段或选择一个 profile");
  const result = await json("/api/mapping-profiles", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(profile),
  });
  selectedProfileId = result.profile.profile.profile_id;
  await loadMappingProfiles();
  setProfileStatus(`模板已保存：${selectedProfileId}`);
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
  showToast(result.ok ? "Dry-run 通过，可以用于正式接入。" : `Dry-run 未通过，缺失字段：${missing || "请查看结果"}`, result.ok ? "success" : "error");
}

async function loadLlmConfig() {
  const cfg = await json("/api/config/llm");
  document.querySelector("#llm-provider").value = cfg.provider || "local";
  document.querySelector("#llm-endpoint").value = cfg.endpoint || "";
  document.querySelector("#llm-model").value = cfg.model || "";
  document.querySelector("#llm-api-key").value = "";
  document.querySelector("#llm-api-key").placeholder = cfg.api_key_set ? "已设置，留空则保留" : "未设置";
  document.querySelector("#llm-api-key-env").value = cfg.api_key_env || "DEFENSIVE_AI_LLM_API_KEY";
  document.querySelector("#llm-timeout").value = cfg.timeout_seconds || 30;
  setConfigStatus(cfg.api_key_set ? "已加载配置，API Key 当前已设置。" : "已加载配置，API Key 当前未设置。");
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
  document.querySelector("#llm-api-key").placeholder = result.llm.api_key_set ? "已设置，留空则保留" : "未设置";
  setConfigStatus(`保存成功：${result.llm.provider} / ${result.llm.model}`);
}

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
  document.querySelector("#source-log").value = JSON.stringify(SAMPLE_RASP_LOG, null, 2);
  setProfileStatus("已加载 RASP 示例日志。");
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
    showToast(`Dry-run 失败：${err.message || String(err)}`, "error");
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

Promise.all([loadCases(), loadLlmConfig(), loadMappingProfiles()]).catch((err) => showToast(err.message || String(err), "error"));
