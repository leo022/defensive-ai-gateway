const API_TOKEN_KEY = "defensive-ai-api-token";
const LANGUAGE_KEY = "dashboard-language";
const DEFAULT_SECTION = "raw-alerts";

const SECTION_COPY = {
  "raw-alerts": {
    zh: {
      title: "关联原始告警",
      subtitle: "查看关联告警的原始载荷与处置状态",
      back: "返回研判与处置",
      empty: "该 Case 没有关联的原始告警。",
      record: "原始告警",
      payload: "原始载荷",
    },
    en: {
      title: "Linked Raw Alerts",
      subtitle: "Review raw payloads and dispositions for linked alerts",
      back: "Back to triage and disposition",
      empty: "This case has no linked raw alerts.",
      record: "Raw alert",
      payload: "Raw payload",
    },
  },
  "normalized-evidence": {
    zh: {
      title: "归一化证据",
      subtitle: "查看结构化实体、证据与敏感标签",
      back: "返回研判与处置",
      empty: "该 Case 没有归一化证据。",
      record: "归一化事件",
      payload: "归一化事件",
    },
    en: {
      title: "Normalized Evidence",
      subtitle: "Review structured entities, evidence, and sensitivity tags",
      back: "Back to triage and disposition",
      empty: "This case has no normalized evidence.",
      record: "Normalized event",
      payload: "Normalized event",
    },
  },
  "analysis-runs": {
    zh: {
      title: "研判运行记录",
      subtitle: "查看分析输出与验证记录",
      back: "返回研判与处置",
      empty: "该 Case 暂无研判运行记录。",
      record: "运行记录",
      payload: "运行明细",
    },
    en: {
      title: "Triage Run Records",
      subtitle: "Review analysis outputs and validation records",
      back: "Back to triage and disposition",
      empty: "This case has no triage run records.",
      record: "Run record",
      payload: "Run details",
    },
  },
};

function language() {
  try {
    return localStorage.getItem(LANGUAGE_KEY) === "en" ? "en" : "zh";
  } catch (err) {
    return "zh";
  }
}

function escapeHtml(value) {
  return String(value ?? "-")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function pretty(value) {
  return escapeHtml(JSON.stringify(value ?? {}, null, 2));
}

function fmtTime(value) {
  const timestamp = typeof value === "number" ? value : Date.parse(String(value || ""));
  return Number.isFinite(timestamp) && timestamp > 0 ? new Date(timestamp).toLocaleString() : "-";
}

function recordTypeLabel(record, copy) {
  if (record.record_type === "agent_run") return language() === "en" ? "Analysis run" : "分析运行";
  if (record.record_type === "validation_run") return language() === "en" ? "Validation record" : "验证记录";
  return copy.record;
}

function recordTitle(record, copy) {
  const data = record.data || {};
  if (record.record_type === "raw_alert") {
    return data.alert_id || record.alert_id || copy.record;
  }
  if (record.record_type === "normalized_evidence") {
    return data.event_id || record.event_id || copy.record;
  }
  if (record.record_type === "agent_run") {
    return data.run_id || data.agent || copy.record;
  }
  return data.validation_id || copy.record;
}

function recordMeta(record) {
  const data = record.data || {};
  if (record.record_type === "raw_alert" || record.record_type === "normalized_evidence") {
    return [data.product, data.event_type, data.severity].filter(Boolean).join(" · ");
  }
  if (record.record_type === "agent_run") {
    return [data.agent, data.product, fmtTime(data.created_at_ms)].filter(Boolean).join(" · ");
  }
  return [data.status, data.validator, fmtTime(data.created_at_ms)].filter(Boolean).join(" · ");
}

function renderRecord(record, copy) {
  const data = record.data || {};
  const payload = record.record_type === "agent_run" ? data.result : data;
  const disposition = record.disposition?.status
    ? `<span class="case-status">${escapeHtml(record.disposition.status)}</span>`
    : "";
  return `
    <article class="case-details-record">
      <div class="case-details-record-heading">
        <div>
          <strong>${escapeHtml(recordTitle(record, copy))}</strong>
          <span>${escapeHtml(recordTypeLabel(record, copy))}${recordMeta(record) ? ` · ${escapeHtml(recordMeta(record))}` : ""}</span>
        </div>
        ${disposition}
      </div>
      <details class="json-details" open>
        <summary>${escapeHtml(copy.payload)}</summary>
        <pre class="json-block">${pretty(payload)}</pre>
      </details>
    </article>
  `;
}

function displayError(message) {
  document.querySelector("#case-details-content").innerHTML = `<p class="case-details-empty">${escapeHtml(message)}</p>`;
}

async function requestDetails(caseId, section) {
  let token = "";
  try {
    token = sessionStorage.getItem(API_TOKEN_KEY) || "";
  } catch (err) {
    token = "";
  }
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  const response = await fetch(
    `/api/cases/${encodeURIComponent(caseId)}/details/${encodeURIComponent(section)}`,
    { headers },
  );
  if (!response.ok) {
    const body = await response.text();
    throw new Error(body || `Request failed (${response.status})`);
  }
  return response.json();
}

async function loadPage() {
  const params = new URLSearchParams(window.location.search);
  const caseId = params.get("case_id") || "";
  const section = params.get("section") || DEFAULT_SECTION;
  const copy = SECTION_COPY[section]?.[language()];
  if (!caseId || !copy) {
    displayError(language() === "en" ? "The detail link is invalid." : "详细信息链接无效。");
    return;
  }

  document.documentElement.lang = language() === "en" ? "en" : "zh-CN";
  document.title = `${copy.title} · ${caseId}`;
  document.querySelector("#case-details-title").textContent = copy.title;
  document.querySelector("#case-details-subtitle").textContent = `${copy.subtitle} · Case ID: ${caseId}`;
  document.querySelector("#case-details-back").textContent = copy.back;

  try {
    const payload = await requestDetails(caseId, section);
    const records = Array.isArray(payload.items) ? payload.items : [];
    const caseInfo = payload.case || {};
    const overview = `
      <section class="case-details-overview">
        <strong>Case ID · ${escapeHtml(caseInfo.case_id || caseId)}</strong>
        <span class="case-product">${escapeHtml(caseInfo.product || "-").toUpperCase()}</span>
        <span class="badge ${escapeHtml(caseInfo.severity || "")}">${escapeHtml(caseInfo.severity || "-")}</span>
        <span class="case-status">${escapeHtml(caseInfo.status || "-")}</span>
      </section>
    `;
    const content = records.length
      ? `<div class="case-details-list">${records.map((record) => renderRecord(record, copy)).join("")}</div>`
      : `<p class="case-details-empty">${escapeHtml(copy.empty)}</p>`;
    document.querySelector("#case-details-content").innerHTML = overview + content;
  } catch (err) {
    displayError(language() === "en" ? `Unable to load details: ${err.message}` : `加载详细信息失败：${err.message}`);
  }
}

document.querySelector("#case-details-back").addEventListener("click", () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.location.assign("/");
  }
});

loadPage();
