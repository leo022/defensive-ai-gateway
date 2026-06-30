const detailCache = new Map();
const THEME_KEY = "dashboard-theme";
const LANGUAGE_KEY = "dashboard-language";
const SYSLOG_CONFIG_KEY = "dashboard-syslog-intake-config";
const LOG_PRODUCT_OPTIONS = [
  { product: "waf", label: "WAF" },
  { product: "hips", label: "HIPS" },
  { product: "ndr", label: "NDR" },
  { product: "rasp", label: "RASP" },
  { product: "siem", label: "SIEM" },
];
const DEFAULT_SYSLOG_CONFIGS = [
  { product: "rasp", label: "RASP", port: 1514, profile: "demo-rasp-json", saved: false },
  { product: "waf", label: "WAF", port: 1515, profile: "waf-syslog-json", saved: false },
  { product: "hips", label: "HIPS", port: 1516, profile: "hips-syslog-json", saved: false },
  { product: "ndr", label: "NDR", port: 1517, profile: "ndr-syslog-json", saved: false },
  { product: "siem", label: "SIEM", port: 1518, profile: "siem-syslog-json", saved: false },
];
const STRINGS = {
  zh: {
    appTitle: "安全运营研判中心",
    appSubtitle: "多源告警处置与证据治理",
    navDashboard: "处置台",
    navAdapter: "日志接入",
    navSettings: "运行配置",
    workspaceEyebrow: "Security Operations",
    workspaceTitle: "告警处置队列",
    workspaceTitleDashboard: "告警处置队列",
    workspaceTitleAdapter: "日志接入",
    workspaceTitleSettings: "运行配置",
    environment: "Offline-ready",
    refresh: "刷新",
    alerts: "告警总量",
    highCritical: "高危与严重",
    latestCases: "Case 队列",
    latestCasesHint: "按更新时间排序，展开查看证据、结论和动作。",
    llmConfig: "模型服务",
    llmConfigHint: "切换本地分析器、Ollama 或内网 Gateway。",
    apiKeyPlaceholder: "留空则保留现有 Key",
    provider: "服务类型",
    serviceUrl: "服务 URL",
    model: "模型",
    apiKey: "访问凭据",
    keyEnv: "Key 环境变量",
    timeoutSeconds: "超时秒数",
    saveConfig: "保存配置",
    reload: "重新加载",
    intakeChannels: "告警接入通道",
    intakeChannelsHint: "HTTP 接口继续保留，新增 UDP syslog collector 通道。",
    httpChannelTitle: "现有 HTTP 告警入口",
    httpChannelSubtitle: "适合已能主动调用接口的系统、脚本和联调工具。",
    syslogChannelTitle: "新增 UDP Syslog 通道",
    syslogChannelSubtitle: "适合服务区内只支持 syslog 推送的安全设备。",
    channelProtocol: "协议",
    channelEndpoint: "入口",
    channelAuth: "鉴权",
    channelTarget: "转发",
    channelStatus: "状态",
    channelRetained: "保留",
    channelPlanned: "规划新增",
    httpChannelAuth: "沿用网关 Bearer Token 策略",
    flowSecuritySystem: "安全系统",
    flowServiceIp: "服务区 IP:产品端口/udp",
    flowGateway: "网关 HTTP 告警入口",
    syslogConfigTitle: "Syslog 产品接收配置",
    syslogConfigHint: "为每类安全系统配置 UDP 接收端口，保存后确认为对应产品日志接收。",
    resetSyslogConfig: "恢复默认端口",
    syslogProduct: "安全系统",
    syslogUdpPort: "UDP 端口",
    syslogProfile: "映射 Profile",
    syslogConfirm: "接收确认",
    syslogAction: "操作",
    saveSyslogConfig: "保存",
    syslogPendingStatus: "待保存",
    syslogSavedStatus: "已保存为 {product} 日志接收：UDP {port}",
    syslogSavedToast: "{product} 已配置为 UDP {port} 日志接收",
    syslogPortInvalid: "端口必须在 1-65535 之间",
    syslogDefaultsRestored: "已恢复默认 UDP 端口配置",
    syslogOpsTitle: "安全系统侧配置",
    syslogOpsText: "目的地址填写服务区暴露的 syslog collector IP，端口使用对应产品配置，协议 UDP。",
    syslogMappingTitle: "字段处理策略",
    syslogMappingText: "collector 优先解析 syslog message 中的 JSON；未匹配 profile 时按 SIEM 标准告警兜底。",
    syslogDeployTitle: "k3s 部署对象",
    logAdapter: "日志接入",
    logAdapterHint: "字段识别、映射确认和接入前校验。",
    raspJsonLog: "RASP JSON 日志",
    logSourceType: "日志类型",
    securityAlertLog: "安全设备告警日志",
    autoDetectFields: "识别字段",
    loadSample: "加载示例",
    saveTemplate: "保存映射",
    advancedConfig: "映射模板",
    profileJson: "Profile JSON",
    saveProfile: "保存 Profile",
    dryRunPreview: "映射校验",
    dryRunPreviewHint: "验证 RawAlert 与归一化事件是否符合接入要求。",
    runDryRun: "运行校验",
    dryRunHint: "等待日志与映射配置。",
    themeAria: "切换深色或浅色模式",
    switchLight: "切换浅色模式",
    switchDark: "切换深色模式",
    languageButton: "English",
    languageAria: "Switch to English",
    statusRisk: "风险",
    statusBlocked: "已阻断",
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
    aiAnalysis: "研判摘要",
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
    agentRuns: "研判运行记录",
    rawPayload: "原始载荷",
    runPayload: "运行明细",
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
    noCases: "暂无 Case。",
    refreshFailed: "刷新失败：{message}",
    enabled: "启用",
    disabled: "停用",
    profilesLoaded: "已加载 {count} 个 profile。",
    saved: "保存成功：{id}",
    mappingEmpty: "自动识别后会在这里显示字段确认结果。",
    requiredMissing: "缺少必填字段：{fields}",
    recommendedMissing: "必填字段已识别，建议补充：{fields}",
    mappingPassed: "必填字段与关键设备字段已识别",
    standardField: "标准字段",
    detectedPath: "识别路径",
    sampleValue: "样例值",
    status: "状态",
    noMapping: "不映射",
    required: "必填",
    enhanced: "增强",
    inferOk: "字段识别完成，可以运行校验。",
    inferNeedsRequired: "字段识别完成，但仍有必填字段需要补充。",
    selectProfileFirst: "请先自动识别字段或选择一个 profile",
    templateSaved: "模板已保存：{id}",
    dryRunOk: "映射校验通过，可以用于正式接入。",
    dryRunFailed: "映射校验未通过，缺失字段：{fields}",
    checkResult: "请查看结果",
    keySetKeep: "已设置，留空则保留",
    keyUnset: "未设置",
    configLoadedWithKey: "已加载配置，API Key 当前已设置。",
    configLoadedNoKey: "已加载配置，API Key 当前未设置。",
    configSaved: "保存成功：{provider} / {model}",
    configRestored: "已恢复为配置文件与环境变量的默认 LLM 配置（如启动时的 local）。",
    restoreDefaults: "恢复默认",
    loadModels: "同步模型",
    modelsLoaded: "已从 {endpoint} 拉取 {count} 个本地模型，可在 Model 下拉中选择。",
    modelsEmpty: "未在 {endpoint} 发现任何模型，请确认 Ollama 已启动。",
    modelsLoadFailed: "拉取模型失败：{error}",
    sampleLoaded: "已加载 {product} 示例日志。",
    dryRunError: "映射校验失败：{message}",
    fieldRequired: "必填",
    fieldEnhanced: "增强",
  },
  en: {
    appTitle: "Security Operations Triage Center",
    appSubtitle: "Alert response and evidence governance",
    navDashboard: "Queue",
    navAdapter: "Log Intake",
    navSettings: "Runtime",
    workspaceEyebrow: "Security Operations",
    workspaceTitle: "Alert Triage Queue",
    workspaceTitleDashboard: "Alert Triage Queue",
    workspaceTitleAdapter: "Log Intake",
    workspaceTitleSettings: "Runtime Configuration",
    environment: "Offline-ready",
    refresh: "Refresh",
    alerts: "Total Alerts",
    highCritical: "High and Critical",
    latestCases: "Case Queue",
    latestCasesHint: "Sorted by last update; expand a case to review evidence, verdict, and actions.",
    llmConfig: "Model Service",
    llmConfigHint: "Switch between local analyzer, Ollama, and the internal gateway.",
    apiKeyPlaceholder: "Leave blank to keep the existing key",
    provider: "Service type",
    serviceUrl: "Service URL",
    model: "Model",
    apiKey: "Credential",
    keyEnv: "Key environment variable",
    timeoutSeconds: "Timeout seconds",
    saveConfig: "Save configuration",
    reload: "Reload",
    intakeChannels: "Alert Intake Channels",
    intakeChannelsHint: "Keep the HTTP endpoint and add a UDP syslog collector path.",
    httpChannelTitle: "Existing HTTP Alert Endpoint",
    httpChannelSubtitle: "For systems, scripts, and test tools that can actively call the gateway API.",
    syslogChannelTitle: "New UDP Syslog Channel",
    syslogChannelSubtitle: "For security devices in the service zone that only push syslog.",
    channelProtocol: "Protocol",
    channelEndpoint: "Endpoint",
    channelAuth: "Auth",
    channelTarget: "Forwarding",
    channelStatus: "Status",
    channelRetained: "Retained",
    channelPlanned: "Planned",
    httpChannelAuth: "Uses the gateway Bearer Token policy",
    flowSecuritySystem: "Security system",
    flowServiceIp: "Service-zone IP:product port/udp",
    flowGateway: "Gateway HTTP alert endpoint",
    syslogConfigTitle: "Syslog Product Receiver Config",
    syslogConfigHint: "Configure a UDP receiver port for each security system; saving confirms the product log receiver.",
    resetSyslogConfig: "Restore default ports",
    syslogProduct: "Security system",
    syslogUdpPort: "UDP port",
    syslogProfile: "Mapping profile",
    syslogConfirm: "Receiver confirmation",
    syslogAction: "Action",
    saveSyslogConfig: "Save",
    syslogPendingStatus: "Pending",
    syslogSavedStatus: "Saved as {product} log receiver: UDP {port}",
    syslogSavedToast: "{product} is configured as a UDP {port} log receiver",
    syslogPortInvalid: "Port must be between 1 and 65535",
    syslogDefaultsRestored: "Default UDP port configuration restored",
    syslogOpsTitle: "Security System Setup",
    syslogOpsText: "Use the service-zone syslog collector IP as the target, the configured product port, and UDP protocol.",
    syslogMappingTitle: "Field Handling",
    syslogMappingText: "The collector parses JSON in the syslog message first; unmatched sources fall back to SIEM-style standard alerts.",
    syslogDeployTitle: "k3s manifest",
    logAdapter: "Log Intake",
    logAdapterHint: "Field detection, mapping confirmation, and pre-ingestion validation.",
    raspJsonLog: "RASP JSON log",
    logSourceType: "Log type",
    securityAlertLog: "Security device alert log",
    autoDetectFields: "Detect fields",
    loadSample: "Load sample",
    saveTemplate: "Save mapping",
    advancedConfig: "Mapping templates",
    profileJson: "Profile JSON",
    saveProfile: "Save profile",
    dryRunPreview: "Mapping Validation",
    dryRunPreviewHint: "Validate RawAlert and normalized event output before ingestion.",
    runDryRun: "Run validation",
    dryRunHint: "Waiting for log and mapping configuration.",
    themeAria: "Toggle dark or light mode",
    switchLight: "Switch to light mode",
    switchDark: "Switch to dark mode",
    languageButton: "中文",
    languageAria: "切换到中文",
    statusRisk: "Risk",
    statusBlocked: "Blocked",
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
    aiAnalysis: "Triage Summary",
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
    agentRuns: "Triage Runs",
    rawPayload: "Raw payload",
    runPayload: "Run detail",
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
    noCases: "No cases.",
    refreshFailed: "Refresh failed: {message}",
    enabled: "Enabled",
    disabled: "Disabled",
    profilesLoaded: "Loaded {count} profiles.",
    saved: "Saved: {id}",
    mappingEmpty: "Field confirmation results will appear here after auto-detection.",
    requiredMissing: "Missing required fields: {fields}",
    recommendedMissing: "Required fields are mapped. Recommended additions: {fields}",
    mappingPassed: "Required fields and key device fields are mapped",
    standardField: "Standard field",
    detectedPath: "Detected path",
    sampleValue: "Sample value",
    status: "Status",
    noMapping: "Do not map",
    required: "Required",
    enhanced: "Enhanced",
    inferOk: "Field detection completed. You can run validation.",
    inferNeedsRequired: "Field detection completed, but required fields still need mapping.",
    selectProfileFirst: "Auto-detect fields or select a profile first",
    templateSaved: "Template saved: {id}",
    dryRunOk: "Mapping validation passed. Ready for production ingestion.",
    dryRunFailed: "Mapping validation failed. Missing fields: {fields}",
    checkResult: "check the result",
    keySetKeep: "Set. Leave blank to keep it",
    keyUnset: "Not set",
    configLoadedWithKey: "Configuration loaded. API Key is currently set.",
    configLoadedNoKey: "Configuration loaded. API Key is not set.",
    configSaved: "Saved: {provider} / {model}",
    configRestored: "Restored the default LLM config from the config file and environment (e.g. startup local).",
    restoreDefaults: "Restore defaults",
    loadModels: "Sync models",
    modelsLoaded: "Loaded {count} local model(s) from {endpoint}; pick one from the Model dropdown.",
    modelsEmpty: "No models found at {endpoint}. Is Ollama running?",
    modelsLoadFailed: "Failed to load models: {error}",
    sampleLoaded: "Loaded {product} sample log.",
    dryRunError: "Mapping validation failed: {message}",
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
const sampleLogCache = new Map();
let syslogConfigs = loadSyslogConfigs();
async function loadSampleLog(product = selectedLogProduct()) {
  if (sampleLogCache.has(product)) return sampleLogCache.get(product);
  const sample = await json(`/api/samples/${encodeURIComponent(product)}-alert`);
  sampleLogCache.set(product, sample);
  return sample;
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
  const active = document.querySelector(".nav-button.active")?.dataset.view || "dashboard";
  updateWorkspaceTitle(active);
  renderProfileList();
  renderSyslogConfigTable();
  renderLogProductOptions();
}

function renderLogProductOptions() {
  const select = document.querySelector("#log-product-select");
  if (!select) return;
  const current = selectedLogProduct();
  select.innerHTML = LOG_PRODUCT_OPTIONS.map((item) => {
    const label = `${item.label} JSON ${currentLanguage === "en" ? "log" : "日志"}`;
    return `<option value="${escapeHtml(item.product)}" ${item.product === current ? "selected" : ""}>${escapeHtml(label)}</option>`;
  }).join("");
}

function selectedLogProduct() {
  const value = document.querySelector("#log-product-select")?.value || "waf";
  return LOG_PRODUCT_OPTIONS.some((item) => item.product === value) ? value : "waf";
}

function selectedLogProductLabel() {
  const product = selectedLogProduct();
  return LOG_PRODUCT_OPTIONS.find((item) => item.product === product)?.label || product.toUpperCase();
}

function defaultSyslogConfigs() {
  return DEFAULT_SYSLOG_CONFIGS.map((item) => ({ ...item }));
}

function loadSyslogConfigs() {
  let saved = [];
  try {
    saved = JSON.parse(localStorage.getItem(SYSLOG_CONFIG_KEY) || "[]");
  } catch (err) {
    saved = [];
  }
  const savedByProduct = new Map((Array.isArray(saved) ? saved : []).map((item) => [item.product, item]));
  return defaultSyslogConfigs().map((item) => {
    const persisted = savedByProduct.get(item.product) || {};
    const port = Number(persisted.port || item.port);
    return {
      ...item,
      port: Number.isInteger(port) && port >= 1 && port <= 65535 ? port : item.port,
      profile: String(persisted.profile || item.profile),
      saved: Boolean(persisted.saved),
    };
  });
}

function persistSyslogConfigs() {
  try {
    localStorage.setItem(SYSLOG_CONFIG_KEY, JSON.stringify(syslogConfigs));
  } catch (err) {
    // The current session still reflects the saved configuration when storage is unavailable.
  }
}

function setSyslogConfigStatus(message, isError = false) {
  const status = document.querySelector("#syslog-config-status");
  if (!status) return;
  status.textContent = message;
  status.classList.toggle("error", isError);
}

function renderSyslogConfigTable() {
  const container = document.querySelector("#syslog-config-table");
  if (!container) return;
  container.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>${escapeHtml(tr("syslogProduct"))}</th>
          <th>${escapeHtml(tr("syslogUdpPort"))}</th>
          <th>${escapeHtml(tr("syslogProfile"))}</th>
          <th>${escapeHtml(tr("syslogConfirm"))}</th>
          <th>${escapeHtml(tr("syslogAction"))}</th>
        </tr>
      </thead>
      <tbody>
        ${syslogConfigs
          .map(
            (item) => `
              <tr data-product="${escapeHtml(item.product)}">
                <td><strong>${escapeHtml(item.label)}</strong></td>
                <td>
                  <input
                    class="syslog-port-input"
                    type="number"
                    min="1"
                    max="65535"
                    step="1"
                    value="${escapeHtml(item.port)}"
                    aria-label="${escapeHtml(`${item.label} ${tr("syslogUdpPort")}`)}"
                  />
                </td>
                <td><code>${escapeHtml(item.profile)}</code></td>
                <td>
                  <span class="field-status ${item.saved ? "mapped" : "needs_review"}">
                    ${escapeHtml(item.saved ? tr("syslogSavedStatus", { product: item.label, port: item.port }) : tr("syslogPendingStatus"))}
                  </span>
                </td>
                <td>
                  <button type="button" class="save-syslog-row" data-product="${escapeHtml(item.product)}">
                    ${escapeHtml(tr("saveSyslogConfig"))}
                  </button>
                </td>
              </tr>
            `,
          )
          .join("")}
      </tbody>
    </table>
  `;
  container.querySelectorAll(".save-syslog-row").forEach((button) => {
    button.addEventListener("click", () => saveSyslogConfigRow(button.dataset.product));
  });
}

function saveSyslogConfigRow(product) {
  const row = document.querySelector(`#syslog-config-table tr[data-product="${CSS.escape(product)}"]`);
  const config = syslogConfigs.find((item) => item.product === product);
  if (!row || !config) return;
  const port = Number(row.querySelector(".syslog-port-input")?.value || 0);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    setSyslogConfigStatus(tr("syslogPortInvalid"), true);
    showToast(tr("syslogPortInvalid"), "error");
    return;
  }
  config.port = port;
  config.saved = true;
  persistSyslogConfigs();
  renderSyslogConfigTable();
  const message = tr("syslogSavedToast", { product: config.label, port });
  setSyslogConfigStatus(message);
  showToast(message);
}

function resetSyslogConfigs() {
  syslogConfigs = defaultSyslogConfigs();
  persistSyslogConfigs();
  renderSyslogConfigTable();
  setSyslogConfigStatus(tr("syslogDefaultsRestored"));
  showToast(tr("syslogDefaultsRestored"));
}

function updateWorkspaceTitle(name) {
  const title = document.querySelector("[data-i18n='workspaceTitle']");
  if (!title) return;
  const key = {
    dashboard: "workspaceTitleDashboard",
    adapter: "workspaceTitleAdapter",
    settings: "workspaceTitleSettings",
  }[name] || "workspaceTitleDashboard";
  title.textContent = tr(key);
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
  // "blocked" has its own color class (status-dot.blocked) and means the action
  // was already mitigated — give it a distinct label so text and color stay
  // consistent instead of showing "风险" in a non-risk color.
  if (value === "blocked") return tr("statusBlocked");
  if (["risk", "malicious", "high"].includes(value)) return tr("statusRisk");
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
        <details class="json-details">
          <summary>${escapeHtml(tr("rawPayload"))}</summary>
          <pre class="json-block">${pretty(raw.payload)}</pre>
        </details>
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
        <details class="json-details">
          <summary>${escapeHtml(tr("runPayload"))}</summary>
          <pre class="json-block">${pretty(detail.agent_runs || [])}</pre>
        </details>
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
  updateWorkspaceTitle(name);
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
  const selectedProduct = selectedLogProduct();
  if (profile?.profile_id === `demo-${selectedProduct}-json` && !sourceLog.value.trim() && sampleLogCache.has(selectedProduct)) {
    sourceLog.value = JSON.stringify(sampleLogCache.get(selectedProduct), null, 2);
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
  const product = selectedLogProduct();
  const result = await json("/api/mapping-profiles/infer", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ log, product, profile_id: `auto-${product}-json` }),
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
  populateLlmForm(cfg);
  setConfigStatus(cfg.api_key_set ? tr("configLoadedWithKey") : tr("configLoadedNoKey"));
  if ((cfg.provider || "local") === "ollama") {
    loadOllamaModels().catch((err) => setConfigStatus(err.message || String(err), true));
  }
}

function populateLlmForm(cfg) {
  document.querySelector("#llm-provider").value = cfg.provider || "local";
  document.querySelector("#llm-endpoint").value = cfg.endpoint || "";
  // local provider ignores the model field; force the canonical value so the
  // form always reflects the real "local" configuration instead of stale
  // model names left over from a previous ollama session.
  document.querySelector("#llm-model").value =
    (cfg.provider || "local") === "local" ? "local-rule-analyst" : cfg.model || "";
  document.querySelector("#llm-api-key").value = "";
  document.querySelector("#llm-api-key").placeholder = cfg.api_key_set ? tr("keySetKeep") : tr("keyUnset");
  document.querySelector("#llm-api-key-env").value = cfg.api_key_env || "DEFENSIVE_AI_LLM_API_KEY";
  document.querySelector("#llm-timeout").value = cfg.timeout_seconds || 30;
}

function applyProviderDefaults(provider) {
  const endpoint = document.querySelector("#llm-endpoint");
  const timeout = document.querySelector("#llm-timeout");
  if (provider === "local") {
    document.querySelector("#llm-model").value = "local-rule-analyst";
    timeout.value = 30;
    document.querySelector("#ollama-models").innerHTML = "";
  } else if (provider === "ollama") {
    if (!endpoint.value.trim()) endpoint.value = "http://127.0.0.1:11434/api/generate";
    if (!timeout.value || Number(timeout.value) < 60) timeout.value = 300;
    loadOllamaModels().catch((err) => setConfigStatus(err.message || String(err), true));
  } else if (provider === "gateway") {
    if (!timeout.value || Number(timeout.value) < 60) timeout.value = 120;
    document.querySelector("#ollama-models").innerHTML = "";
  }
}

async function restoreLlmDefaults() {
  const result = await json("/api/config/llm/reload", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  populateLlmForm(result.llm);
  document.querySelector("#llm-api-key").placeholder = result.llm.api_key_set ? tr("keySetKeep") : tr("keyUnset");
  setConfigStatus(tr("configRestored"));
  if ((result.llm.provider || "local") === "ollama") {
    loadOllamaModels().catch((err) => setConfigStatus(err.message || String(err), true));
  }
}

async function loadOllamaModels() {
  const datalist = document.querySelector("#ollama-models");
  // Pass the endpoint currently typed in the form so the picker works before
  // the configuration is saved (the backend no longer gates on the saved
  // provider).
  const endpoint = document.querySelector("#llm-endpoint").value.trim();
  const qs = endpoint ? `?endpoint=${encodeURIComponent(endpoint)}` : "";
  const result = await json(`/api/config/llm/models${qs}`);
  const models = Array.isArray(result.models) ? result.models : [];
  const current = document.querySelector("#llm-model").value;
  datalist.innerHTML = models.map((name) => `<option value="${escapeHtml(name)}"></option>`).join("");
  if (!result.ok) {
    setConfigStatus(tr("modelsLoadFailed", { error: result.error || "unknown" }), true);
    return models;
  }
  if (models.length === 0) {
    setConfigStatus(tr("modelsEmpty", { endpoint: result.endpoint || "" }));
  } else {
    setConfigStatus(tr("modelsLoaded", { count: models.length, endpoint: result.endpoint || "" }));
  }
  if (current && !models.includes(current)) {
    datalist.innerHTML += `<option value="${escapeHtml(current)}"></option>`;
  }
  return models;
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
  populateLlmForm(result.llm);
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
document.querySelector("#restore-llm-defaults").addEventListener("click", () => {
  restoreLlmDefaults().catch((err) => setConfigStatus(err.message || String(err), true));
});
document.querySelector("#load-llm-models").addEventListener("click", () => {
  loadOllamaModels().catch((err) => setConfigStatus(err.message || String(err), true));
});
document.querySelector("#llm-provider").addEventListener("change", () => {
  applyProviderDefaults(document.querySelector("#llm-provider").value);
});
document.querySelector("#llm-endpoint").addEventListener("change", () => {
  if (document.querySelector("#llm-provider").value === "ollama") {
    loadOllamaModels().catch((err) => setConfigStatus(err.message || String(err), true));
  }
});
document.querySelector("#profile-form").addEventListener("submit", (event) => {
  saveMappingProfile(event).catch((err) => setProfileStatus(err.message || String(err), true));
});
document.querySelector("#infer-form").addEventListener("submit", (event) => {
  inferMappingProfile(event).catch((err) => setProfileStatus(err.message || String(err), true));
});
document.querySelector("#load-sample-log").addEventListener("click", () => {
  const product = selectedLogProduct();
  loadSampleLog(product)
    .then((sample) => {
      document.querySelector("#source-log").value = JSON.stringify(sample, null, 2);
      setProfileStatus(tr("sampleLoaded", { product: selectedLogProductLabel() }));
    })
    .catch((err) => setProfileStatus(err.message || String(err), true));
});
document.querySelector("#log-product-select").addEventListener("change", () => {
  inferredProfile = null;
  inferredFields = [];
  lastFieldMappingResult = null;
  setProfileJson({});
  renderFieldMappingTable(null);
  document.querySelector("#dry-run-result").textContent = tr("dryRunHint");
  setProfileStatus("");
});
document.querySelector("#save-inferred-profile").addEventListener("click", () => {
  saveCurrentProfile().catch((err) => setProfileStatus(err.message || String(err), true));
});
document.querySelector("#reload-profiles").addEventListener("click", () => {
  loadMappingProfiles().catch((err) => setProfileStatus(err.message || String(err), true));
});
document.querySelector("#reset-syslog-config").addEventListener("click", resetSyslogConfigs);
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

renderLogProductOptions();
Promise.all([loadSampleLog(selectedLogProduct()), loadCases(), loadLlmConfig(), loadMappingProfiles()]).catch((err) =>
  showToast(err.message || String(err), "error"),
);
