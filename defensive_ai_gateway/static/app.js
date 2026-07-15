const detailCache = new Map();
const THEME_KEY = "dashboard-theme";
const LANGUAGE_KEY = "dashboard-language";
const API_TOKEN_KEY = "defensive-ai-api-token";
const SYSLOG_CONFIG_KEY = "dashboard-syslog-intake-config";
const REFRESH_PAUSED_KEY = "dashboard-refresh-paused";
const LEGACY_OFFLINE_MODE_KEY = "dashboard-offline-mode";
const COLLAPSIBLE_TEXT_LIMIT = 280;
const COLLAPSIBLE_TEXT_LINE_LIMIT = 8;
const DASHBOARD_REFRESH_MS = 5000;
const REQUEST_TIMEOUT_MS = 30_000;
const LOG_PRODUCT_OPTIONS = [
  { product: "waf", label: "WAF" },
  { product: "hips", label: "HIPS" },
  { product: "ndr", label: "NDR" },
  { product: "rasp", label: "RASP" },
  { product: "siem", label: "SIEM" },
];
const DEFAULT_SYSLOG_CONFIGS = [
  { product: "waf", label: "WAF", port: 15140, protocol: "tcp", profile: "auto-waf-json", saved: false },
  { product: "hips", label: "HIPS", port: 15141, protocol: "tcp", profile: "auto-hips-json", saved: false },
  { product: "ndr", label: "NDR", port: 15142, protocol: "tcp", profile: "auto-ndr-json", saved: false },
  { product: "rasp", label: "RASP", port: 15143, protocol: "tcp", profile: "auto-rasp-json", saved: false },
  { product: "siem", label: "SIEM", port: 15144, protocol: "tcp", profile: "auto-siem-json", saved: false },
];
const STRINGS = {
  zh: {
    appTitle: "安全运营研判中心",
    appSubtitle: "多源告警处置与证据治理",
    navMonitor: "监控大屏",
    navDashboard: "处置台",
    navMemory: "记忆治理",
    navAdapter: "日志接入",
    navSettings: "运行配置",
    memorySecondaryNav: "记忆治理二级目录",
    memorySubInventory: "记忆清单",
    memorySubAudit: "治理审计",
    adapterSecondaryNav: "日志接入二级目录",
    adapterSubIntake: "告警接入",
    adapterSubConfig: "日志配置",
    authSession: "API 认证",
    authTitle: "API 认证",
    authToken: "访问 Token",
    authConnect: "连接",
    authClear: "清除",
    authClose: "关闭",
    authRequired: "需要 API 认证",
    authConnected: "认证成功",
    authCleared: "会话认证已清除",
    authIdentity: "当前身份：{actor} · 权限：{roles}",
    permissionDenied: "当前会话没有执行此操作的权限",
    workspaceEyebrow: "Security Operations",
    workspaceTitle: "实时监控大屏",
    workspaceTitleMonitor: "实时监控大屏",
    workspaceTitleDashboard: "告警处置队列",
    workspaceTitleMemory: "记忆治理工作台",
    workspaceTitleAdapter: "日志接入",
    workspaceTitleSettings: "运行配置",
    dashboardEyebrow: "Realtime SOC Overview",
    dashboardTitle: "实时监控大屏",
    dashboardSubtitle: "集中监控告警趋势、处置压力、接入健康和模型运行状态。",
    runtimeChecking: "检查中",
    runtimeHealthy: "运行正常",
    runtimeDegraded: "部分降级",
    runtimeCritical: "需要关注",
    autoRefreshOn: "自动刷新",
    autoRefreshPaused: "暂停刷新",
    lastRefresh: "更新于 {time}",
    openCases: "待处置 Case",
    queueDepth: "待处理队列",
    healthTitle: "系统健康度",
    healthHint: "综合 API、分析队列、模型服务与日志接入状态。",
    healthScore: "{score} 分",
    distributionTitle: "产品告警分布",
    distributionHint: "按安全产品聚合最近 Case，快速定位噪声来源和重点防线。",
    handlingTitle: "处置结论",
    handlingHint: "按研判结论观察真实攻击、待复核与误报占比。",
    intakeHealthTitle: "接入与监听",
    intakeHealthHint: "HTTP 入口与 Syslog 监听状态。",
    healthApi: "API 服务",
    healthQueue: "分析队列",
    healthModel: "模型服务",
    healthSyslog: "Syslog 监听",
    healthOk: "正常",
    healthWarn: "降级",
    healthBad: "异常",
    queueIdle: "队列空闲",
    queueBacklog: "{count} 条未完成：{queued} 等待，{inflight} 分析中",
    queueSync: "同步分析模式",
    modelLocal: "本地规则分析器",
    modelRemote: "{provider} / {model}",
    syslogActive: "{active}/{total} 个监听在线",
    syslogInactive: "未启用监听",
    httpActive: "HTTP 接入在线",
    noDistribution: "暂无分布数据",
    refresh: "刷新",
    alerts: "告警总量",
    highCritical: "高危与严重",
    latestCases: "Case 队列",
    latestCasesHint: "按创建时间排序，处置后队列顺序保持不变。",
    memoryTotal: "记忆总量",
    memoryActive: "生效中",
    memoryPending: "待审批",
    memoryQuarantined: "已隔离",
    memoryOverdue: "逾期复核",
    memoryInventory: "记忆清单",
    memoryInventoryHint: "检索全部层级与生命周期状态。",
    memorySweep: "治理扫描",
    memorySearch: "关键词",
    memorySearchPlaceholder: "ID、命名空间、检索键或内容",
    memoryLayer: "层级",
    memoryAllLayers: "全部层级",
    memoryLayerCase: "Case 短期",
    memoryLayerProduct: "产品长期",
    memoryLayerAsset: "资产画像",
    memoryLayerOrg: "组织知识",
    memoryLayerEvidence: "证据引用",
    memoryStatus: "状态",
    memoryAllStatuses: "全部状态",
    memoryStatusActive: "生效中",
    memoryStatusPending: "待审批",
    memoryStatusQuarantined: "已隔离",
    memoryStatusRevoked: "已撤销",
    memoryStatusExpired: "已过期",
    memoryNamespace: "命名空间",
    memoryDetail: "治理详情",
    memoryDetailHint: "核验证据、适用范围、期限和审计轨迹。",
    memorySelectPrompt: "从左侧选择一条记忆开始治理。",
    memoryAudit: "治理审计",
    memoryAuditHint: "最近的提议、审批、隔离、恢复、冲突和过期事件。",
    memoryLoading: "正在加载记忆治理数据...",
    memoryNoResults: "当前筛选条件下没有记忆。",
    memoryCount: "显示 {count} 条",
    memorySourceCase: "来源 Case",
    memoryRetrievalKey: "检索键",
    memoryTrust: "信任等级",
    memoryScope: "适用范围",
    memoryCreated: "创建时间",
    memoryUpdated: "更新时间",
    memoryExpires: "过期时间",
    memoryApprover: "批准人",
    memoryContent: "结构化内容",
    memoryGovernanceForm: "治理操作",
    memoryAnalyst: "操作人",
    memoryReason: "治理理由",
    memoryReasonPlaceholder: "记录审批依据、投毒风险或恢复原因",
    memoryPromotionScope: "批准范围",
    memoryExpiry: "有效期至",
    memoryPromote: "批准晋升",
    memoryReject: "撤销",
    memoryQuarantine: "隔离",
    memoryRestore: "恢复",
    memoryGateStatus: "晋升五门禁",
    memoryGateEvidence: "证据可追溯",
    memoryGateApprover: "分析师已确认",
    memoryGateScope: "适用范围清晰",
    memoryGateExpiry: "有效期明确",
    memoryGateSensitive: "无敏感信息泄漏",
    memoryGatePass: "通过",
    memoryGateFail: "待补充",
    memoryActionDone: "记忆 {id} 已完成{action}。",
    memoryActionFailed: "治理操作失败：{message}",
    memorySweepDone: "扫描完成：过期 {expired} 条，冲突隔离 {conflicts} 条。",
    memoryAuditEmpty: "暂无治理事件。",
    memoryAssociations: "关联告警",
    memoryAssociationsHint: "由统一 matcher 保存的候选评分与最终影响。",
    memoryAssociationsEmpty: "尚无后续告警与该记忆产生有效候选关联。",
    memoryMatchOverall: "综合分",
    memoryMatchStructured: "结构化",
    memoryMatchSemantic: "语义向量",
    memoryMatchRetrieval: "检索键",
    memoryMatchDecision: "决策",
    memoryMatchDowngraded: "降级为误报",
    memoryMatchReinforced: "强化误报结论",
    memoryMatchAttackVeto: "攻击证据否决降级",
    memoryMatchReview: "仅供复核",
    memoryMatchEligible: "达到应用阈值",
    memoryMatchIgnored: "未达到阈值",
    memoryEventProposed: "提出候选",
    memoryEventPromoted: "批准晋升",
    memoryEventRejected: "拒绝或撤销",
    memoryEventQuarantined: "隔离",
    memoryEventExpired: "过期",
    memoryEventConflict: "发现冲突",
    memoryEventRestored: "恢复生效",
    memoryEventRestoredReview: "恢复待审",
    memoryEventHumanConfirmed: "人工确认误报",
    memoryEventAssetRecorded: "更新资产画像",
    memoryReasonRequired: "撤销、隔离或恢复必须填写治理理由。",
    memoryPromotionRequired: "晋升必须填写操作人、适用范围和未来有效期。",
    caseSearchProduct: "系统",
    caseSearchSeverity: "风险等级",
    caseSearchStatus: "处置状态",
    caseSearchFrom: "开始时间",
    caseSearchTo: "结束时间",
    caseSearchAll: "全部",
    caseSearchSubmit: "搜索",
    caseSearchReset: "重置",
    severityCritical: "严重",
    severityHigh: "高",
    severityMedium: "中",
    severityLow: "低",
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
    intakeChannelsHint: "HTTP 接口继续保留，新增可选 TCP/UDP syslog collector 通道。",
    httpChannelTitle: "现有 HTTP 告警入口",
    httpChannelSubtitle: "适合已能主动调用接口的系统、脚本和联调工具。",
    syslogChannelTitle: "新增 Syslog 通道",
    syslogChannelSubtitle: "支持 TCP/UDP；长报文推荐 TCP，避免 UDP 分片后截断或丢包。",
    channelProtocol: "协议",
    channelEndpoint: "入口",
    channelAuth: "鉴权",
    channelTarget: "转发",
    channelStatus: "状态",
    channelRetained: "保留",
    channelPlanned: "规划新增",
    httpChannelAuth: "沿用网关 Bearer Token 策略",
    flowSecuritySystem: "安全系统",
    flowServiceIp: "服务区 IP:产品端口/协议",
    flowGateway: "网关 HTTP 告警入口",
    syslogConfigTitle: "Syslog 产品接收配置",
    syslogConfigHint: "为每类安全系统配置接收端口和协议；syslog 报文非常长时推荐 TCP，已作为默认项。",
    resetSyslogConfig: "填入默认值",
    syslogProduct: "安全系统",
    syslogPort: "端口",
    syslogProtocol: "协议",
    syslogProfile: "映射 Profile",
    syslogConfirm: "接收确认",
    syslogAction: "操作",
    saveSyslogConfig: "保存",
    syslogPendingStatus: "待保存",
    syslogSavedStatus: "已保存为 {product} 日志接收：{protocol} {port}",
    syslogSavedToast: "{product} 已配置为 {protocol} {port} 日志接收，配置已生效",
    syslogPortInvalid: "端口必须在 1-65535 之间",
    syslogProtocolInvalid: "协议必须选择 TCP 或 UDP",
    syslogDefaultsRestored: "已填入默认 TCP 端口草稿；后端配置尚未改变，请逐行保存需要生效的配置",
    syslogConfigLoadFailed: "加载 Syslog 配置失败：{message}",
    syslogConfigApiUnavailable: "当前后端尚未加载 Syslog 动态配置接口，已显示本地默认值；请重启网关服务后再保存使端口生效。",
    syslogModeEmbedded: "内嵌监听",
    syslogModeExternal: "外部 Vector",
    syslogEmbeddedReady: "网关内嵌 Syslog 监听已启用",
    syslogExternalManaged: "接收端口已由外部 Vector collector 托管；网关内嵌监听器按设计关闭。端口与协议由部署配置管理。",
    syslogExternalStatus: "外部 Collector 托管",
    syslogManagedStatus: "外部接收：{protocol} {port}",
    syslogExternalHealth: "外部 Collector 托管 {total} 个入口",
    syslogOpsTitle: "安全系统侧配置",
    syslogOpsText: "目的地址填写服务区暴露的 syslog collector IP，端口和协议使用对应产品配置。",
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
    expandLongText: "展开全文",
    collapseLongText: "收起",
    confirmFalsePositive: "确认为业务误报",
    caseDisposition: "Case 处置",
    caseStatusOpen: "待处置",
    caseStatusUnderReview: "人工复核",
    caseStatusConfirmedAttack: "确认攻击",
    caseStatusFalsePositive: "业务误报",
    caseStatusClosed: "已关闭",
    markAttack: "确认攻击",
    escalateReview: "升级复核",
    closeCase: "关闭",
    reopenCase: "重开",
    dispositionSaved: "Case 已更新为：{status}",
    dispositionFailed: "处置失败：{message}",
    dispositionReasonAttack: "分析师确认该 Case 为真实攻击，进入人工响应流程。",
    dispositionReasonReview: "证据需要人工复核，暂不做自动化处置。",
    dispositionReasonClose: "分析师关闭该 Case，不执行生产动作。",
    dispositionReasonReopen: "分析师重新打开 Case。",
    aiAnalysis: "研判摘要",
    product: "产品",
    classification: "分类",
    confidence: "置信度",
    updatedAt: "更新时间",
    recommendedActions: "建议动作",
    validationGate: "验证门禁",
    validationPassed: "通过",
    validationReview: "需复核",
    validationBlocked: "已阻断",
    noValidationFindings: "未发现证据或策略违规",
    approvalQueue: "处置审批",
    approvalPending: "待审批",
    approvalApproved: "已批准",
    approvalRejected: "已拒绝",
    approvalCancelled: "已取消",
    executionNotRun: "未执行生产动作",
    rollbackCondition: "回滚条件",
    approveAction: "批准",
    rejectAction: "拒绝",
    approvalReasonPrompt: "请输入审批理由。批准仅表示授权给既有处置流程，本系统不会执行生产动作。",
    approvalDecisionDefault: "Dashboard 分析师已复核证据与回滚条件",
    approvalSaved: "审批状态已更新：{status}（未执行）",
    approvalProgress: "审批进度 {count}/{required}",
    approvalVoteSaved: "审批意见已记录：{count}/{required}，当前状态为 {status}（未执行）",
    approvalFailed: "审批失败：{message}",
    noApprovals: "当前 Case 无可流转审批项",
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
    testConnection: "测试连接",
    testConnecting: "测试中...",
    testConnOk: "{message}",
    testConnFailed: "{message}",
    modelsLoaded: "已从 {endpoint} 拉取 {count} 个本地模型，可在 Model 下拉中选择。",
    modelsEmpty: "未在 {endpoint} 发现任何模型，请确认 Ollama 已启动。",
    modelsLoadFailed: "拉取模型失败：{error}",
    sampleLoaded: "已加载 {product} 示例日志。",
    dryRunError: "映射校验失败：{message}",
    fieldRequired: "必填",
    fieldEnhanced: "增强",
    requestTimedOut: "请求超过 {seconds} 秒未完成，已自动取消。",
    requestCancelled: "请求已取消。",
  },
  en: {
    appTitle: "Security Operations Triage Center",
    appSubtitle: "Alert response and evidence governance",
    navMonitor: "Monitoring",
    navDashboard: "Queue",
    navMemory: "Memory Governance",
    navAdapter: "Log Intake",
    navSettings: "Runtime",
    memorySecondaryNav: "Memory governance sections",
    memorySubInventory: "Memory Inventory",
    memorySubAudit: "Governance Audit",
    adapterSecondaryNav: "Log intake sections",
    adapterSubIntake: "Alert Intake",
    adapterSubConfig: "Log Configuration",
    authSession: "API Access",
    authTitle: "API Access",
    authToken: "Access token",
    authConnect: "Connect",
    authClear: "Clear",
    authClose: "Close",
    authRequired: "API authentication required",
    authConnected: "Authenticated",
    authCleared: "Session credential cleared",
    authIdentity: "Current identity: {actor} · Roles: {roles}",
    permissionDenied: "The current session cannot perform this operation",
    workspaceEyebrow: "Security Operations",
    workspaceTitle: "Realtime Monitoring",
    workspaceTitleMonitor: "Realtime Monitoring",
    workspaceTitleDashboard: "Alert Triage Queue",
    workspaceTitleMemory: "Memory Governance",
    workspaceTitleAdapter: "Log Intake",
    workspaceTitleSettings: "Runtime Configuration",
    dashboardEyebrow: "Realtime SOC Overview",
    dashboardTitle: "Realtime Monitoring",
    dashboardSubtitle: "Monitor alert trends, response pressure, intake health, and model runtime status.",
    runtimeChecking: "Checking",
    runtimeHealthy: "Healthy",
    runtimeDegraded: "Degraded",
    runtimeCritical: "Attention needed",
    autoRefreshOn: "Auto refresh",
    autoRefreshPaused: "Refresh paused",
    lastRefresh: "Updated {time}",
    openCases: "Open Cases",
    queueDepth: "Queue Depth",
    healthTitle: "System Health",
    healthHint: "Combines API, analysis queue, model service, and log intake status.",
    healthScore: "{score} pts",
    distributionTitle: "Product Distribution",
    distributionHint: "Recent cases grouped by security product to spot noisy sources and priority controls.",
    handlingTitle: "Response Verdicts",
    handlingHint: "Verdict mix across malicious, review, benign, and insufficient evidence.",
    intakeHealthTitle: "Intake and Listeners",
    intakeHealthHint: "HTTP endpoint and Syslog listener status.",
    healthApi: "API Service",
    healthQueue: "Analysis Queue",
    healthModel: "Model Service",
    healthSyslog: "Syslog Listeners",
    healthOk: "OK",
    healthWarn: "Degraded",
    healthBad: "Fault",
    queueIdle: "Queue idle",
    queueBacklog: "{count} unfinished: {queued} waiting, {inflight} analyzing",
    queueSync: "Synchronous mode",
    modelLocal: "Local rule analyzer",
    modelRemote: "{provider} / {model}",
    syslogActive: "{active}/{total} listeners online",
    syslogInactive: "No listener enabled",
    httpActive: "HTTP intake online",
    noDistribution: "No distribution data",
    refresh: "Refresh",
    alerts: "Total Alerts",
    highCritical: "High and Critical",
    latestCases: "Case Queue",
    latestCasesHint: "Sorted by creation time; disposition changes keep the queue order stable.",
    memoryTotal: "Total Memories",
    memoryActive: "Active",
    memoryPending: "Pending",
    memoryQuarantined: "Quarantined",
    memoryOverdue: "Review Overdue",
    memoryInventory: "Memory Inventory",
    memoryInventoryHint: "Search every layer and lifecycle state.",
    memorySweep: "Run Governance Scan",
    memorySearch: "Keyword",
    memorySearchPlaceholder: "ID, namespace, retrieval key, or content",
    memoryLayer: "Layer",
    memoryAllLayers: "All layers",
    memoryLayerCase: "Case short-term",
    memoryLayerProduct: "Product long-term",
    memoryLayerAsset: "Asset profile",
    memoryLayerOrg: "Organization knowledge",
    memoryLayerEvidence: "Evidence reference",
    memoryStatus: "Status",
    memoryAllStatuses: "All statuses",
    memoryStatusActive: "Active",
    memoryStatusPending: "Pending approval",
    memoryStatusQuarantined: "Quarantined",
    memoryStatusRevoked: "Revoked",
    memoryStatusExpired: "Expired",
    memoryNamespace: "Namespace",
    memoryDetail: "Governance Detail",
    memoryDetailHint: "Verify evidence, scope, expiry, and audit history.",
    memorySelectPrompt: "Select a memory from the inventory to begin governance.",
    memoryAudit: "Governance Audit",
    memoryAuditHint: "Recent proposal, approval, quarantine, restore, conflict, and expiry events.",
    memoryLoading: "Loading memory governance data...",
    memoryNoResults: "No memories match the current filters.",
    memoryCount: "Showing {count}",
    memorySourceCase: "Source case",
    memoryRetrievalKey: "Retrieval key",
    memoryTrust: "Trust level",
    memoryScope: "Scope",
    memoryCreated: "Created",
    memoryUpdated: "Updated",
    memoryExpires: "Expires",
    memoryApprover: "Approved by",
    memoryContent: "Structured content",
    memoryGovernanceForm: "Governance Actions",
    memoryAnalyst: "Operator",
    memoryReason: "Governance reason",
    memoryReasonPlaceholder: "Record approval evidence, poisoning risk, or restore rationale",
    memoryPromotionScope: "Approved scope",
    memoryExpiry: "Valid until",
    memoryPromote: "Approve Promotion",
    memoryReject: "Revoke",
    memoryQuarantine: "Quarantine",
    memoryRestore: "Restore",
    memoryGateStatus: "Five Promotion Gates",
    memoryGateEvidence: "Evidence traceable",
    memoryGateApprover: "Analyst approved",
    memoryGateScope: "Scope is clear",
    memoryGateExpiry: "Expiry is set",
    memoryGateSensitive: "No sensitive data leak",
    memoryGatePass: "Pass",
    memoryGateFail: "Needs input",
    memoryActionDone: "Memory {id}: {action} completed.",
    memoryActionFailed: "Governance action failed: {message}",
    memorySweepDone: "Scan complete: {expired} expired, {conflicts} conflicts quarantined.",
    memoryAuditEmpty: "No governance events.",
    memoryAssociations: "Associated Alerts",
    memoryAssociationsHint: "Candidate scores and final effects persisted by the unified matcher.",
    memoryAssociationsEmpty: "No subsequent alert has produced an eligible association with this memory.",
    memoryMatchOverall: "Overall",
    memoryMatchStructured: "Structured",
    memoryMatchSemantic: "Semantic vector",
    memoryMatchRetrieval: "Retrieval key",
    memoryMatchDecision: "Decision",
    memoryMatchDowngraded: "Downgraded to benign",
    memoryMatchReinforced: "Benign verdict reinforced",
    memoryMatchAttackVeto: "Attack evidence vetoed downgrade",
    memoryMatchReview: "Review only",
    memoryMatchEligible: "Apply threshold met",
    memoryMatchIgnored: "Below threshold",
    memoryEventProposed: "Candidate proposed",
    memoryEventPromoted: "Promotion approved",
    memoryEventRejected: "Rejected or revoked",
    memoryEventQuarantined: "Quarantined",
    memoryEventExpired: "Expired",
    memoryEventConflict: "Conflict detected",
    memoryEventRestored: "Restored active",
    memoryEventRestoredReview: "Restored for review",
    memoryEventHumanConfirmed: "False positive confirmed",
    memoryEventAssetRecorded: "Asset profile updated",
    memoryReasonRequired: "Revoking, quarantining, or restoring requires a governance reason.",
    memoryPromotionRequired: "Promotion requires an operator, scope, and future expiry.",
    caseSearchProduct: "System",
    caseSearchSeverity: "Risk level",
    caseSearchStatus: "Disposition",
    caseSearchFrom: "Start time",
    caseSearchTo: "End time",
    caseSearchAll: "All",
    caseSearchSubmit: "Search",
    caseSearchReset: "Reset",
    severityCritical: "Critical",
    severityHigh: "High",
    severityMedium: "Medium",
    severityLow: "Low",
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
    intakeChannelsHint: "Keep the HTTP endpoint and add a TCP/UDP syslog collector path.",
    httpChannelTitle: "Existing HTTP Alert Endpoint",
    httpChannelSubtitle: "For systems, scripts, and test tools that can actively call the gateway API.",
    syslogChannelTitle: "New Syslog Channel",
    syslogChannelSubtitle: "Supports TCP/UDP; TCP is recommended for long messages to avoid UDP fragmentation loss.",
    channelProtocol: "Protocol",
    channelEndpoint: "Endpoint",
    channelAuth: "Auth",
    channelTarget: "Forwarding",
    channelStatus: "Status",
    channelRetained: "Retained",
    channelPlanned: "Planned",
    httpChannelAuth: "Uses the gateway Bearer Token policy",
    flowSecuritySystem: "Security system",
    flowServiceIp: "Service-zone IP:product port/protocol",
    flowGateway: "Gateway HTTP alert endpoint",
    syslogConfigTitle: "Syslog Product Receiver Config",
    syslogConfigHint: "Configure a receiver port and protocol for each security system. TCP is the default recommendation for very long syslog messages.",
    resetSyslogConfig: "Fill default values",
    syslogProduct: "Security system",
    syslogPort: "Port",
    syslogProtocol: "Protocol",
    syslogProfile: "Mapping profile",
    syslogConfirm: "Receiver confirmation",
    syslogAction: "Action",
    saveSyslogConfig: "Save",
    syslogPendingStatus: "Pending",
    syslogSavedStatus: "Saved as {product} log receiver: {protocol} {port}",
    syslogSavedToast: "{product} is configured as a {protocol} {port} log receiver and is active",
    syslogPortInvalid: "Port must be between 1 and 65535",
    syslogProtocolInvalid: "Protocol must be TCP or UDP",
    syslogDefaultsRestored: "Default TCP values were filled in as a draft. The backend is unchanged until each required row is saved.",
    syslogConfigLoadFailed: "Failed to load Syslog config: {message}",
    syslogConfigApiUnavailable: "The backend has not loaded the dynamic Syslog config API yet. Local defaults are shown; restart the gateway before saving ports.",
    syslogModeEmbedded: "Embedded listeners",
    syslogModeExternal: "External Vector",
    syslogEmbeddedReady: "Embedded gateway Syslog listeners are enabled",
    syslogExternalManaged: "Receiver ports are managed by the external Vector collector. Embedded gateway listeners are intentionally disabled, and deployment config owns ports and protocols.",
    syslogExternalStatus: "Managed by external collector",
    syslogManagedStatus: "External receiver: {protocol} {port}",
    syslogExternalHealth: "External collector manages {total} endpoint(s)",
    syslogOpsTitle: "Security System Setup",
    syslogOpsText: "Use the service-zone syslog collector IP as the target, with the configured product port and protocol.",
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
    expandLongText: "Expand full text",
    collapseLongText: "Collapse",
    confirmFalsePositive: "Confirm business false positive",
    caseDisposition: "Case disposition",
    caseStatusOpen: "Open",
    caseStatusUnderReview: "Under review",
    caseStatusConfirmedAttack: "Confirmed attack",
    caseStatusFalsePositive: "Business false positive",
    caseStatusClosed: "Closed",
    markAttack: "Confirm attack",
    escalateReview: "Escalate",
    closeCase: "Close",
    reopenCase: "Reopen",
    dispositionSaved: "Case updated: {status}",
    dispositionFailed: "Disposition failed: {message}",
    dispositionReasonAttack: "Analyst confirmed this case as a real attack for human response.",
    dispositionReasonReview: "Evidence requires human review; no automated response executed.",
    dispositionReasonClose: "Analyst closed this case without executing production actions.",
    dispositionReasonReopen: "Analyst reopened this case.",
    aiAnalysis: "Triage Summary",
    product: "Product",
    classification: "Classification",
    confidence: "Confidence",
    updatedAt: "Updated at",
    recommendedActions: "Recommended actions",
    validationGate: "Validation gate",
    validationPassed: "Passed",
    validationReview: "Review required",
    validationBlocked: "Blocked",
    noValidationFindings: "No evidence or policy violations found",
    approvalQueue: "Response approvals",
    approvalPending: "Pending",
    approvalApproved: "Approved",
    approvalRejected: "Rejected",
    approvalCancelled: "Cancelled",
    executionNotRun: "No production action executed",
    rollbackCondition: "Rollback condition",
    approveAction: "Approve",
    rejectAction: "Reject",
    approvalReasonPrompt: "Enter a decision reason. Approval only authorizes the existing response workflow; this gateway executes no production action.",
    approvalDecisionDefault: "Dashboard analyst reviewed the evidence and rollback condition",
    approvalSaved: "Approval updated: {status} (not executed)",
    approvalProgress: "Approval progress {count}/{required}",
    approvalVoteSaved: "Approval vote recorded: {count}/{required}; current status is {status} (not executed)",
    approvalFailed: "Approval failed: {message}",
    noApprovals: "No approval item can be routed for this case",
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
    testConnection: "Test connection",
    testConnecting: "Testing...",
    testConnOk: "{message}",
    testConnFailed: "{message}",
    modelsLoaded: "Loaded {count} local model(s) from {endpoint}; pick one from the Model dropdown.",
    modelsEmpty: "No models found at {endpoint}. Is Ollama running?",
    modelsLoadFailed: "Failed to load models: {error}",
    sampleLoaded: "Loaded {product} sample log.",
    dryRunError: "Mapping validation failed: {message}",
    fieldRequired: "Required",
    fieldEnhanced: "Enhanced",
    requestTimedOut: "The request exceeded {seconds} seconds and was cancelled.",
    requestCancelled: "The request was cancelled.",
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
let syslogRuntime = { mode: "embedded", editable: true, unavailable: false };
let refreshPaused = false;
let dashboardRefreshTimer = null;
let memoryItems = [];
let memoryAuditEvents = [];
let selectedMemoryId = "";
let selectedMemoryDetail = null;
let memorySelectionRequestId = 0;
let caseToUsesCurrentTime = true;
let currentSession = null;
let apiToken = "";
try {
  apiToken = sessionStorage.getItem(API_TOKEN_KEY) || "";
} catch (err) {
  apiToken = "";
}
async function loadSampleLog(product = selectedLogProduct()) {
  if (sampleLogCache.has(product)) return sampleLogCache.get(product);
  const sample = await json(`/api/samples/${encodeURIComponent(product)}-alert`);
  sampleLogCache.set(product, sample);
  return sample;
}

async function json(url, options) {
  const request = { ...(options || {}) };
  const acceptedErrorStatuses = Array.isArray(request.acceptStatuses) ? request.acceptStatuses : [];
  delete request.acceptStatuses;
  const timeoutMs = Number.isFinite(request.timeoutMs) && request.timeoutMs > 0
    ? Number(request.timeoutMs)
    : REQUEST_TIMEOUT_MS;
  delete request.timeoutMs;
  const headers = new Headers(request.headers || {});
  if (apiToken) headers.set("Authorization", `Bearer ${apiToken}`);
  request.headers = headers;
  const upstreamSignal = request.signal;
  const controller = new AbortController();
  let timedOut = false;
  const cancelFromUpstream = () => controller.abort(upstreamSignal?.reason);
  if (upstreamSignal) {
    if (upstreamSignal.aborted) cancelFromUpstream();
    else upstreamSignal.addEventListener("abort", cancelFromUpstream, { once: true });
  }
  request.signal = controller.signal;
  const timeoutId = window.setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  try {
    const res = await fetch(url, request);
    if (!res.ok && !acceptedErrorStatuses.includes(res.status)) {
      if (res.status === 401) showAuthDialog(tr("authRequired"));
      const error = new Error(await res.text());
      error.status = res.status;
      throw error;
    }
    return await res.json();
  } catch (err) {
    if (timedOut) {
      const timeoutError = new Error(tr("requestTimedOut", { seconds: Math.ceil(timeoutMs / 1000) }));
      timeoutError.name = "TimeoutError";
      throw timeoutError;
    }
    if (controller.signal.aborted) {
      const cancelError = new Error(tr("requestCancelled"));
      cancelError.name = "AbortError";
      throw cancelError;
    }
    throw err;
  } finally {
    window.clearTimeout(timeoutId);
    upstreamSignal?.removeEventListener("abort", cancelFromUpstream);
  }
}

function showAuthDialog(message = "") {
  const dialog = document.querySelector("#auth-dialog");
  document.querySelector("#auth-session").hidden = false;
  document.querySelector("#auth-status").textContent = message || sessionIdentityText();
  document.querySelector("#auth-token").value = apiToken;
  if (!dialog.open) dialog.showModal();
  window.setTimeout(() => document.querySelector("#auth-token").focus(), 0);
}

function storeApiToken(value) {
  apiToken = value.trim();
  try {
    if (apiToken) sessionStorage.setItem(API_TOKEN_KEY, apiToken);
    else sessionStorage.removeItem(API_TOKEN_KEY);
  } catch (err) {
    // In-memory authentication still works when session storage is unavailable.
  }
}

function sessionIdentityText() {
  if (!currentSession?.actor) return "";
  return tr("authIdentity", {
    actor: currentSession.actor,
    roles: currentSession.roles.length ? currentSession.roles.join(", ") : "-",
  });
}

function hasAnyRole(...roles) {
  // Keep controls available during the initial local Demo bootstrap. Once the
  // session endpoint responds, its server-issued roles become authoritative.
  if (!currentSession) return true;
  return roles.some((role) => currentSession.roles.includes(role));
}

function canReadCases() {
  return hasAnyRole("read", "analyst", "approver");
}

function canReadRuntimeConfig() {
  return hasAnyRole("read", "config");
}

function canReadMappingProfiles() {
  return hasAnyRole("read", "config", "analyst");
}

function currentActor() {
  return currentSession?.actor || "-";
}

function applyPermission(selector, roles) {
  const allowed = hasAnyRole(...roles);
  document.querySelectorAll(selector).forEach((control) => {
    control.disabled = !allowed;
    if (allowed) {
      if (control.dataset.permissionDenied === "true") control.removeAttribute("title");
      delete control.dataset.permissionDenied;
    } else {
      control.title = tr("permissionDenied");
      control.dataset.permissionDenied = "true";
    }
  });
}

function applySessionPermissions() {
  applyPermission('#llm-form button[type="submit"]', ["config"]);
  applyPermission("#test-llm-connection", ["config"]);
  applyPermission("#restore-llm-defaults", ["config"]);
  applyPermission('#profile-form button[type="submit"]', ["config"]);
  applyPermission("#save-inferred-profile", ["config"]);
  applyPermission('#infer-form button[type="submit"]', ["analyst", "config"]);
  applyPermission('#dry-run-form button[type="submit"]', ["analyst", "config"]);
  applyPermission("#memory-sweep", ["memory"]);
  applyPermission(".case-disposition-button", ["analyst"]);
  applyPermission(".review-button", ["analyst", "memory"]);
  applyPermission(".approval-decision", ["approver"]);
  applyPermission("[data-memory-action]", ["memory"]);
  const authButton = document.querySelector("#auth-session");
  if (authButton) {
    if (currentSession?.actor) authButton.title = sessionIdentityText();
    else authButton.removeAttribute("title");
  }
  updateSyslogModeUi();
}

async function loadSession() {
  try {
    const result = await json("/api/session");
    currentSession = {
      actor: String(result.actor || ""),
      roles: Array.isArray(result.roles) ? result.roles.map(String) : [],
    };
    applySessionPermissions();
    return currentSession;
  } catch (err) {
    currentSession = { actor: "", roles: [] };
    applySessionPermissions();
    throw err;
  }
}

if (apiToken) document.querySelector("#auth-session").hidden = false;

function isApiNotFoundError(err) {
  const message = err?.message || String(err);
  try {
    return JSON.parse(message).error === "not found";
  } catch (parseErr) {
    return message.includes('"error"') && message.includes("not found");
  }
}

function fmtTime(ms) {
  return ms ? new Date(ms).toLocaleString() : "-";
}

function formatDatetimeLocal(date) {
  const pad = (value) => String(value).padStart(2, "0");
  return [
    date.getFullYear(),
    pad(date.getMonth() + 1),
    pad(date.getDate()),
  ].join("-") + `T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function setDefaultCaseDateRange() {
  const fromInput = document.querySelector("#case-filter-from");
  const toInput = document.querySelector("#case-filter-to");
  if (!fromInput || !toInput) return;
  const now = new Date();
  const from = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  fromInput.value = formatDatetimeLocal(from);
  toInput.value = formatDatetimeLocal(now);
  caseToUsesCurrentTime = true;
  fromInput.defaultValue = fromInput.value;
  toInput.defaultValue = toInput.value;
}

function datetimeLocalMs(value) {
  if (!value) return null;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms : null;
}

function caseSearchQuery() {
  const params = new URLSearchParams({ limit: "50" });
  const product = document.querySelector("#case-filter-product")?.value || "";
  const severity = document.querySelector("#case-filter-severity")?.value || "";
  const status = document.querySelector("#case-filter-status")?.value || "";
  const createdFrom = datetimeLocalMs(document.querySelector("#case-filter-from")?.value || "");
  const toInput = document.querySelector("#case-filter-to");
  if (caseToUsesCurrentTime && toInput) toInput.value = formatDatetimeLocal(new Date());
  const createdTo = caseToUsesCurrentTime ? Date.now() : datetimeLocalMs(toInput?.value || "");
  if (product) params.set("product", product);
  if (severity) params.set("severity", severity);
  if (status) params.set("status", status);
  if (createdFrom !== null) params.set("created_from_ms", String(createdFrom));
  // The default range follows the current clock on every refresh. An end time
  // explicitly edited by the operator remains fixed and includes that minute.
  if (createdTo !== null) params.set("created_to_ms", String(createdTo + (caseToUsesCurrentTime ? 0 : 59_999)));
  return params.toString();
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
  const active = document.querySelector(".nav-button.active")?.dataset.view || "monitor";
  updateWorkspaceTitle(active);
  renderProfileList();
  renderSyslogConfigTable();
  renderLogProductOptions();
  renderMemoryList();
  renderMemoryAudit(memoryAuditEvents, "#memory-audit-list");
  if (selectedMemoryDetail) renderMemoryDetail(selectedMemoryDetail);
  updateRefreshModeUi();
  applySessionPermissions();
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
    const protocol = String(persisted.protocol || item.protocol || "tcp").toLowerCase();
    return {
      ...item,
      port: Number.isInteger(port) && port >= 1 && port <= 65535 ? port : item.port,
      protocol: ["tcp", "udp"].includes(protocol) ? protocol : item.protocol,
      profile: String(persisted.profile || item.profile),
      saved: Boolean(persisted.saved),
    };
  });
}

function mergeSyslogConfigs(items) {
  const incoming = new Map((Array.isArray(items) ? items : []).map((item) => [item.product, item]));
  syslogConfigs = defaultSyslogConfigs().map((item) => {
    const updated = incoming.get(item.product) || {};
    const port = Number(updated.port || item.port);
    const protocol = String(updated.protocol || item.protocol || "tcp").toLowerCase();
    return {
      ...item,
      label: String(updated.label || item.label),
      port: Number.isInteger(port) && port >= 1 && port <= 65535 ? port : item.port,
      protocol: ["tcp", "udp"].includes(protocol) ? protocol : item.protocol,
      profile: String(updated.profile || item.profile),
      saved: Boolean(updated.saved),
    };
  });
}

async function loadSyslogConfig() {
  let payload = null;
  try {
    payload = await json("/api/config/syslog");
  } catch (err) {
    if (!isApiNotFoundError(err)) throw err;
    setSyslogRuntime({ mode: "embedded", editable: true, unavailable: true });
    mergeSyslogConfigs(loadSyslogConfigs());
    renderSyslogConfigTable();
    setSyslogConfigStatus(tr("syslogConfigApiUnavailable"));
    return { configs: syslogConfigs, unavailable: true };
  }
  setSyslogRuntime(payload);
  mergeSyslogConfigs(payload.configs || []);
  persistSyslogConfigs();
  renderSyslogConfigTable();
  if (syslogRuntime.mode === "external_vector") {
    setSyslogConfigStatus(tr("syslogExternalManaged"));
  }
  return payload;
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

function setSyslogRuntime(payload = {}) {
  const mode = payload.mode === "external_vector" ? "external_vector" : "embedded";
  syslogRuntime = {
    mode,
    editable: mode === "embedded" && payload.editable !== false,
    unavailable: Boolean(payload.unavailable),
  };
  updateSyslogModeUi();
}

function updateSyslogModeUi() {
  const external = syslogRuntime.mode === "external_vector";
  const block = document.querySelector(".syslog-config-block");
  const badge = document.querySelector("#syslog-mode-badge");
  const summary = document.querySelector("#syslog-mode-summary");
  const reset = document.querySelector("#reset-syslog-config");
  const channelStatus = document.querySelector("#syslog-channel-status");
  if (block) block.dataset.mode = syslogRuntime.mode;
  if (badge) badge.textContent = tr(external ? "syslogModeExternal" : "syslogModeEmbedded");
  if (summary) {
    summary.hidden = !external;
    summary.textContent = external ? tr("syslogExternalManaged") : "";
  }
  if (reset) {
    reset.hidden = external;
    reset.disabled = !external && !hasAnyRole("config");
    if (!external && reset.disabled) reset.title = tr("permissionDenied");
    else reset.removeAttribute("title");
  }
  if (channelStatus) {
    channelStatus.className = `field-status ${external || syslogRuntime.editable ? "mapped" : "needs_review"}`;
    channelStatus.textContent = tr(external ? "syslogExternalStatus" : "syslogEmbeddedReady");
  }
}

function renderSyslogConfigTable() {
  const container = document.querySelector("#syslog-config-table");
  if (!container) return;
  const editable = syslogRuntime.editable && hasAnyRole("config");
  const external = syslogRuntime.mode === "external_vector";
  container.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>${escapeHtml(tr("syslogProduct"))}</th>
          <th>${escapeHtml(tr("syslogPort"))}</th>
          <th>${escapeHtml(tr("syslogProtocol"))}</th>
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
                    aria-label="${escapeHtml(`${item.label} ${tr("syslogPort")}`)}"
                    ${editable ? "" : "disabled"}
                  />
                </td>
                <td>
                  <select class="syslog-protocol-input" aria-label="${escapeHtml(`${item.label} ${tr("syslogProtocol")}`)}" ${editable ? "" : "disabled"}>
                    <option value="tcp" ${item.protocol === "tcp" ? "selected" : ""}>TCP</option>
                    <option value="udp" ${item.protocol === "udp" ? "selected" : ""}>UDP</option>
                  </select>
                </td>
                <td><code>${escapeHtml(item.profile)}</code></td>
                <td>
                  <span class="field-status ${item.saved ? "mapped" : "needs_review"}">
                    ${escapeHtml(
                      external
                        ? tr("syslogManagedStatus", { port: item.port, protocol: item.protocol.toUpperCase() })
                        : item.saved
                        ? tr("syslogSavedStatus", { product: item.label, port: item.port, protocol: item.protocol.toUpperCase() })
                        : tr("syslogPendingStatus"),
                    )}
                  </span>
                </td>
                <td>
                  ${external
                    ? `<span class="syslog-managed-label">${escapeHtml(tr("syslogExternalStatus"))}</span>`
                    : `<button type="button" class="save-syslog-row" data-product="${escapeHtml(item.product)}" ${editable ? "" : `disabled title="${escapeHtml(tr("permissionDenied"))}"`}>
                        ${escapeHtml(tr("saveSyslogConfig"))}
                      </button>`}
                </td>
              </tr>
            `,
          )
          .join("")}
      </tbody>
    </table>
  `;
  container.querySelectorAll(".save-syslog-row").forEach((button) => {
    button.addEventListener("click", () => {
      saveSyslogConfigRow(button.dataset.product).catch((err) => {
        const message = isApiNotFoundError(err) ? tr("syslogConfigApiUnavailable") : err.message || String(err);
        setSyslogConfigStatus(message, true);
        showToast(message, "error");
      });
    });
  });
  updateSyslogModeUi();
}

async function saveSyslogConfigRow(product) {
  if (!syslogRuntime.editable) {
    setSyslogConfigStatus(tr("syslogExternalManaged"));
    return;
  }
  if (!hasAnyRole("config")) {
    setSyslogConfigStatus(tr("permissionDenied"), true);
    return;
  }
  const row = document.querySelector(`#syslog-config-table tr[data-product="${CSS.escape(product)}"]`);
  const config = syslogConfigs.find((item) => item.product === product);
  if (!row || !config) return;
  const port = Number(row.querySelector(".syslog-port-input")?.value || 0);
  const protocol = String(row.querySelector(".syslog-protocol-input")?.value || "").toLowerCase();
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    setSyslogConfigStatus(tr("syslogPortInvalid"), true);
    showToast(tr("syslogPortInvalid"), "error");
    return;
  }
  if (!["tcp", "udp"].includes(protocol)) {
    setSyslogConfigStatus(tr("syslogProtocolInvalid"), true);
    showToast(tr("syslogProtocolInvalid"), "error");
    return;
  }
  const result = await json("/api/config/syslog", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ product, port, protocol }),
  });
  mergeSyslogConfigs(result.syslog?.configs || []);
  const saved = syslogConfigs.find((item) => item.product === product) || config;
  persistSyslogConfigs();
  renderSyslogConfigTable();
  const message = tr("syslogSavedToast", { product: saved.label, port: saved.port, protocol: saved.protocol.toUpperCase() });
  setSyslogConfigStatus(message);
  showToast(message);
}

function fillDefaultSyslogConfigs() {
  if (!syslogRuntime.editable) {
    setSyslogConfigStatus(tr("syslogExternalManaged"));
    return;
  }
  if (!hasAnyRole("config")) {
    setSyslogConfigStatus(tr("permissionDenied"), true);
    return;
  }
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
    monitor: "workspaceTitleMonitor",
    dashboard: "workspaceTitleDashboard",
    memory: "workspaceTitleMemory",
    adapter: "workspaceTitleAdapter",
    settings: "workspaceTitleSettings",
  }[name] || "workspaceTitleMonitor";
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

function loadRefreshPreference() {
  try {
    const stored = localStorage.getItem(REFRESH_PAUSED_KEY);
    refreshPaused = stored === null ? localStorage.getItem(LEGACY_OFFLINE_MODE_KEY) === "true" : stored === "true";
  } catch (err) {
    refreshPaused = false;
  }
  updateRefreshModeUi();
}

function saveRefreshPreference(paused) {
  refreshPaused = Boolean(paused);
  try {
    localStorage.setItem(REFRESH_PAUSED_KEY, String(refreshPaused));
    localStorage.removeItem(LEGACY_OFFLINE_MODE_KEY);
  } catch (err) {
    // The current session still honors the selected refresh mode when storage is unavailable.
  }
  updateRefreshModeUi();
  scheduleDashboardRefresh();
}

function updateRefreshModeUi() {
  const button = document.querySelector("#refresh-mode-toggle");
  if (!button) return;
  button.setAttribute("aria-pressed", String(refreshPaused));
  button.classList.toggle("active", refreshPaused);
  const label = button.querySelector("span") || button;
  label.textContent = tr(refreshPaused ? "autoRefreshPaused" : "autoRefreshOn");
}

function scheduleDashboardRefresh() {
  if (dashboardRefreshTimer) {
    window.clearInterval(dashboardRefreshTimer);
    dashboardRefreshTimer = null;
  }
  if (refreshPaused) return;
  dashboardRefreshTimer = window.setInterval(() => {
    if (document.querySelector("#monitor-view")?.classList.contains("active")) {
      loadCases({ quiet: true }).catch((err) => showToast(err.message || String(err), "error"));
    }
  }, DASHBOARD_REFRESH_MS);
}

function countBy(items, field) {
  const counts = new Map();
  for (const item of items || []) {
    const value = text(item[field] || "unknown").toLowerCase();
    counts.set(value, (counts.get(value) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
}

function renderDistribution(containerId, rows, total, labelForValue = (value) => value) {
  const container = document.querySelector(containerId);
  if (!container) return;
  if (!rows.length || !total) {
    container.innerHTML = `<p class="empty">${escapeHtml(tr("noDistribution"))}</p>`;
    return;
  }
  container.innerHTML = rows
    .map(([value, count]) => {
      const percent = Math.round((count / total) * 100);
      return `
        <div class="distribution-row">
          <div>
            <strong>${escapeHtml(labelForValue(value))}</strong>
            <span>${escapeHtml(String(count))}</span>
          </div>
          <div class="distribution-bar" aria-hidden="true"><i style="width: ${percent}%"></i></div>
          <small>${percent}%</small>
        </div>
      `;
    })
    .join("");
}

function healthItem(status, title, detail) {
  return { status, title, detail };
}

function unfinishedAlertCount(processing = {}) {
  const explicit = Number(processing.unfinished);
  if (Number.isFinite(explicit)) return Math.max(0, explicit);
  return Math.max(0, Number(processing.queued || 0) + Number(processing.inflight || 0));
}

function buildHealthItems(health, llmConfig, syslogPayload) {
  const processing = health?.processing || {};
  const llmProvider = llmConfig?.provider || "local";
  const llmConfigured = llmProvider === "local" || Boolean(llmConfig?.endpoint);
  const externalSyslog = syslogPayload?.mode === "external_vector";
  const listeners = Array.isArray(syslogPayload?.listeners) ? syslogPayload.listeners : [];
  const configs = Array.isArray(syslogPayload?.configs) ? syslogPayload.configs : syslogConfigs;
  const activeListeners = listeners.filter((item) => item.active).length || configs.filter((item) => item.saved).length;
  const queued = Number(processing.queued || 0);
  const inflight = Number(processing.inflight || 0);
  const unfinished = unfinishedAlertCount(processing);
  const failed = Number(processing.failed || 0);
  const rejected = Number(processing.rejected || 0);
  return [
    healthItem(health?.ok ? "ok" : "bad", tr("healthApi"), health?.ok ? tr("healthOk") : tr("healthBad")),
    healthItem(
      failed || rejected ? "warn" : "ok",
      tr("healthQueue"),
      processing.enabled
        ? (unfinished ? tr("queueBacklog", { count: unfinished, queued, inflight }) : tr("queueIdle"))
        : tr("queueSync"),
    ),
    healthItem(
      llmConfigured ? "ok" : "bad",
      tr("healthModel"),
      llmProvider === "local" ? tr("modelLocal") : tr("modelRemote", { provider: llmProvider, model: llmConfig?.model || "-" }),
    ),
    externalSyslog
      ? healthItem("ok", tr("healthSyslog"), tr("syslogExternalHealth", { total: configs.length }))
      : healthItem(
        activeListeners ? "ok" : "warn",
        tr("healthSyslog"),
        configs.length ? tr("syslogActive", { active: activeListeners, total: configs.length }) : tr("syslogInactive"),
      ),
  ];
}

function renderHealth(items) {
  const container = document.querySelector("#health-checks");
  const scoreNode = document.querySelector("#health-score");
  const runtime = document.querySelector("#runtime-status");
  if (!container || !scoreNode || !runtime) return;
  const score = Math.round(
    items.reduce((sum, item) => sum + (item.status === "ok" ? 25 : item.status === "warn" ? 15 : 0), 0),
  );
  const runtimeStatus = items.some((item) => item.status === "bad") ? "bad" : items.some((item) => item.status === "warn") ? "warn" : "ok";
  const runtimeLabel = runtimeStatus === "ok" ? tr("runtimeHealthy") : runtimeStatus === "warn" ? tr("runtimeDegraded") : tr("runtimeCritical");
  scoreNode.textContent = tr("healthScore", { score });
  scoreNode.className = `health-score ${runtimeStatus}`;
  runtime.innerHTML = `
    <span class="runtime-dot ${runtimeStatus}" aria-hidden="true"></span>
    <span>${escapeHtml(runtimeLabel)}</span>
  `;
  container.innerHTML = items
    .map(
      (item) => `
        <article class="health-check ${escapeHtml(item.status)}">
          <span class="runtime-dot ${escapeHtml(item.status)}" aria-hidden="true"></span>
          <div>
            <strong>${escapeHtml(item.title)}</strong>
            <p>${escapeHtml(item.detail)}</p>
          </div>
          <small>${escapeHtml(item.status === "ok" ? tr("healthOk") : item.status === "warn" ? tr("healthWarn") : tr("healthBad"))}</small>
        </article>
      `,
    )
    .join("");
}

function renderIntakeHealth(syslogPayload) {
  const container = document.querySelector("#intake-health");
  if (!container) return;
  const external = syslogPayload?.mode === "external_vector";
  const configs = Array.isArray(syslogPayload?.configs) ? syslogPayload.configs : syslogConfigs;
  container.innerHTML = `
    <article class="intake-health-row ok">
      <strong>HTTP</strong>
      <span>${escapeHtml(tr("httpActive"))}</span>
      <code>POST /api/alerts</code>
    </article>
    ${configs
      .map(
        (item) => `
          <article class="intake-health-row ${external || item.saved ? "ok" : "warn"}">
            <strong>${escapeHtml(item.label || text(item.product).toUpperCase())}</strong>
            <span>${escapeHtml(external ? tr("syslogExternalStatus") : item.saved ? tr("healthOk") : tr("healthWarn"))}</span>
            <code>${escapeHtml(String(item.port))}/${escapeHtml(String(item.protocol || "tcp").toUpperCase())}</code>
          </article>
        `,
      )
      .join("")}
  `;
}

function renderDashboard(health, cases, llmConfig, syslogPayload) {
  const processing = health?.processing || {};
  if (syslogPayload && !syslogPayload.unavailable) setSyslogRuntime(syslogPayload);
  document.querySelector("#alerts").textContent = health?.stats?.alerts ?? 0;
  document.querySelector("#cases").textContent = health?.stats?.open_cases ?? health?.stats?.cases ?? 0;
  document.querySelector("#high").textContent = health?.stats?.high_or_critical_cases ?? 0;
  document.querySelector("#queue-depth").textContent = unfinishedAlertCount(processing);
  const productRows = countBy(cases, "product").map(([product, count]) => [product.toUpperCase(), count]);
  const classificationRows = countBy(cases, "classification");
  renderDistribution("#product-distribution", productRows, cases.length);
  renderDistribution("#classification-distribution", classificationRows, cases.length, (value) => value.replaceAll("_", " "));
  renderHealth(buildHealthItems(health, llmConfig, syslogPayload));
  renderIntakeHealth(syslogPayload);
  const lastRefresh = document.querySelector("#last-refresh");
  if (lastRefresh) lastRefresh.textContent = tr("lastRefresh", { time: fmtTime(Date.now()) });
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

function caseStatusLabel(status) {
  const key = {
    open: "caseStatusOpen",
    under_review: "caseStatusUnderReview",
    confirmed_attack: "caseStatusConfirmedAttack",
    false_positive: "caseStatusFalsePositive",
    closed: "caseStatusClosed",
  }[status || "open"];
  return key ? tr(key) : text(status || "open");
}

function caseStatusClass(status) {
  return text(status || "open").replaceAll("_", "-");
}

function dispositionActions(status) {
  const current = status || "open";
  if (current === "closed" || current === "false_positive") {
    return [{ status: "open", label: tr("reopenCase"), reason: tr("dispositionReasonReopen") }];
  }
  const actions = [];
  if (current !== "confirmed_attack") {
    actions.push({ status: "confirmed_attack", label: tr("markAttack"), reason: tr("dispositionReasonAttack") });
  }
  if (current !== "under_review") {
    actions.push({ status: "under_review", label: tr("escalateReview"), reason: tr("dispositionReasonReview") });
  }
  actions.push({ status: "closed", label: tr("closeCase"), reason: tr("dispositionReasonClose") });
  return actions;
}

function caseDispositionControls(detail) {
  const status = detail.status || "open";
  const actions = dispositionActions(status);
  const allowed = hasAnyRole("analyst");
  return `
    <div class="case-disposition">
      <div class="case-disposition-head">
        <span>${escapeHtml(tr("caseDisposition"))}</span>
        <strong class="case-status ${escapeHtml(caseStatusClass(status))}">${escapeHtml(caseStatusLabel(status))}</strong>
      </div>
      <div class="case-disposition-actions">
        ${actions
          .map(
            (item) => `
              <button
                class="case-disposition-button"
                type="button"
                data-case-id="${escapeHtml(detail.case_id)}"
                data-status="${escapeHtml(item.status)}"
                data-reason="${escapeHtml(item.reason)}"
                ${allowed ? "" : `disabled title="${escapeHtml(tr("permissionDenied"))}"`}
              >${escapeHtml(item.label)}</button>
            `,
          )
          .join("")}
      </div>
      <p class="case-disposition-status" data-case-disposition-status="${escapeHtml(detail.case_id)}"></p>
    </div>
  `;
}

function evidenceValueText(item) {
  const value = item.value ?? item.text ?? item;
  if (value === null || value === undefined || value === "") return "-";
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch (err) {
    return String(value);
  }
}

function shouldCollapseText(value) {
  const lineCount = value.split(/\r\n|\r|\n/).length;
  return value.length > COLLAPSIBLE_TEXT_LIMIT || lineCount > COLLAPSIBLE_TEXT_LINE_LIMIT;
}

function collapsibleText(value) {
  const escaped = escapeHtml(value);
  if (!shouldCollapseText(value)) {
    return `<span class="evidence-value">${escaped}</span>`;
  }
  return `
    <div class="collapsible-text" data-expanded="false">
      <div class="collapsible-text-content">${escaped}</div>
      <button
        class="collapsible-text-toggle"
        type="button"
        aria-expanded="false"
        data-expand-label="${escapeHtml(tr("expandLongText"))}"
        data-collapse-label="${escapeHtml(tr("collapseLongText"))}"
      >${escapeHtml(tr("expandLongText"))}</button>
    </div>
  `;
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
          <td>${collapsibleText(evidenceValueText(item))}</td>
          <td>${escapeHtml(item.weight || item.source || "-")}</td>
        </tr>
      `,
    )
    .join("");
}

function reviewTools(raw) {
  const alertId = raw.alert_id || "";
  if (!alertId) return "";
  const allowed = hasAnyRole("analyst", "memory");
  return `
    <div class="review-tools">
      <button class="review-button" type="button" data-alert-id="${escapeHtml(alertId)}" ${allowed ? "" : `disabled title="${escapeHtml(tr("permissionDenied"))}"`}>
        ${escapeHtml(tr("confirmFalsePositive"))}
      </button>
      <p class="review-status" data-alert-status="${escapeHtml(alertId)}"></p>
    </div>
  `;
}

function validationStatusLabel(status) {
  return tr({ passed: "validationPassed", review: "validationReview", blocked: "validationBlocked" }[status] || "validationReview");
}

function validationBlock(validation) {
  if (!validation) return "";
  const findings = validation.findings || [];
  return `
    <div class="validation-gate ${escapeHtml(validation.status || "review")}">
      <div class="case-disposition-head">
        <span>${escapeHtml(tr("validationGate"))}</span>
        <strong>${escapeHtml(validationStatusLabel(validation.status))}</strong>
      </div>
      <ul class="plain-list">
        ${findings.length
          ? findings.map((item) => `<li><strong>${escapeHtml(item.code)}</strong> ${escapeHtml(item.message)}</li>`).join("")
          : `<li>${escapeHtml(tr("noValidationFindings"))}</li>`}
      </ul>
    </div>
  `;
}

function approvalStatusLabel(status) {
  return tr({ pending: "approvalPending", approved: "approvalApproved", rejected: "approvalRejected", cancelled: "approvalCancelled" }[status] || "approvalPending");
}

function approvalProgressText(approval) {
  const count = Number(approval?.vote_count);
  const required = Number(approval?.required_approvals);
  if (!Number.isInteger(count) || count < 0 || !Number.isInteger(required) || required < 1) return "";
  return tr("approvalProgress", { count, required });
}

function approvalDecisionMessage(approval) {
  const count = Number(approval?.vote_count);
  const required = Number(approval?.required_approvals);
  if (Number.isInteger(count) && count >= 0 && Number.isInteger(required) && required > 0) {
    return tr("approvalVoteSaved", { count, required, status: approvalStatusLabel(approval.status) });
  }
  return tr("approvalSaved", { status: approvalStatusLabel(approval.status) });
}

function approvalBlock(approvals, caseId) {
  return `
    <div class="approval-queue">
      <h4>${escapeHtml(tr("approvalQueue"))}</h4>
      ${(approvals || []).length
        ? approvals.map((item) => `
            <article class="approval-item ${escapeHtml(item.status)}">
              <div class="case-disposition-head">
                <strong>${escapeHtml(approvalStatusLabel(item.status))}</strong>
                <span>${escapeHtml(tr("executionNotRun"))}</span>
              </div>
              <p>${escapeHtml(item.action?.action || "")}</p>
              <small>${escapeHtml(item.action?.rationale || "")}</small>
              ${approvalProgressText(item) ? `<small class="approval-progress">${escapeHtml(approvalProgressText(item))}</small>` : ""}
              <dl class="kv"><dt>${escapeHtml(tr("rollbackCondition"))}</dt><dd>${escapeHtml(item.action?.rollback || "-")}</dd></dl>
              ${item.status === "pending" ? `
                <div class="approval-actions">
                  <button type="button" class="approval-decision" data-case-id="${escapeHtml(caseId)}" data-approval-id="${escapeHtml(item.approval_id)}" data-decision="approved" ${hasAnyRole("approver") ? "" : `disabled title="${escapeHtml(tr("permissionDenied"))}"`}>${escapeHtml(tr("approveAction"))}</button>
                  <button type="button" class="approval-decision" data-case-id="${escapeHtml(caseId)}" data-approval-id="${escapeHtml(item.approval_id)}" data-decision="rejected" ${hasAnyRole("approver") ? "" : `disabled title="${escapeHtml(tr("permissionDenied"))}"`}>${escapeHtml(tr("rejectAction"))}</button>
                </div>
              ` : ""}
            </article>
          `).join("")
        : `<p class="empty">${escapeHtml(tr("noApprovals"))}</p>`}
      <p class="approval-status" data-approval-status="${escapeHtml(caseId)}"></p>
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
  const validation = detail.validation_runs?.[0] || latestRun.explanation?.validation;

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
        ${caseDispositionControls(detail)}
        ${validationBlock(validation)}
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
        ${approvalBlock(detail.approvals || [], detail.case_id)}
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
      <span class="case-status ${escapeHtml(caseStatusClass(item.status))}">${escapeHtml(caseStatusLabel(item.status))}</span>
      <span class="case-summary">${escapeHtml(item.summary)}</span>
      <span class="linked-count">${escapeHtml(tr("alertCountLong", { count: item.alert_count || 0 }))}</span>
      <small class="case-time">${fmtTime(item.created_at_ms)}</small>
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
  bindDetailActions(panel, caseId);
}

function bindDetailActions(panel, caseId) {
  panel.querySelectorAll(".case-disposition-button").forEach((button) => {
    button.addEventListener("click", () => updateCaseDisposition(button, caseId));
  });
  panel.querySelectorAll(".review-button").forEach((button) => {
    button.addEventListener("click", () => confirmBusinessFalsePositive(button, caseId));
  });
  panel.querySelectorAll(".approval-decision").forEach((button) => {
    button.addEventListener("click", () => decideApproval(button, panel, caseId));
  });
}

async function decideApproval(button, panel, caseId) {
  const decision = button.dataset.decision;
  const reason = window.prompt(tr("approvalReasonPrompt"), tr("approvalDecisionDefault"));
  if (reason === null) return;
  const statusNode = panel.querySelector(`[data-approval-status="${CSS.escape(caseId)}"]`);
  const buttons = [...panel.querySelectorAll(".approval-decision")];
  buttons.forEach((item) => { item.disabled = true; });
  try {
    const result = await json(`/api/approvals/${encodeURIComponent(button.dataset.approvalId)}/decision`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ decision, reason: reason.trim() || tr("approvalDecisionDefault") }),
    });
    const detail = detailCache.get(caseId);
    detail.approvals = (detail.approvals || []).map((item) => item.approval_id === result.approval.approval_id ? result.approval : item);
    panel.innerHTML = renderDetail(detail);
    bindDetailActions(panel, caseId);
    const message = approvalDecisionMessage(result.approval);
    panel.querySelector(`[data-approval-status="${CSS.escape(caseId)}"]`).textContent = message;
    showToast(message);
  } catch (err) {
    buttons.forEach((item) => { item.disabled = false; });
    const message = tr("approvalFailed", { message: err.message || String(err) });
    if (statusNode) statusNode.textContent = message;
    showToast(message, "error");
  }
}

async function updateCaseDisposition(button, caseId) {
  const status = button.dataset.status;
  const statusNode = document.querySelector(`[data-case-disposition-status="${CSS.escape(caseId)}"]`);
  const buttons = [...document.querySelectorAll(`.case-disposition-button[data-case-id="${CSS.escape(caseId)}"]`)];
  buttons.forEach((item) => {
    item.disabled = true;
  });
  if (statusNode) statusNode.textContent = caseStatusLabel(status);
  try {
    const result = await json(`/api/cases/${encodeURIComponent(caseId)}/disposition`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status,
        reason: button.dataset.reason || "",
      }),
    });
    detailCache.set(caseId, { ...detailCache.get(caseId), ...result.case });
    if (statusNode) statusNode.textContent = tr("dispositionSaved", { status: caseStatusLabel(result.case.status) });
    await loadCases();
    showToast(tr("dispositionSaved", { status: caseStatusLabel(result.case.status) }));
  } catch (err) {
    buttons.forEach((item) => {
      item.disabled = false;
    });
    const message = err.message || String(err);
    if (statusNode) statusNode.textContent = tr("dispositionFailed", { message });
    showToast(tr("dispositionFailed", { message }), "error");
  }
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

function toggleCollapsibleText(button) {
  const wrapper = button.closest(".collapsible-text");
  if (!wrapper) return;
  const expanded = wrapper.dataset.expanded === "true";
  const nextExpanded = !expanded;
  wrapper.dataset.expanded = String(nextExpanded);
  button.setAttribute("aria-expanded", String(nextExpanded));
  button.textContent = nextExpanded ? button.dataset.collapseLabel : button.dataset.expandLabel;
}

function memoryStatusLabel(status) {
  const key = {
    active: "memoryStatusActive",
    pending_approval: "memoryStatusPending",
    quarantined: "memoryStatusQuarantined",
    revoked: "memoryStatusRevoked",
    expired: "memoryStatusExpired",
  }[status];
  return key ? tr(key) : text(status);
}

function memoryLayerLabel(layer) {
  const key = {
    case_short_term: "memoryLayerCase",
    product_long_term: "memoryLayerProduct",
    asset_profile: "memoryLayerAsset",
    org_knowledge: "memoryLayerOrg",
    evidence: "memoryLayerEvidence",
  }[layer];
  return key ? tr(key) : text(layer);
}

function memoryEventLabel(eventType) {
  const key = {
    proposed: "memoryEventProposed",
    promoted: "memoryEventPromoted",
    rejected: "memoryEventRejected",
    quarantined: "memoryEventQuarantined",
    expired: "memoryEventExpired",
    conflict_detected: "memoryEventConflict",
    restored: "memoryEventRestored",
    restored_for_review: "memoryEventRestoredReview",
    human_confirmed_business_false_positive: "memoryEventHumanConfirmed",
    asset_profile_recorded: "memoryEventAssetRecorded",
  }[eventType];
  return key ? tr(key) : text(eventType).replaceAll("_", " ");
}

function memoryContentObject(content) {
  if (typeof content !== "string") return content || {};
  try {
    return JSON.parse(content);
  } catch (err) {
    return content;
  }
}

function memoryContentSummary(memory) {
  const content = memoryContentObject(memory.content);
  if (typeof content === "string") return content.slice(0, 140);
  const value = content.summary || content.verdict || content.confirmation_reason || content.content;
  if (value) return text(value).slice(0, 140);
  return text(memory.retrieval_key || memory.scope || memory.memory_id);
}

function memoryFilterQuery() {
  const params = new URLSearchParams({ include_expired: "true", limit: "500" });
  const values = {
    q: document.querySelector("#memory-filter-query")?.value.trim(),
    layer: document.querySelector("#memory-filter-layer")?.value,
    status: document.querySelector("#memory-filter-status")?.value,
    namespace: document.querySelector("#memory-filter-namespace")?.value.trim(),
  };
  for (const [key, value] of Object.entries(values)) {
    if (value) params.set(key, value);
  }
  return params.toString();
}

function renderMemorySummary(summary = {}) {
  const status = summary.by_status || {};
  const values = {
    "#memory-total": summary.total || 0,
    "#memory-active": status.active || 0,
    "#memory-pending": status.pending_approval || 0,
    "#memory-quarantined": status.quarantined || 0,
    "#memory-overdue": summary.overdue_review || 0,
  };
  for (const [selector, value] of Object.entries(values)) {
    const node = document.querySelector(selector);
    if (node) node.textContent = String(value);
  }
}

function renderMemoryList() {
  const list = document.querySelector("#memory-list");
  if (!list) return;
  if (!memoryItems.length) {
    list.innerHTML = `<p class="empty-state">${escapeHtml(tr("memoryNoResults"))}</p>`;
    return;
  }
  list.innerHTML = `
    <div class="memory-list-count">${escapeHtml(tr("memoryCount", { count: memoryItems.length }))}</div>
    ${memoryItems.map((memory) => `
      <button
        type="button"
        class="memory-row ${memory.memory_id === selectedMemoryId ? "selected" : ""}"
        data-memory-id="${escapeHtml(memory.memory_id)}"
      >
        <span class="memory-row-top">
          <strong>${escapeHtml(memoryLayerLabel(memory.layer))}</strong>
          <span class="memory-status ${escapeHtml(memory.status.replaceAll("_", "-"))}">${escapeHtml(memoryStatusLabel(memory.status))}</span>
        </span>
        <span class="memory-row-summary">${escapeHtml(memoryContentSummary(memory))}</span>
        <span class="memory-row-meta">
          <code>${escapeHtml(memory.namespace)}</code>
          <time>${escapeHtml(fmtTime(memory.updated_at_ms))}</time>
        </span>
      </button>
    `).join("")}
  `;
  list.querySelectorAll(".memory-row").forEach((button) => {
    button.addEventListener("click", () => selectMemory(button.dataset.memoryId));
  });
}

function memoryGateRows(gates) {
  const rows = [
    ["evidence_traceable", "memoryGateEvidence"],
    ["analyst_approved", "memoryGateApprover"],
    ["scope_clear", "memoryGateScope"],
    ["expiry_set", "memoryGateExpiry"],
    ["no_sensitive_leak", "memoryGateSensitive"],
  ];
  return rows.map(([name, label]) => {
    const passed = Boolean(gates[name]);
    return `
      <li class="${passed ? "passed" : "failed"}">
        <span aria-hidden="true">${passed ? "✓" : "!"}</span>
        <strong>${escapeHtml(tr(label))}</strong>
        <small>${escapeHtml(tr(passed ? "memoryGatePass" : "memoryGateFail"))}</small>
      </li>
    `;
  }).join("");
}

function defaultMemoryExpiry(memory) {
  const current = Number(memory.expires_at_ms || 0);
  const minimum = Date.now() + 24 * 3600 * 1000;
  return formatDatetimeLocal(new Date(Math.max(current, Date.now() + 90 * 24 * 3600 * 1000, minimum)));
}

function memoryMatchDecisionLabel(decision, finalEffect) {
  const value = decision || finalEffect || "ignored";
  const key = {
    downgraded_to_benign: "memoryMatchDowngraded",
    classification_reinforced: "memoryMatchReinforced",
    attack_signal_veto: "memoryMatchAttackVeto",
    review_only: "memoryMatchReview",
    review: "memoryMatchReview",
    apply: "memoryMatchEligible",
    ignored: "memoryMatchIgnored",
  }[value];
  return key ? tr(key) : text(value).replaceAll("_", " ");
}

function memoryScorePercent(value) {
  return `${Math.round(Number(value || 0) * 100)}%`;
}

function renderMemoryAssociations(matches) {
  if (!matches.length) {
    return `<p class="empty-state">${escapeHtml(tr("memoryAssociationsEmpty"))}</p>`;
  }
  return `
    <div class="memory-association-list">
      ${matches.slice(0, 50).map((match) => `
        <article class="memory-association-row">
          <div class="memory-association-heading">
            <span>
              <strong>${escapeHtml(match.alert_id)}</strong>
              <code>${escapeHtml(match.case_id)} · ${escapeHtml(match.event_id)}</code>
            </span>
            <span class="memory-match-decision ${escapeHtml(match.decision.replaceAll("_", "-"))}">
              ${escapeHtml(memoryMatchDecisionLabel(match.decision, match.final_effect))}
            </span>
          </div>
          <div class="memory-score-grid">
            <span><small>${escapeHtml(tr("memoryMatchOverall"))}</small><strong>${escapeHtml(memoryScorePercent(match.overall_score))}</strong></span>
            <span><small>${escapeHtml(tr("memoryMatchStructured"))}</small><strong>${escapeHtml(memoryScorePercent(match.structured_score))}</strong></span>
            <span><small>${escapeHtml(tr("memoryMatchSemantic"))}</small><strong>${escapeHtml(memoryScorePercent(match.semantic_score))}</strong></span>
            <span><small>${escapeHtml(tr("memoryMatchRetrieval"))}</small><strong>${escapeHtml(memoryScorePercent(match.retrieval_score))}</strong></span>
          </div>
          <div class="memory-score-bar" aria-hidden="true"><i style="width:${Math.min(100, Math.max(0, Number(match.overall_score || 0) * 100))}%"></i></div>
          <div class="memory-matched-features">
            ${(match.matched_features || []).slice(0, 8).map((feature) => `<code>${escapeHtml(feature)}</code>`).join("")}
          </div>
          <small class="memory-association-time">${escapeHtml(match.matcher_version)} · ${escapeHtml(fmtTime(match.created_at_ms))}</small>
        </article>
      `).join("")}
    </div>
  `;
}

function renderMemoryDetail(memory) {
  const container = document.querySelector("#memory-detail");
  if (!container) return;
  const governance = memory.governance || {};
  const status = memory.status;
  const canPromote = governance.actionable && status !== "active";
  const canReject = governance.actionable && status !== "revoked";
  const canQuarantine = governance.actionable && status !== "quarantined";
  const canRestore = governance.actionable && ["quarantined", "revoked", "expired"].includes(status);
  const canGovern = hasAnyRole("memory");
  const content = memoryContentObject(memory.content);
  container.innerHTML = `
    <div class="memory-detail-heading">
      <div>
        <code>${escapeHtml(memory.memory_id)}</code>
        <h3>${escapeHtml(memoryContentSummary(memory))}</h3>
      </div>
      <span class="memory-status ${escapeHtml(status.replaceAll("_", "-"))}">${escapeHtml(memoryStatusLabel(status))}</span>
    </div>
    <dl class="memory-meta-grid">
      <div><dt>${escapeHtml(tr("memoryLayer"))}</dt><dd>${escapeHtml(memoryLayerLabel(memory.layer))}</dd></div>
      <div><dt>${escapeHtml(tr("memoryNamespace"))}</dt><dd>${escapeHtml(memory.namespace)}</dd></div>
      <div><dt>${escapeHtml(tr("memoryRetrievalKey"))}</dt><dd>${escapeHtml(memory.retrieval_key)}</dd></div>
      <div><dt>${escapeHtml(tr("memoryTrust"))}</dt><dd>${escapeHtml(memory.trust_level)}</dd></div>
      <div><dt>${escapeHtml(tr("memorySourceCase"))}</dt><dd>${escapeHtml(memory.source_case_id)}</dd></div>
      <div><dt>${escapeHtml(tr("memoryScope"))}</dt><dd>${escapeHtml(memory.scope)}</dd></div>
      <div><dt>${escapeHtml(tr("memoryApprover"))}</dt><dd>${escapeHtml(memory.approved_by)}</dd></div>
      <div><dt>${escapeHtml(tr("memoryExpires"))}</dt><dd>${escapeHtml(fmtTime(memory.expires_at_ms))}</dd></div>
      <div><dt>${escapeHtml(tr("memoryCreated"))}</dt><dd>${escapeHtml(fmtTime(memory.created_at_ms))}</dd></div>
      <div><dt>${escapeHtml(tr("memoryUpdated"))}</dt><dd>${escapeHtml(fmtTime(memory.updated_at_ms))}</dd></div>
    </dl>
    ${governance.actionable ? `
      <section class="memory-gates">
        <h4>${escapeHtml(tr("memoryGateStatus"))}</h4>
        <ul>${memoryGateRows(governance.gates || {})}</ul>
      </section>
    ` : ""}
    ${governance.actionable ? `
      <section class="memory-associations">
        <h4>${escapeHtml(tr("memoryAssociations"))}</h4>
        <p>${escapeHtml(tr("memoryAssociationsHint"))}</p>
        ${renderMemoryAssociations(governance.matches || [])}
      </section>
    ` : ""}
    <section class="memory-content-section">
      <h4>${escapeHtml(tr("memoryContent"))}</h4>
      <pre>${escapeHtml(typeof content === "string" ? content : JSON.stringify(content, null, 2))}</pre>
    </section>
    ${governance.actionable ? `
      <form id="memory-action-form" class="memory-action-form">
        <h4>${escapeHtml(tr("memoryGovernanceForm"))}</h4>
        <label>
          <span>${escapeHtml(tr("memoryAnalyst"))}</span>
          <input id="memory-action-actor" type="text" maxlength="500" value="${escapeHtml(currentActor())}" readonly />
        </label>
        <label>
          <span>${escapeHtml(tr("memoryPromotionScope"))}</span>
          <input id="memory-action-scope" type="text" maxlength="500" value="${escapeHtml(memory.scope)}" />
        </label>
        <label>
          <span>${escapeHtml(tr("memoryRetrievalKey"))}</span>
          <input id="memory-action-retrieval-key" type="text" maxlength="500" value="${escapeHtml(memory.retrieval_key)}" />
        </label>
        <label>
          <span>${escapeHtml(tr("memoryExpiry"))}</span>
          <input id="memory-action-expiry" type="datetime-local" value="${escapeHtml(defaultMemoryExpiry(memory))}" />
        </label>
        <label class="memory-reason-field">
          <span>${escapeHtml(tr("memoryReason"))}</span>
          <textarea id="memory-action-reason" rows="2" maxlength="500" placeholder="${escapeHtml(tr("memoryReasonPlaceholder"))}"></textarea>
        </label>
        <div class="memory-action-buttons">
          ${canPromote ? `<button type="button" data-memory-action="promote" data-memory-id="${escapeHtml(memory.memory_id)}" ${canGovern ? "" : "disabled"}>${escapeHtml(tr("memoryPromote"))}</button>` : ""}
          ${canReject ? `<button type="button" data-memory-action="reject" data-memory-id="${escapeHtml(memory.memory_id)}" ${canGovern ? "" : "disabled"}>${escapeHtml(tr("memoryReject"))}</button>` : ""}
          ${canQuarantine ? `<button type="button" data-memory-action="quarantine" data-memory-id="${escapeHtml(memory.memory_id)}" ${canGovern ? "" : "disabled"}>${escapeHtml(tr("memoryQuarantine"))}</button>` : ""}
          ${canRestore ? `<button type="button" data-memory-action="restore" data-memory-id="${escapeHtml(memory.memory_id)}" ${canGovern ? "" : "disabled"}>${escapeHtml(tr("memoryRestore"))}</button>` : ""}
        </div>
      </form>
    ` : ""}
    <section class="memory-detail-audit">
      <h4>${escapeHtml(tr("memoryAudit"))}</h4>
      <div id="memory-detail-audit-list" class="memory-audit-list compact"></div>
    </section>
  `;
  container.querySelectorAll("[data-memory-action]").forEach((button) => {
    button.addEventListener("click", () => governMemory(button.dataset.memoryAction, button));
  });
  renderMemoryAudit(governance.events || [], "#memory-detail-audit-list", false);
}

function renderMemoryAudit(events, selector, interactive = true) {
  const container = document.querySelector(selector);
  if (!container) return;
  if (!events.length) {
    container.innerHTML = `<p class="empty-state">${escapeHtml(tr("memoryAuditEmpty"))}</p>`;
    return;
  }
  container.innerHTML = events.map((event) => `
    <${interactive ? "button" : "div"} ${interactive ? "type=\"button\"" : ""} class="memory-audit-row" data-memory-id="${escapeHtml(event.memory_id)}">
      <span class="memory-audit-marker" aria-hidden="true"></span>
      <span class="memory-audit-main">
        <strong>${escapeHtml(memoryEventLabel(event.event_type))}</strong>
        <small>${escapeHtml(event.actor)} · ${escapeHtml(fmtTime(event.created_at_ms))}</small>
        <code>${escapeHtml(event.memory_id)}</code>
      </span>
      <span class="memory-audit-detail">${escapeHtml(JSON.stringify(event.detail || {}))}</span>
    </${interactive ? "button" : "div"}>
  `).join("");
  if (interactive) {
    container.querySelectorAll(".memory-audit-row").forEach((button) => {
      button.addEventListener("click", async () => {
        const memoryId = button.dataset.memoryId;
        setSecondaryView("memory", "inventory");
        document.querySelector("#memory-filter-form")?.reset();
        const query = document.querySelector("#memory-filter-query");
        if (query) query.value = memoryId;
        selectedMemoryId = memoryId;
        memoryItems = [];
        try {
          await loadMemoryInventory({ skipSelection: true });
          await selectMemory(memoryId);
        } catch (err) {
          showToast(tr("memoryActionFailed", { message: err.message || String(err) }), "error");
        }
      });
    });
  }
}

async function selectMemory(memoryId) {
  const requestId = ++memorySelectionRequestId;
  selectedMemoryId = memoryId;
  renderMemoryList();
  const container = document.querySelector("#memory-detail");
  if (container) container.innerHTML = `<p class="empty-state">${escapeHtml(tr("memoryLoading"))}</p>`;
  try {
    const detail = await json(`/api/memory/${encodeURIComponent(memoryId)}`);
    if (requestId !== memorySelectionRequestId || memoryId !== selectedMemoryId) return;
    selectedMemoryDetail = detail;
    renderMemoryDetail(selectedMemoryDetail);
  } catch (err) {
    if (requestId !== memorySelectionRequestId || memoryId !== selectedMemoryId) return;
    if (container) container.innerHTML = `<p class="empty-state">${escapeHtml(err.message || String(err))}</p>`;
  }
}

async function loadMemoryInventory(options = {}) {
  const list = document.querySelector("#memory-list");
  const status = document.querySelector("#memory-inventory-status");
  if (list && !options.quiet) list.innerHTML = `<p class="empty-state">${escapeHtml(tr("memoryLoading"))}</p>`;
  if (status) {
    status.textContent = "";
    status.classList.remove("error");
  }
  const [summaryResult, inventoryResult] = await Promise.allSettled([
    json("/api/memory/summary"),
    json(`/api/memory?${memoryFilterQuery()}`),
  ]);

  const errors = [];
  if (summaryResult.status === "fulfilled") {
    renderMemorySummary(summaryResult.value);
  } else {
    errors.push(summaryResult.reason?.message || String(summaryResult.reason));
  }
  if (inventoryResult.status === "rejected") {
    const message = inventoryResult.reason?.message || String(inventoryResult.reason);
    errors.push(message);
    if (list) list.innerHTML = `<p class="empty-state">${escapeHtml(message)}</p>`;
    if (status) {
      status.textContent = errors.join(" · ");
      status.classList.add("error");
    }
    return { errors };
  }

  memoryItems = inventoryResult.value.memories || [];
  if (selectedMemoryId && !memoryItems.some((item) => item.memory_id === selectedMemoryId)) {
    selectedMemoryId = "";
    selectedMemoryDetail = null;
  }
  renderMemoryList();
  if (options.skipSelection) {
    return { errors };
  }
  if (selectedMemoryId) {
    await selectMemory(selectedMemoryId);
  } else if (memoryItems.length) {
    await selectMemory(memoryItems[0].memory_id);
  } else {
    selectedMemoryDetail = null;
    const detail = document.querySelector("#memory-detail");
    if (detail) detail.innerHTML = `<p class="empty-state">${escapeHtml(tr("memorySelectPrompt"))}</p>`;
  }
  if (status && errors.length) {
    status.textContent = errors.join(" · ");
    status.classList.add("error");
  }
  return { errors };
}

async function loadMemoryAudit(options = {}) {
  const list = document.querySelector("#memory-audit-list");
  if (list && !options.quiet) list.innerHTML = `<p class="empty-state">${escapeHtml(tr("memoryLoading"))}</p>`;
  try {
    const audit = await json("/api/memory/events?limit=200");
    memoryAuditEvents = audit.events || [];
    renderMemoryAudit(memoryAuditEvents, "#memory-audit-list");
    return { errors: [] };
  } catch (err) {
    if (list) list.innerHTML = `<p class="empty-state">${escapeHtml(err.message || String(err))}</p>`;
    return { errors: [err] };
  }
}

async function loadMemoryGovernance(options = {}) {
  const section = options.section || "all";
  const tasks = [];
  if (section === "all" || section === "inventory") tasks.push(loadMemoryInventory(options));
  if (section === "all" || section === "audit") tasks.push(loadMemoryAudit(options));
  return Promise.all(tasks);
}

async function governMemory(action, button) {
  const memoryId = button.dataset.memoryId;
  if (!memoryId) return;
  const reason = document.querySelector("#memory-action-reason")?.value.trim() || "";
  const expiryValue = document.querySelector("#memory-action-expiry")?.value || "";
  const expiresAtMs = datetimeLocalMs(expiryValue);
  let payload;
  if (action === "promote") {
    const scope = document.querySelector("#memory-action-scope")?.value.trim() || "";
    if (!scope || !expiresAtMs || expiresAtMs <= Date.now()) {
      showToast(tr("memoryPromotionRequired"), "error");
      return;
    }
    payload = {
      scope,
      retrieval_key: document.querySelector("#memory-action-retrieval-key")?.value.trim() || "",
      expires_at_ms: expiresAtMs,
    };
  } else {
    if (!reason) {
      showToast(tr("memoryReasonRequired"), "error");
      return;
    }
    payload = { reason };
    if (action === "restore" && expiresAtMs && expiresAtMs > Date.now()) payload.expires_at_ms = expiresAtMs;
  }
  button.disabled = true;
  try {
    const result = await json(`/api/memory/${encodeURIComponent(memoryId)}/${action}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (action === "promote" && !result.ok) {
      throw new Error((result.reasons || []).join(", ") || "promotion gates failed");
    }
    showToast(tr("memoryActionDone", { id: selectedMemoryId, action: button.textContent.trim() }));
    if (selectedMemoryId === memoryId) await loadMemoryGovernance({ quiet: true });
  } catch (err) {
    showToast(tr("memoryActionFailed", { message: err.message || String(err) }), "error");
  } finally {
    button.disabled = false;
  }
}

async function sweepMemory() {
  const button = document.querySelector("#memory-sweep");
  button.disabled = true;
  try {
    const result = await json("/api/memory/sweep", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    showToast(tr("memorySweepDone", { expired: result.expired.length, conflicts: result.conflicts.length }));
    await loadMemoryGovernance({ quiet: true });
  } catch (err) {
    showToast(tr("memoryActionFailed", { message: err.message || String(err) }), "error");
  } finally {
    button.disabled = false;
  }
}

function setView(name) {
  document.querySelectorAll(".view").forEach((view) => view.classList.remove("active"));
  document.querySelector(`#${name}-view`).classList.add("active");
  document.querySelectorAll(".nav-button").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.view === name);
  });
  document.querySelectorAll(".nav-group").forEach((group) => {
    group.classList.toggle("active", group.dataset.viewGroup === name);
  });
  document.querySelectorAll(".nav-subbutton").forEach((btn) => {
    const current = btn.dataset.view === name && btn.classList.contains("active");
    if (current) btn.setAttribute("aria-current", "page");
    else btn.removeAttribute("aria-current");
  });
  updateWorkspaceTitle(name);
}

function setSecondaryView(group, name) {
  const tabs = [...document.querySelectorAll(`.nav-subbutton[data-secondary-group="${group}"]`)];
  const panels = [...document.querySelectorAll(`.secondary-view[data-secondary-panel="${group}"]`)];
  const selectedTab = tabs.find((tab) => tab.dataset.secondaryTarget === name);
  if (!selectedTab) return;

  tabs.forEach((tab) => {
    const selected = tab === selectedTab;
    tab.classList.toggle("active", selected);
    const current = selected && document.querySelector(".nav-button.active")?.dataset.view === tab.dataset.view;
    if (current) tab.setAttribute("aria-current", "page");
    else tab.removeAttribute("aria-current");
  });
  panels.forEach((panel) => {
    const selected = panel.dataset.secondaryName === name;
    panel.classList.toggle("active", selected);
    panel.hidden = !selected;
  });
}

function activeSecondaryView(group, fallback = "") {
  return document.querySelector(`.nav-subbutton.active[data-secondary-group="${group}"]`)?.dataset.secondaryTarget || fallback;
}

function loadViewData(name) {
  if (name === "settings") {
    return loadLlmConfig().catch((err) => setConfigStatus(err.message || String(err), true));
  }
  if (name === "memory") {
    return loadMemoryGovernance({ section: activeSecondaryView("memory", "inventory") }).catch((err) =>
      showToast(tr("memoryActionFailed", { message: err.message || String(err) }), "error"),
    );
  }
  if (name === "adapter") {
    const section = activeSecondaryView("adapter", "intake");
    const tasks = [
      loadSyslogConfig().catch((err) =>
        setSyslogConfigStatus(tr("syslogConfigLoadFailed", { message: err.message || String(err) }), true),
      ),
    ];
    if (section === "config") {
      tasks.push(loadMappingProfiles().catch((err) => setProfileStatus(err.message || String(err), true)));
    }
    return Promise.all(tasks);
  }
  return loadCases();
}

function refreshCurrentView() {
  const active = document.querySelector(".nav-button.active")?.dataset.view || "monitor";
  return loadViewData(active);
}

async function loadDashboardRuntime() {
  const llmFallback = { provider: "unavailable", model: "-", endpoint: "", unavailable: true };
  const syslogFallback = { configs: syslogConfigs, listeners: [], unavailable: true };
  const caseQuery = caseSearchQuery();
  const [health, casesData, llmConfig, syslogPayload] = await Promise.all([
    json("/api/health", { acceptStatuses: [503] }),
    canReadCases() ? json(`/api/cases?${caseQuery}`) : Promise.resolve({ cases: [] }),
    canReadRuntimeConfig()
      ? json("/api/config/llm").catch(() => llmFallback)
      : Promise.resolve(llmFallback),
    canReadRuntimeConfig()
      ? json("/api/config/syslog").catch(() => syslogFallback)
      : Promise.resolve(syslogFallback),
  ]);
  return { health, cases: casesData.cases || [], llmConfig, syslogPayload };
}

async function loadCases(options = {}) {
  const list = document.querySelector("#cases-list");
  try {
    const { health, cases, llmConfig, syslogPayload } = await loadDashboardRuntime();
    renderDashboard(health, cases, llmConfig, syslogPayload);
    list.innerHTML = "";
    detailCache.clear();
    if (!cases.length) {
      list.innerHTML = `<div class="empty-state">${escapeHtml(tr("noCases"))}</div>`;
      return;
    }
    for (const item of cases) {
      list.appendChild(renderCase(item));
    }
  } catch (err) {
    if (list) list.innerHTML = `<div class="empty-state">${escapeHtml(err.stack || String(err))}</div>`;
    if (!options.quiet) showToast(tr("refreshFailed", { message: err.message || String(err) }), "error");
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
  inferredFields = [];
  lastFieldMappingResult = null;
  renderFieldMappingTable(null);
  document.querySelector("#dry-run-result").textContent = tr("dryRunHint");
  inferredProfile = profile ? JSON.parse(JSON.stringify(profile)) : null;
  setProfileJson(inferredProfile);
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
  const model = document.querySelector("#llm-model");
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
    if (!endpoint.value.trim() || endpoint.value.includes("127.0.0.1:11434")) {
      endpoint.value = "https://kkcoder.com/v1/messages";
    }
    if (!model.value.trim() || ["local-rule-analyst", "gemma3:4b", "gemma3:latest"].includes(model.value.trim())) {
      model.value = "claude-sonnet-4-6";
    }
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

async function testLlmConnection() {
  const button = document.querySelector("#test-llm-connection");
  const originalText = button.textContent;
  button.disabled = true;
  button.textContent = tr("testConnecting");
  try {
    const payload = {
      provider: document.querySelector("#llm-provider").value,
      endpoint: document.querySelector("#llm-endpoint").value,
      model: document.querySelector("#llm-model").value,
      api_key: document.querySelector("#llm-api-key").value,
      timeout_seconds: Number(document.querySelector("#llm-timeout").value || 30),
    };
    const result = await json("/api/config/llm/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      timeoutMs: Math.max(REQUEST_TIMEOUT_MS, payload.timeout_seconds * 1000 + 5_000),
    });
    if (result.ok) {
      setConfigStatus(tr("testConnOk", { message: result.message }));
      showToast(tr("testConnOk", { message: result.message }));
    } else {
      setConfigStatus(tr("testConnFailed", { message: result.message }), true);
      showToast(tr("testConnFailed", { message: result.message }), "error");
    }
  } catch (err) {
    const message = err.message || String(err);
    setConfigStatus(tr("testConnFailed", { message }), true);
  } finally {
    button.disabled = false;
    button.textContent = originalText;
  }
}

loadLanguagePreference();
loadThemePreference();
loadRefreshPreference();

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

document.querySelector("#refresh").addEventListener("click", () => {
  refreshCurrentView().catch((err) => showToast(err.message || String(err), "error"));
});
document.querySelector("#test-llm-connection").addEventListener("click", () => {
  testLlmConnection().catch((err) => setConfigStatus(err.message || String(err), true));
});
document.querySelector("#case-search-form").addEventListener("submit", (event) => {
  event.preventDefault();
  loadCases().catch((err) => showToast(err.message || String(err), "error"));
});
document.querySelector("#case-search-reset").addEventListener("click", () => {
  document.querySelector("#case-search-form").reset();
  setDefaultCaseDateRange();
  loadCases().catch((err) => showToast(err.message || String(err), "error"));
});
document.querySelector("#case-filter-to").addEventListener("input", () => {
  caseToUsesCurrentTime = false;
});
document.querySelector("#memory-filter-form").addEventListener("submit", (event) => {
  event.preventDefault();
  loadMemoryGovernance().catch((err) => showToast(tr("memoryActionFailed", { message: err.message || String(err) }), "error"));
});
document.querySelector("#memory-filter-reset").addEventListener("click", () => {
  document.querySelector("#memory-filter-form").reset();
  loadMemoryGovernance().catch((err) => showToast(tr("memoryActionFailed", { message: err.message || String(err) }), "error"));
});
document.querySelector("#memory-sweep").addEventListener("click", sweepMemory);
document.querySelector("#memory-audit-refresh").addEventListener("click", () => {
  loadMemoryAudit({ quiet: true }).catch((err) =>
    showToast(tr("memoryActionFailed", { message: err.message || String(err) }), "error"),
  );
});
document.querySelector("#refresh-mode-toggle").addEventListener("click", () => {
  saveRefreshPreference(!refreshPaused);
});
document.addEventListener("click", (event) => {
  const button = event.target.closest(".collapsible-text-toggle");
  if (!button) return;
  toggleCollapsibleText(button);
});
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
document.querySelector("#reset-syslog-config").addEventListener("click", fillDefaultSyslogConfigs);
document.querySelector("#dry-run-form").addEventListener("submit", (event) => {
  runDryRun(event).catch((err) => {
    document.querySelector("#dry-run-result").textContent = err.message || String(err);
    showToast(tr("dryRunError", { message: err.message || String(err) }), "error");
  });
});
document.querySelectorAll(".nav-button").forEach((btn) => {
  btn.addEventListener("click", () => {
    setView(btn.dataset.view);
    if (btn.dataset.secondaryGroup) {
      const activeChild = document.querySelector(
        `.nav-subbutton.active[data-secondary-group="${btn.dataset.secondaryGroup}"]`,
      );
      setSecondaryView(
        btn.dataset.secondaryGroup,
        activeChild?.dataset.secondaryTarget || btn.dataset.defaultSecondary,
      );
    }
    loadViewData(btn.dataset.view);
  });
});
document.querySelectorAll(".nav-subbutton").forEach((btn) => {
  btn.addEventListener("click", () => {
    setView(btn.dataset.view);
    setSecondaryView(btn.dataset.secondaryGroup, btn.dataset.secondaryTarget);
    loadViewData(btn.dataset.view);
  });
});

async function loadApplicationData() {
  await loadSession();
  const tasks = [
    loadSampleLog(selectedLogProduct()),
    loadCases(),
  ];
  if (canReadRuntimeConfig()) {
    tasks.push(loadLlmConfig(), loadSyslogConfig());
  }
  if (canReadMappingProfiles()) {
    tasks.push(loadMappingProfiles());
  }
  return Promise.all(tasks);
}

document.querySelector("#auth-session").addEventListener("click", () => showAuthDialog());
document.querySelector("#auth-close").addEventListener("click", () => document.querySelector("#auth-dialog").close());
document.querySelector("#auth-clear").addEventListener("click", async () => {
  storeApiToken("");
  currentSession = { actor: "", roles: [] };
  applySessionPermissions();
  document.querySelector("#auth-token").value = "";
  document.querySelector("#auth-status").textContent = tr("authCleared");
  try {
    await loadSession();
    document.querySelector("#auth-status").textContent = sessionIdentityText() || tr("authCleared");
  } catch (err) {
    document.querySelector("#auth-status").textContent = err.status === 401 ? tr("authRequired") : err.message || String(err);
  }
});
document.querySelector("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  storeApiToken(document.querySelector("#auth-token").value);
  try {
    await loadApplicationData();
    document.querySelector("#auth-status").textContent = tr("authConnected");
    document.querySelector("#auth-dialog").close();
  } catch (err) {
    document.querySelector("#auth-status").textContent = err.status === 401 ? tr("authRequired") : err.message || String(err);
  }
});

setDefaultCaseDateRange();
renderLogProductOptions();
loadApplicationData().catch((err) =>
  showToast(err.message || String(err), "error"),
);
scheduleDashboardRefresh();
