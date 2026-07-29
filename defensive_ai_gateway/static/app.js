const detailCache = new Map();
const THEME_KEY = "dashboard-theme";
const LANGUAGE_KEY = "dashboard-language";
const API_TOKEN_KEY = "defensive-ai-api-token";
const SYSLOG_CONFIG_KEY = "dashboard-syslog-intake-config";
const REFRESH_PAUSED_KEY = "dashboard-refresh-paused";
const LEGACY_OFFLINE_MODE_KEY = "dashboard-offline-mode";
const COLLAPSIBLE_TEXT_LIMIT = 280;
const COLLAPSIBLE_TEXT_LINE_LIMIT = 8;
const DASHBOARD_REFRESH_MS = 10_000;
const OLLAMA_MODEL_REFRESH_MS = 15000;
const REQUEST_TIMEOUT_MS = 30_000;
const PAGE_SIZE_OPTIONS = [10, 20, 50, 100];
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
    dashboardSecondaryNav: "处置台二级目录",
    dashboardSubPending: "待处理队列",
    dashboardSubHistory: "处理记录",
    navMemory: "记忆治理",
    navAdapter: "日志接入",
    navAutomation: "自动化处置",
    navSettings: "运行配置",
    memorySecondaryNav: "记忆治理二级目录",
    memorySubInventory: "记忆清单",
    memorySubAudit: "治理审计",
    adapterSecondaryNav: "日志接入二级目录",
    adapterSubIntake: "告警接入",
    adapterSubConfig: "日志配置",
    automationSecondaryNav: "自动化处置二级目录",
    automationSubTasks: "执行任务",
    automationSubConnectors: "连接器",
    automationSubPolicy: "处置策略",
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
    workspaceEyebrow: "安全运营",
    workspaceTitle: "实时监控大屏",
    workspaceTitleMonitor: "实时监控大屏",
    workspaceTitleDashboard: "告警处置队列",
    workspaceTitleHistory: "告警处理记录",
    workspaceTitleTriage: "研判与处置",
    workspaceTitleMemory: "记忆治理工作台",
    workspaceTitleMemoryAssociations: "关联告警清单",
    workspaceTitleAdapter: "日志接入",
    workspaceTitleAutomation: "自动化处置",
    workspaceTitleSettings: "运行配置",
    automationTotal: "任务总量",
    automationActive: "处理中",
    automationVerified: "已生效",
    automationFailed: "执行异常",
    automationTasks: "执行任务",
    automationTasksHint: "跟踪审批后的调度、设备核验、到期解封和回滚结果。",
    automationStatus: "任务状态",
    automationConnectorConfig: "连接器配置",
    automationConnectorHint: "配置 WAF 或边界防火墙动作接口；凭据仅填写环境变量名。",
    configuredConnectors: "已配置连接器",
    configuredConnectorsHint: "真实执行前必须通过非破坏性健康检查。",
    connectorName: "连接器名称",
    connectorEndpoint: "API 地址",
    connectorSecretEnv: "凭据环境变量",
    connectorMode: "执行模式",
    connectorModeShadow: "影子",
    connectorModeManual: "手工调度",
    connectorModeAuto: "审批后自动执行",
    connectorMaxTtl: "最大封禁时长（秒）",
    connectorTimeout: "调用超时（秒）",
    connectorEnabled: "启用连接器",
    connectorHealth: "健康状态",
    connectorHealthUntested: "未检查",
    connectorHealthHealthy: "连接正常",
    connectorHealthError: "连接异常",
    connectorCredentialReady: "凭据已配置",
    connectorCredentialMissing: "凭据未配置",
    connectorTest: "测试连接",
    connectorEdit: "编辑",
    connectorSaved: "连接器已保存",
    connectorTested: "连接器检查结果：{status}",
    automationPolicy: "处置策略",
    automationPolicyHint: "设置全局执行开关、封禁时效和受保护网络对象。",
    automationEnabled: "允许调度处置任务",
    automationDefaultTtl: "默认封禁时长（秒）",
    automationMaxTtl: "全局最大时长（秒）",
    automationProtectedCidrs: "受保护 CIDR",
    automationPolicySaved: "处置策略已保存",
    responseWaitingConfiguration: "待配置",
    responseWaitingDispatch: "待调度",
    responsePaused: "已暂停",
    responseQueued: "已入队",
    responseRunning: "执行中",
    responseRetryWait: "等待重试",
    responseVerified: "已生效",
    responseShadowed: "影子执行",
    responseFailed: "执行失败",
    responseCancelled: "已取消",
    responseRollbackQueued: "等待回滚",
    responseRollbackRunning: "回滚中",
    responseRollbackRetry: "回滚重试",
    responseRolledBack: "已回滚",
    responseRollbackFailed: "回滚失败",
    responseTaskEmpty: "暂无自动化处置任务。",
    responseConnectorEmpty: "尚未配置处置连接器。",
    responseTaskId: "任务 ID",
    responseActionBlockSourceIp: "临时封禁源 IP",
    responseObject: "处置对象",
    responseScope: "作用范围",
    responseMode: "执行模式",
    responseRemoteRule: "远端规则",
    responseExpires: "到期时间",
    responseDispatch: "立即调度",
    responseRollback: "回滚",
    responseActionPlan: "自动化动作",
    responseNoActionPlan: "该审批建议不会转换为自动执行动作。",
    responseTaskCreated: "已创建处置任务：{status}",
    responseActionDone: "任务状态已更新：{status}",
    applyFilter: "应用筛选",
    dashboardEyebrow: "安全运营实时概览",
    dashboardTitle: "实时监控大屏",
    dashboardSubtitle: "集中监控告警趋势、处置压力、接入健康和模型运行状态。",
    footer: "© 2026 防御式 AI 网关 · TC 设计与研发",
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
    distributionHint: "按安全产品聚合全部 Case，快速定位噪声来源和重点防线。",
    handlingTitle: "处置结论",
    handlingHint: "按全部 Case 的研判结论观察真实攻击、待复核与误报占比。",
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
    modelCredentialMissing: "Gateway 未配置部署凭据，告警已保留在待恢复队列。",
    modelDurableRetry: "模型暂不可用，告警等待恢复调度（约 {seconds} 秒后）。",
    modelDeferredBacklog: "远程模型待恢复分析：{count} 条告警。",
    syslogActive: "{active}/{total} 个监听在线",
    syslogInactive: "未启用监听",
    httpActive: "HTTP 接入在线",
    noDistribution: "暂无分布数据",
    refresh: "刷新",
    alerts: "告警总量",
    highCritical: "高危与严重",
    latestCases: "Case 队列",
    latestCasesHint: "按创建时间排序，处置后队列顺序保持不变。",
    triageEyebrow: "Alert triage",
    triageTitle: "聚焦当前需要决策的告警",
    triageSubtitle: "从待处理队列中选择一条 Case，进入研判与处置页面。",
    triageOpen: "待处置",
    triageReview: "人工复核",
    triagePriority: "高危/严重",
    triageAll: "全部",
    triageConfirmed: "确认攻击",
    triageCompleted: "已完成",
    triageFilterToggle: "筛选",
    triageFilterHide: "收起筛选",
    triageQueue: "待处理队列",
    triageQueueHint: "仅显示尚未完成的 Case；点击一条记录进入研判与处置。",
    processedQueue: "处理记录",
    processedQueueHint: "保留已完成处置的 Case，支持按条件检索并追溯历史研判。",
    triageDetail: "研判与处置",
    triageDetailHint: "完成研判、处置与审批；详细信息按需在独立页面中查看。",
    triageBack: "返回待处理队列",
    triageBackHistory: "返回处理记录",
    triageSelectPrompt: "从待处理队列选择一条 Case，开始研判与处置。",
    triageResultCount: "显示 {shown} / {total} 条",
    paginationRange: "第 {start}-{end} 条，共 {total} 条",
    paginationPage: "第 {page} / {pages} 页",
    paginationSize: "每页",
    paginationPrevious: "上一页",
    paginationNext: "下一页",
    triageNoResults: "当前没有待处理 Case。",
    processedNoResults: "当前没有符合条件的处理记录。",
    viewCase: "进入 Case {id} 的研判与处置",
    triageAlertVolume: "关联告警",
    triageDetails: "详细信息",
    triageDetailsHint: "原始数据、归一化证据和运行记录在独立页面中按需查看。",
    detailRawAlertsHint: "查看关联告警的完整原始载荷与处置状态。",
    detailEvidenceHint: "查看结构化实体、证据和敏感标签。",
    detailRunsHint: "查看分析结果与验证记录。",
    responsePackTitle: "AI 响应工作台",
    responsePackHint: "按需生成证据约束的摘要、时间线、遏制建议、Playbook 与内部沟通草稿。",
    responsePackBadge: "按需生成",
    detailOpen: "打开详情",
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
    memoryAssociationsOpen: "查看清单",
    memoryAssociationsBack: "返回治理详情",
    memoryAssociationsBreadcrumb: "记忆治理 / 关联告警",
    memoryAssociationsPageTitle: "关联告警清单",
    memoryAssociationsRecordCount: "关联记录",
    memoryAssociationsRecords: "匹配记录",
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
    syslogDeploymentTitle: "Syslog 接入部署",
    syslogDeploymentHint: "集中维护安全设备的发送目标与来源网段。",
    syslogCollectorAddress: "Collector 对外地址",
    syslogCollectorAddressPlaceholder: "LoadBalancer IP 或企业 DNS 名称",
    syslogSourceCidrs: "安全设备来源 CIDR",
    syslogSourceCidrsPlaceholder: "每行一个，或以逗号分隔",
    syslogIngestIdentity: "Collector 接入身份",
    syslogIngestIdentitySecret: "Kubernetes Secret 托管",
    saveSyslogDeployment: "保存部署配置",
    exportSyslogDeployment: "下载部署参数",
    syslogDeploymentSyncRequired: "待部署同步",
    syslogDeploymentAddressPending: "待填写对外地址",
    syslogDeploymentSaved: "Syslog 部署配置已保存，等待 k3s 同步。",
    syslogDeploymentLoadFailed: "加载 Syslog 部署配置失败：{message}",
    syslogSourceCidrsRequired: "请至少填写一个安全设备来源 CIDR。",
    syslogDeploymentTarget: "设备发送目标",
    syslogOpsTitle: "安全系统侧配置",
    syslogOpsText: "目的地址填写服务区暴露的 syslog collector IP，端口和协议使用对应产品配置。",
    syslogMappingTitle: "字段处理策略",
    syslogMappingText: "collector 优先解析 syslog message 中的 JSON；未匹配 profile 时按 SIEM 标准告警兜底。",
    syslogDeployTitle: "k3s 部署对象",
    logAdapter: "日志接入",
    logAdapterHint: "字段识别、映射确认和接入前校验。",
    raspJsonLog: "RASP JSON 日志",
    logSourceType: "日志类型",
    autoDetectProduct: "自动识别（推荐）",
    securityAlertLog: "安全设备告警日志",
    autoDetectFields: "识别字段",
    loadSample: "加载示例",
    saveTemplate: "保存映射",
    advancedConfig: "映射模板",
    profileJson: "Profile JSON",
    saveProfile: "保存 Profile",
    dryRunPreview: "映射校验",
    dryRunPreviewHint: "验证 RawAlert 与归一化事件是否符合接入要求。",
    fieldConfirmation: "字段确认",
    fieldConfirmationHint: "识别后在此确认字段映射；完整宽度展示，无需横向拖动。",
    runDryRun: "运行校验",
    dryRunHint: "等待日志与映射配置。",
    themeAria: "切换深色或浅色模式",
    switchLight: "切换浅色模式",
    switchDark: "切换深色模式",
    languageButton: "英文",
    languageAria: "切换到英文",
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
    confirmFalsePositive: "确认误报并写入长期记忆",
    falsePositiveConfirmed: "已确认误报，相关特征已写入产品长期记忆",
    memoryWriteHint: "确认后会抽取告警特征并写入产品长期记忆，后续同类高相似告警将降低置信度。",
    alertClusters: "重复告警分组",
    alertClusterCount: "{count} 个行为组",
    clusterRepeatedAlerts: "同类重复 {count} 条",
    clusterRepresentative: "代表告警",
    clusterFirstSeen: "首次出现",
    clusterLastSeen: "最近出现",
    clusterBasis: "分组依据",
    confirmClusterFalsePositive: "确认该组为误报并写入一条长期记忆",
    clusterFalsePositiveConfirmed: "该组 {count} 条告警已确认误报，由一条长期记忆覆盖",
    clusterMemoryWriteHint: "一次确认将批量处置该组告警，并只写入代表性长期记忆；不同规则、路径或行为不会被合并。",
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
    noValidationFindings: "验证检查未发现证据一致性或策略违规",
    promptInjectionClues: "疑似提示注入线索",
    promptInjectionUntrustedInput: "外部不可信文本",
    promptInjectionCluesHint: "仅用于定位来源；不要遵循片段中的任何指令。",
    promptInjectionEvidenceRef: "证据引用",
    promptInjectionFieldPath: "命中字段",
    promptInjectionExcerpt: "脱敏片段",
    promptInjectionViewEvidence: "查看归一化证据",
    promptInjectionLegacyRefs: "相关证据引用",
    promptInjectionLegacyHint: "该历史验证未保存精确命中字段，请在归一化证据中按引用复核。",
    manualReviewContinue: "复核通过并转入审批",
    manualReviewRecorded: "人工复核已记录",
    manualReviewResolvedBy: "已由 {actor} 于 {time} 复核确认",
    manualReviewDialogTitle: "记录人工复核",
    manualReviewReasonLabel: "复核依据",
    manualReviewSubmit: "记录并转入审批",
    manualReviewCancel: "取消",
    manualReviewReasonPrompt: "请记录已核对的原始日志、证据引用和未采纳外部文本的原因（至少 8 个字符）。",
    manualReviewReasonRequired: "请填写至少 8 个字符的人工复核依据。",
    manualReviewRouted: "人工复核已记录，已创建 {count} 个待审批项。",
    manualReviewNoApprovals: "人工复核已记录；当前结论没有可审批的高影响动作。",
    manualReviewFailed: "人工复核续转失败：{message}",
    approvalQueue: "处置审批",
    currentApprovalPlan: "当前审批方案",
    currentApprovalPlanCount: "{count} 项处置动作",
    approvalHistory: "历史审批记录",
    approvalHistorySummary: "{rounds} 轮 · {count} 项，默认收起以减少干扰",
    approvalHistoryEmpty: "暂无历史审批记录",
    actionStageVerify: "研判确认",
    actionStageCoordinate: "协同响应",
    actionStageContain: "遏制风险",
    actionStageEradicate: "修复加固",
    actionStageRecover: "恢复业务",
    actionStageMonitor: "持续监测",
    approvalPending: "待审批",
    approvalApproved: "已批准",
    approvalRejected: "已拒绝",
    approvalCancelled: "已取消",
    executionNotRun: "未执行生产动作",
    rollbackCondition: "回滚条件",
    approveAction: "批准",
    rejectAction: "拒绝",
    approvalReasonPrompt: "请输入审批理由。自动模式将在最终审批通过后立即调用已配置的处置接口。",
    approvalDecisionDefault: "Dashboard 分析师已复核证据与回滚条件",
    approvalSaved: "审批状态已更新：{status}",
    approvalProgress: "审批进度 {count}/{required}",
    approvalVoteSaved: "审批意见已记录：{count}/{required}，当前状态为 {status}",
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
    extractingClusterMemory: "正在批量处置该组告警并写入一条代表性记忆...",
    falsePositiveReason: "Dashboard 人工确认：该告警符合业务场景下的误报模式",
    clusterFalsePositiveReason: "Dashboard 人工确认：该组同类重复告警符合业务场景下的误报模式",
    memoryWritten: "已写入产品长期记忆：{id}，后续同类高相似告警会降低置信。",
    clusterMemoryWritten: "已处置该组 {count} 条告警，并写入一条产品长期记忆：{id}",
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
    resumeDeferredAlerts: "重新推送待分析告警",
    resumingDeferredAlerts: "正在重新推送...",
    deferredAlertsReleased: "已重新调度 {count} 条待远程模型分析的告警。",
    deferredAlertsNeedRemoteModel: "待恢复告警只能由远程模型处理。请先恢复 Gateway 或 Ollama，再重新推送。",
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
    dashboardSecondaryNav: "Alert triage sections",
    dashboardSubPending: "Active queue",
    dashboardSubHistory: "Disposition history",
    navMemory: "Memory Governance",
    navAdapter: "Log Intake",
    navAutomation: "Automated Response",
    navSettings: "Runtime",
    memorySecondaryNav: "Memory governance sections",
    memorySubInventory: "Memory Inventory",
    memorySubAudit: "Governance Audit",
    adapterSecondaryNav: "Log intake sections",
    adapterSubIntake: "Alert Intake",
    adapterSubConfig: "Log Configuration",
    automationSecondaryNav: "Automated response sections",
    automationSubTasks: "Execution Tasks",
    automationSubConnectors: "Connectors",
    automationSubPolicy: "Response Policy",
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
    workspaceTitleHistory: "Disposition History",
    workspaceTitleTriage: "Triage and Disposition",
    workspaceTitleMemory: "Memory Governance",
    workspaceTitleMemoryAssociations: "Associated Alerts",
    workspaceTitleAdapter: "Log Intake",
    workspaceTitleAutomation: "Automated Response",
    workspaceTitleSettings: "Runtime Configuration",
    automationTotal: "Total Tasks",
    automationActive: "In Progress",
    automationVerified: "Active",
    automationFailed: "Failures",
    automationTasks: "Execution Tasks",
    automationTasksHint: "Track approved dispatches, device verification, expiry and rollback.",
    automationStatus: "Task status",
    automationConnectorConfig: "Connector Configuration",
    automationConnectorHint: "Configure a WAF or edge firewall action API; enter only the credential environment variable name.",
    configuredConnectors: "Configured Connectors",
    configuredConnectorsHint: "A non-mutating health check is required before real execution.",
    connectorName: "Connector name",
    connectorEndpoint: "API endpoint",
    connectorSecretEnv: "Credential environment variable",
    connectorMode: "Execution mode",
    connectorModeShadow: "Shadow",
    connectorModeManual: "Manual dispatch",
    connectorModeAuto: "Run after approval",
    connectorMaxTtl: "Maximum block duration (seconds)",
    connectorTimeout: "Request timeout (seconds)",
    connectorEnabled: "Enable connector",
    connectorHealth: "Health",
    connectorHealthUntested: "Not tested",
    connectorHealthHealthy: "Healthy",
    connectorHealthError: "Connection error",
    connectorCredentialReady: "Credential configured",
    connectorCredentialMissing: "Credential missing",
    connectorTest: "Test connection",
    connectorEdit: "Edit",
    connectorSaved: "Connector saved",
    connectorTested: "Connector check: {status}",
    automationPolicy: "Response Policy",
    automationPolicyHint: "Set the global execution switch, block duration and protected networks.",
    automationEnabled: "Allow response task dispatch",
    automationDefaultTtl: "Default block duration (seconds)",
    automationMaxTtl: "Global maximum duration (seconds)",
    automationProtectedCidrs: "Protected CIDRs",
    automationPolicySaved: "Response policy saved",
    responseWaitingConfiguration: "Needs configuration",
    responseWaitingDispatch: "Awaiting dispatch",
    responsePaused: "Paused",
    responseQueued: "Queued",
    responseRunning: "Running",
    responseRetryWait: "Retry pending",
    responseVerified: "Active",
    responseShadowed: "Shadowed",
    responseFailed: "Failed",
    responseCancelled: "Cancelled",
    responseRollbackQueued: "Rollback queued",
    responseRollbackRunning: "Rolling back",
    responseRollbackRetry: "Rollback retry",
    responseRolledBack: "Rolled back",
    responseRollbackFailed: "Rollback failed",
    responseTaskEmpty: "No automated response tasks.",
    responseConnectorEmpty: "No response connector is configured.",
    responseTaskId: "Task ID",
    responseActionBlockSourceIp: "Temporarily block source IP",
    responseObject: "Response object",
    responseScope: "Scope",
    responseMode: "Execution mode",
    responseRemoteRule: "Remote rule",
    responseExpires: "Expires",
    responseDispatch: "Dispatch now",
    responseRollback: "Rollback",
    responseActionPlan: "Automated action",
    responseNoActionPlan: "This recommendation will not be converted into an automated action.",
    responseTaskCreated: "Response task created: {status}",
    responseActionDone: "Task updated: {status}",
    applyFilter: "Apply filter",
    dashboardEyebrow: "Realtime SOC Overview",
    dashboardTitle: "Realtime Monitoring",
    dashboardSubtitle: "Monitor alert trends, response pressure, intake health, and model runtime status.",
    footer: "© 2026 Defensive AI Gateway · Designed & engineered by TC",
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
    distributionHint: "All cases grouped by security product to spot noisy sources and priority controls.",
    handlingTitle: "Response Verdicts",
    handlingHint: "Verdict mix across all cases, including malicious, review, benign, and insufficient evidence.",
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
    modelCredentialMissing: "Gateway deployment credentials are missing; alerts are retained in the recovery queue.",
    modelDurableRetry: "Model unavailable; alerts await recovery scheduling (about {seconds}s).",
    modelDeferredBacklog: "{count} alert(s) await restored remote-model analysis.",
    syslogActive: "{active}/{total} listeners online",
    syslogInactive: "No listener enabled",
    httpActive: "HTTP intake online",
    noDistribution: "No distribution data",
    refresh: "Refresh",
    alerts: "Total Alerts",
    highCritical: "High and Critical",
    latestCases: "Case Queue",
    latestCasesHint: "Sorted by creation time; disposition changes keep the queue order stable.",
    triageEyebrow: "Alert triage",
    triageTitle: "Focus on alerts that need a decision now",
    triageSubtitle: "Select a case from the active queue to enter triage and disposition.",
    triageOpen: "Open",
    triageReview: "Under review",
    triagePriority: "High / critical",
    triageAll: "All",
    triageConfirmed: "Confirmed attack",
    triageCompleted: "Completed",
    triageFilterToggle: "Filters",
    triageFilterHide: "Hide filters",
    triageQueue: "Active queue",
    triageQueueHint: "Only unfinished cases are shown. Select one to enter triage and disposition.",
    processedQueue: "Disposition history",
    processedQueueHint: "Keep completed cases available for filtered lookup and retrospective review.",
    triageDetail: "Triage and disposition",
    triageDetailHint: "Complete review, disposition, and approval here; open detailed information only when needed.",
    triageBack: "Back to active queue",
    triageBackHistory: "Back to disposition history",
    triageSelectPrompt: "Select a case from the active queue to begin triage and disposition.",
    triageResultCount: "Showing {shown} of {total}",
    paginationRange: "{start}-{end} of {total}",
    paginationPage: "Page {page} of {pages}",
    paginationSize: "Per page",
    paginationPrevious: "Previous page",
    paginationNext: "Next page",
    triageNoResults: "There are no active cases.",
    processedNoResults: "There are no disposition records matching the current filters.",
    viewCase: "Open triage and disposition for case {id}",
    triageAlertVolume: "Linked alerts",
    triageDetails: "Detailed information",
    triageDetailsHint: "Open raw alerts, normalized evidence, and run records on dedicated pages when needed.",
    detailRawAlertsHint: "View the complete raw payload and disposition for each linked alert.",
    detailEvidenceHint: "View structured entities, evidence, and sensitivity tags.",
    detailRunsHint: "View analysis outputs and validation records.",
    responsePackTitle: "AI response workspace",
    responsePackHint: "Generate an evidence-bound summary, timeline, containment plan, playbook, and internal communication draft on demand.",
    responsePackBadge: "On demand",
    detailOpen: "Open details",
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
    memoryAssociationsOpen: "View alerts",
    memoryAssociationsBack: "Back to governance detail",
    memoryAssociationsBreadcrumb: "Memory Governance / Associated Alerts",
    memoryAssociationsPageTitle: "Associated Alert Records",
    memoryAssociationsRecordCount: "associated records",
    memoryAssociationsRecords: "Match records",
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
    syslogDeploymentTitle: "Syslog Intake Deployment",
    syslogDeploymentHint: "Maintain security-device destinations and source ranges in one place.",
    syslogCollectorAddress: "Collector external address",
    syslogCollectorAddressPlaceholder: "LoadBalancer IP or enterprise DNS name",
    syslogSourceCidrs: "Security device source CIDRs",
    syslogSourceCidrsPlaceholder: "One per line or comma-separated",
    syslogIngestIdentity: "Collector ingest identity",
    syslogIngestIdentitySecret: "Managed by Kubernetes Secret",
    saveSyslogDeployment: "Save deployment config",
    exportSyslogDeployment: "Download deployment values",
    syslogDeploymentSyncRequired: "Deployment sync required",
    syslogDeploymentAddressPending: "External address pending",
    syslogDeploymentSaved: "Syslog deployment configuration saved; k3s sync is pending.",
    syslogDeploymentLoadFailed: "Failed to load Syslog deployment configuration: {message}",
    syslogSourceCidrsRequired: "Enter at least one security device source CIDR.",
    syslogDeploymentTarget: "Device destination",
    syslogOpsTitle: "Security System Setup",
    syslogOpsText: "Use the service-zone syslog collector IP as the target, with the configured product port and protocol.",
    syslogMappingTitle: "Field Handling",
    syslogMappingText: "The collector parses JSON in the syslog message first; unmatched sources fall back to SIEM-style standard alerts.",
    syslogDeployTitle: "k3s manifest",
    logAdapter: "Log Intake",
    logAdapterHint: "Field detection, mapping confirmation, and pre-ingestion validation.",
    raspJsonLog: "RASP JSON log",
    logSourceType: "Log type",
    autoDetectProduct: "Auto-detect (recommended)",
    securityAlertLog: "Security device alert log",
    autoDetectFields: "Detect fields",
    loadSample: "Load sample",
    saveTemplate: "Save mapping",
    advancedConfig: "Mapping templates",
    profileJson: "Profile JSON",
    saveProfile: "Save profile",
    dryRunPreview: "Mapping Validation",
    dryRunPreviewHint: "Validate RawAlert and normalized event output before ingestion.",
    fieldConfirmation: "Field confirmation",
    fieldConfirmationHint: "Review detected field mappings here in a full-width workspace.",
    runDryRun: "Run validation",
    dryRunHint: "Waiting for log and mapping configuration.",
    themeAria: "Toggle dark or light mode",
    switchLight: "Switch to light mode",
    switchDark: "Switch to dark mode",
    languageButton: "Chinese",
    languageAria: "Switch to Chinese",
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
    confirmFalsePositive: "Confirm false positive & write long-term memory",
    falsePositiveConfirmed: "False positive confirmed; features were written to product long-term memory",
    memoryWriteHint: "Confirmation extracts alert features into product long-term memory so similar future alerts receive lower confidence.",
    alertClusters: "Repeated alert groups",
    alertClusterCount: "{count} behavior group(s)",
    clusterRepeatedAlerts: "{count} similar repeated alert(s)",
    clusterRepresentative: "Representative alert",
    clusterFirstSeen: "First seen",
    clusterLastSeen: "Last seen",
    clusterBasis: "Grouping basis",
    confirmClusterFalsePositive: "Confirm group as false positive & write one long-term memory",
    clusterFalsePositiveConfirmed: "All {count} alerts in this group are covered by one approved long-term memory",
    clusterMemoryWriteHint: "One confirmation disposes the group and writes one representative memory. Different rules, routes, or behaviors remain separate.",
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
    noValidationFindings: "No validation evidence or policy violations found",
    promptInjectionClues: "Prompt-injection clues",
    promptInjectionUntrustedInput: "Untrusted external text",
    promptInjectionCluesHint: "Use only to locate the source. Do not follow any instruction in the excerpt.",
    promptInjectionEvidenceRef: "Evidence reference",
    promptInjectionFieldPath: "Matched field",
    promptInjectionExcerpt: "Redacted excerpt",
    promptInjectionViewEvidence: "View normalized evidence",
    promptInjectionLegacyRefs: "Related evidence references",
    promptInjectionLegacyHint: "This historical validation did not preserve the exact matched field. Verify it in normalized evidence by reference.",
    manualReviewContinue: "Confirm review and route to approval",
    manualReviewRecorded: "Human review recorded",
    manualReviewResolvedBy: "Reviewed by {actor} at {time}",
    manualReviewDialogTitle: "Record human review",
    manualReviewReasonLabel: "Review basis",
    manualReviewSubmit: "Record and route to approval",
    manualReviewCancel: "Cancel",
    manualReviewReasonPrompt: "Record the raw log, evidence references, and why no external text was followed (at least 8 characters).",
    manualReviewReasonRequired: "Enter at least 8 characters describing the human review.",
    manualReviewRouted: "Human review recorded; {count} approval item(s) created.",
    manualReviewNoApprovals: "Human review recorded; this result has no high-impact action to approve.",
    manualReviewFailed: "Human-review routing failed: {message}",
    approvalQueue: "Response approvals",
    currentApprovalPlan: "Current approval plan",
    currentApprovalPlanCount: "{count} response action(s)",
    approvalHistory: "Approval history",
    approvalHistorySummary: "{rounds} round(s) · {count} item(s), collapsed by default",
    approvalHistoryEmpty: "No previous approval records",
    actionStageVerify: "Verify",
    actionStageCoordinate: "Coordinate",
    actionStageContain: "Contain",
    actionStageEradicate: "Eradicate",
    actionStageRecover: "Recover",
    actionStageMonitor: "Monitor",
    approvalPending: "Pending",
    approvalApproved: "Approved",
    approvalRejected: "Rejected",
    approvalCancelled: "Cancelled",
    executionNotRun: "No production action executed",
    rollbackCondition: "Rollback condition",
    approveAction: "Approve",
    rejectAction: "Reject",
    approvalReasonPrompt: "Enter a decision reason. Auto mode calls the configured response API immediately after final approval.",
    approvalDecisionDefault: "Dashboard analyst reviewed the evidence and rollback condition",
    approvalSaved: "Approval updated: {status}",
    approvalProgress: "Approval progress {count}/{required}",
    approvalVoteSaved: "Approval vote recorded: {count}/{required}; current status is {status}",
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
    extractingClusterMemory: "Disposing this alert group and writing one representative memory...",
    falsePositiveReason: "Dashboard analyst confirmation: this alert matches a business false-positive pattern",
    clusterFalsePositiveReason: "Dashboard analyst confirmed this repeated alert group matches a business false-positive pattern",
    memoryWritten: "Written to product long-term memory: {id}. Similar future alerts will reduce confidence.",
    clusterMemoryWritten: "Disposed {count} alert(s) and wrote one product long-term memory: {id}",
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
    resumeDeferredAlerts: "Resume deferred alerts",
    resumingDeferredAlerts: "Resuming...",
    deferredAlertsReleased: "Rescheduled {count} alert(s) for remote-model analysis.",
    deferredAlertsNeedRemoteModel: "Deferred alerts require a remote model. Restore Gateway or Ollama before resuming them.",
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
let mappingNeedsValidation = true;
let currentLanguage = "zh";
let lastFieldMappingResult = null;
const sampleLogCache = new Map();
let syslogConfigs = loadSyslogConfigs();
let syslogRuntime = { mode: "embedded", editable: true, unavailable: false };
let syslogDeployment = { collector_address: "", source_cidrs: [], targets: [] };
let dashboardLlmConfig = { provider: "unavailable", model: "-", endpoint: "", unavailable: true };
let dashboardSyslogPayload = { configs: syslogConfigs, listeners: [], unavailable: true };
let refreshPaused = false;
let dashboardRefreshTimer = null;
let dashboardRefreshPromise = null;
let memoryItems = [];
let memoryAuditEvents = [];
let memoryPagination = { page: 1, size: 20, total: 0, totalPages: 1 };
let memoryAuditPagination = { page: 1, size: 20, total: 0, totalPages: 1 };
let memoryAssociationPagination = { page: 1, size: 20, total: 0, totalPages: 1 };
let memoryAssociationItems = [];
let memoryAssociationMemoryId = "";
let responseTasks = [];
let responseConnectors = [];
let responsePolicy = {};
let responseTaskStats = {};
let responseTaskPagination = { page: 1, size: 20, total: 0, totalPages: 1 };
let selectedMemoryId = "";
let selectedMemoryDetail = null;
let memorySelectionRequestId = 0;
let memoryAssociationRequestId = 0;
let queueCases = [];
const caseListRenderKeys = { pending: "", history: "" };
const casePagination = {
  pending: { page: 1, size: 20, total: 0, totalPages: 1 },
  history: { page: 1, size: 20, total: 0, totalPages: 1 },
};
let activeDashboardSection = "pending";
let selectedCaseId = "";
let caseSelectionRequestId = 0;
let currentSession = null;
let ollamaModelLoadRequestId = 0;
let ollamaModelRefreshTimer = 0;
let ollamaModelFocusRefreshTimer = 0;
let apiToken = "";
let pendingManualReview = null;
try {
  apiToken = sessionStorage.getItem(API_TOKEN_KEY) || "";
} catch (err) {
  apiToken = "";
}
async function loadSampleLog(product = selectedLogProduct()) {
  product = product || "waf";
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
  return hasAnyRole("config");
}

function canReadAutomation() {
  return hasAnyRole("read", "config", "responder");
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
  applyPermission("#llm-form input, #llm-form select, #llm-form button", ["config"]);
  applyPermission("#resume-llm-deferred", ["analyst"]);
  applyPermission('#profile-form button[type="submit"]', ["config"]);
  applyPermission("#save-inferred-profile", ["config"]);
  applyPermission('#infer-form button[type="submit"]', ["analyst", "config"]);
  applyPermission('#dry-run-form button[type="submit"]', ["analyst", "config"]);
  applyPermission("#memory-sweep", ["memory"]);
  applyPermission(".case-disposition-button", ["analyst"]);
  applyPermission(".review-button", ["analyst", "memory"]);
  applyPermission(".approval-decision", ["approver"]);
  applyPermission("#automation-connector-form input, #automation-connector-form select, #automation-connector-form button", ["config"]);
  applyPermission("#automation-policy-form input, #automation-policy-form textarea, #automation-policy-form button", ["config"]);
  applyPermission("[data-response-action]", ["responder"]);
  applyPermission("[data-connector-action]", ["config"]);
  applyPermission("[data-memory-action]", ["memory"]);
  const authButton = document.querySelector("#auth-session");
  if (authButton) {
    if (currentSession?.actor) authButton.title = sessionIdentityText();
    else authButton.removeAttribute("title");
  }
  updateSyslogModeUi();
  renderSyslogDeployment();
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

function setPendingCaseSearchCurrentMonth(now = new Date()) {
  const form = document.querySelector('form[data-case-search-section="pending"]');
  if (!form) return;
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1, 0, 0, 0, 0);
  const monthEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 0, 0);
  const fromInput = form.elements.namedItem("from");
  const toInput = form.elements.namedItem("to");
  if (fromInput) fromInput.value = formatDatetimeLocal(monthStart);
  if (toInput) toInput.value = formatDatetimeLocal(monthEnd);
}

function datetimeLocalMs(value) {
  if (!value) return null;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms : null;
}

function applyPaginationPayload(state, payload = {}) {
  state.total = Math.max(0, Number(payload.total || 0));
  state.size = PAGE_SIZE_OPTIONS.includes(Number(payload.limit)) ? Number(payload.limit) : state.size;
  state.page = Math.max(1, Number(payload.page || state.page || 1));
  state.totalPages = Math.max(1, Number(payload.total_pages || 1));
  return state;
}

function paginationState(key) {
  if (key === "cases-pending") return casePagination.pending;
  if (key === "cases-history") return casePagination.history;
  if (key === "memory-inventory") return memoryPagination;
  if (key === "memory-audit") return memoryAuditPagination;
  if (key === "memory-associations") return memoryAssociationPagination;
  if (key === "automation-tasks") return responseTaskPagination;
  return null;
}

function renderPagination(containerSelector, state, key) {
  const container = document.querySelector(containerSelector);
  if (!container) return;
  const start = state.total ? (state.page - 1) * state.size + 1 : 0;
  const end = Math.min(state.total, state.page * state.size);
  container.innerHTML = `
    <nav class="list-pagination" aria-label="${escapeHtml(tr("paginationPage", { page: state.page, pages: state.totalPages }))}">
      <span class="pagination-range">${escapeHtml(tr("paginationRange", { start, end, total: state.total }))}</span>
      <label class="pagination-size">
        <span>${escapeHtml(tr("paginationSize"))}</span>
        <select data-pagination-size="${escapeHtml(key)}">
          ${PAGE_SIZE_OPTIONS.map((size) => `<option value="${size}" ${size === state.size ? "selected" : ""}>${size}</option>`).join("")}
        </select>
      </label>
      <span class="pagination-actions">
        <button type="button" data-pagination-action="previous" data-pagination-key="${escapeHtml(key)}" aria-label="${escapeHtml(tr("paginationPrevious"))}" title="${escapeHtml(tr("paginationPrevious"))}" ${state.page <= 1 ? "disabled" : ""}>←</button>
        <strong>${escapeHtml(tr("paginationPage", { page: state.page, pages: state.totalPages }))}</strong>
        <button type="button" data-pagination-action="next" data-pagination-key="${escapeHtml(key)}" aria-label="${escapeHtml(tr("paginationNext"))}" title="${escapeHtml(tr("paginationNext"))}" ${state.page >= state.totalPages ? "disabled" : ""}>→</button>
      </span>
    </nav>
  `;
}

function reloadPagination(key) {
  if (key === "cases-pending") return loadCases({ quiet: true, section: "pending" });
  if (key === "cases-history") return loadCases({ quiet: true, section: "history" });
  if (key === "memory-inventory") return loadMemoryInventory({ quiet: true });
  if (key === "memory-audit") return loadMemoryAudit({ quiet: true });
  if (key === "memory-associations") return loadMemoryAssociations({ quiet: true });
  if (key === "automation-tasks") return loadResponseTasks({ quiet: true });
  return Promise.resolve();
}

function caseSearchQuery(section = activeDashboardSection) {
  const form = document.querySelector(`form[data-case-search-section="${section}"]`);
  const pagination = casePagination[section] || casePagination.pending;
  if (!form) return new URLSearchParams({ limit: String(pagination.size), offset: String((pagination.page - 1) * pagination.size) }).toString();

  const params = new URLSearchParams({
    limit: String(pagination.size),
    offset: String((pagination.page - 1) * pagination.size),
  });
  // Let the API remove terminal Cases before it applies the limit.  Client-side
  // filtering after a mixed-status query can hide older active Cases entirely.
  if (section === "pending") params.set("active_only", "1");
  else params.set("terminal_only", "1");
  const value = (name) => String(form.elements.namedItem(name)?.value || "").trim();
  const product = value("product");
  const severity = value("severity");
  const status = value("status");
  const createdFrom = datetimeLocalMs(value("from"));
  const createdTo = datetimeLocalMs(value("to"));
  if (product) params.set("product", product);
  if (severity) params.set("severity", severity);
  if (status) params.set("status", status);
  if (createdFrom !== null) params.set("created_from_ms", String(createdFrom));
  // A datetime-local value has minute precision; include the whole end minute.
  if (createdTo !== null) params.set("created_to_ms", String(createdTo + 59_999));
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

function toggleLanguage() {
  saveLanguagePreference(currentLanguage === "en" ? "zh" : "en");
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
    languageButton.setAttribute("aria-label", tr("languageAria"));
  }
  if (lastFieldMappingResult) {
    renderFieldMappingTable(lastFieldMappingResult);
  }
  const active = document.querySelector(".view.active")?.id.replace(/-view$/, "")
    || document.querySelector(".nav-button.active")?.dataset.view
    || "monitor";
  updateWorkspaceTitle(active);
  updateTriageBackLabel();
  renderProfileList();
  renderSyslogConfigTable();
  renderSyslogDeployment();
  renderLogProductOptions();
  renderMemoryList();
  renderMemoryAudit(memoryAuditEvents, "#memory-audit-list");
  if (selectedMemoryDetail) renderMemoryDetail(selectedMemoryDetail);
  if (memoryAssociationMemoryId) renderMemoryAssociationPage();
  updateRefreshModeUi();
  if (queueCases.length || document.querySelector("#cases-list, #processed-cases-list")) {
    renderActiveDashboardList();
    if (selectedCaseId && detailCache.has(selectedCaseId)) {
      renderSelectedCaseDetail(detailCache.get(selectedCaseId), selectedCaseId);
    }
  }
  applySessionPermissions();
}

function renderLogProductOptions() {
  const select = document.querySelector("#log-product-select");
  if (!select) return;
  const current = selectedLogProduct();
  const auto = `<option value="" ${!current ? "selected" : ""}>${escapeHtml(tr("autoDetectProduct"))}</option>`;
  select.innerHTML = auto + LOG_PRODUCT_OPTIONS.map((item) => {
    const label = `${item.label} JSON ${currentLanguage === "en" ? "log" : "日志"}`;
    return `<option value="${escapeHtml(item.product)}" ${item.product === current ? "selected" : ""}>${escapeHtml(label)}</option>`;
  }).join("");
}

function selectedLogProduct() {
  const value = document.querySelector("#log-product-select")?.value || "";
  return LOG_PRODUCT_OPTIONS.some((item) => item.product === value) ? value : "";
}

function selectedLogProductLabel() {
  const product = selectedLogProduct();
  return LOG_PRODUCT_OPTIONS.find((item) => item.product === product)?.label || tr("autoDetectProduct");
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
      protocol: item.product === "rasp" ? "tcp" : (["tcp", "udp"].includes(protocol) ? protocol : item.protocol),
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
      protocol: item.product === "rasp" ? "tcp" : (["tcp", "udp"].includes(protocol) ? protocol : item.protocol),
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
    dashboardSyslogPayload = { configs: syslogConfigs, listeners: [], unavailable: true };
    renderSyslogConfigTable();
    setSyslogConfigStatus(tr("syslogConfigApiUnavailable"));
    return dashboardSyslogPayload;
  }
  setSyslogRuntime(payload);
  mergeSyslogConfigs(payload.configs || []);
  dashboardSyslogPayload = { ...payload, configs: syslogConfigs };
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
  const next = {
    mode,
    editable: mode === "embedded" && payload.editable !== false,
    unavailable: Boolean(payload.unavailable),
  };
  const changed = next.mode !== syslogRuntime.mode
    || next.editable !== syslogRuntime.editable
    || next.unavailable !== syslogRuntime.unavailable;
  syslogRuntime = next;
  if (changed) updateSyslogModeUi();
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
                    ${item.product === "rasp" ? "" : `<option value="udp" ${item.protocol === "udp" ? "selected" : ""}>UDP</option>`}
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
  dashboardSyslogPayload = {
    ...dashboardSyslogPayload,
    ...(result.syslog || {}),
    configs: syslogConfigs,
    unavailable: false,
  };
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
  dashboardSyslogPayload = { ...dashboardSyslogPayload, configs: syslogConfigs };
  persistSyslogConfigs();
  renderSyslogConfigTable();
  setSyslogConfigStatus(tr("syslogDefaultsRestored"));
  showToast(tr("syslogDefaultsRestored"));
}

function setSyslogDeploymentStatus(message, isError = false) {
  const status = document.querySelector("#syslog-deployment-status");
  if (!status) return;
  status.textContent = message;
  status.classList.toggle("error", isError);
}

function renderSyslogDeployment() {
  const collectorInput = document.querySelector("#syslog-collector-address");
  const sourceCidrsInput = document.querySelector("#syslog-source-cidrs");
  const save = document.querySelector("#save-syslog-deployment");
  const exportButton = document.querySelector("#export-syslog-deployment");
  const sync = document.querySelector("#syslog-deployment-sync");
  const identity = document.querySelector("#syslog-ingest-identity");
  const targets = document.querySelector("#syslog-deployment-targets");
  if (!collectorInput || !sourceCidrsInput || !save || !exportButton || !sync || !identity || !targets) return;

  const editable = hasAnyRole("config");
  const collectorAddress = String(syslogDeployment.collector_address || "");
  const sourceCidrs = Array.isArray(syslogDeployment.source_cidrs) ? syslogDeployment.source_cidrs : [];
  collectorInput.value = collectorAddress;
  sourceCidrsInput.value = sourceCidrs.join(", ");
  collectorInput.disabled = !editable;
  sourceCidrsInput.disabled = !editable;
  save.disabled = !editable;
  exportButton.disabled = !editable || !sourceCidrs.length;
  if (!editable) {
    save.title = tr("permissionDenied");
    exportButton.title = tr("permissionDenied");
  } else {
    save.removeAttribute("title");
    exportButton.removeAttribute("title");
  }

  sync.className = `field-status ${sourceCidrs.length ? "needs_review" : "missing"}`;
  sync.textContent = tr("syslogDeploymentSyncRequired");
  identity.textContent = tr("syslogIngestIdentitySecret");

  const destination = collectorAddress || tr("syslogDeploymentAddressPending");
  const configuredTargets = Array.isArray(syslogDeployment.targets) ? syslogDeployment.targets : [];
  targets.innerHTML = configuredTargets
    .map(
      (target) => `
        <div class="syslog-deployment-target">
          <strong>${escapeHtml(target.label || target.product || "-")}</strong>
          <span>${escapeHtml(tr("syslogDeploymentTarget"))}</span>
          <code>${escapeHtml(`${destination}:${target.port}/${String(target.protocol || "tcp").toUpperCase()}`)}</code>
        </div>
      `,
    )
    .join("");
}

async function loadSyslogDeployment() {
  const payload = await json("/api/config/syslog/deployment");
  syslogDeployment = {
    collector_address: String(payload.collector_address || ""),
    source_cidrs: Array.isArray(payload.source_cidrs) ? payload.source_cidrs : [],
    targets: Array.isArray(payload.targets) ? payload.targets : [],
  };
  renderSyslogDeployment();
  return payload;
}

async function saveSyslogDeployment(event) {
  event.preventDefault();
  if (!hasAnyRole("config")) {
    setSyslogDeploymentStatus(tr("permissionDenied"), true);
    return;
  }
  const collectorAddress = document.querySelector("#syslog-collector-address")?.value.trim() || "";
  const sourceCidrs = document.querySelector("#syslog-source-cidrs")?.value || "";
  const result = await json("/api/config/syslog/deployment", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ collector_address: collectorAddress, source_cidrs: sourceCidrs }),
  });
  syslogDeployment = {
    collector_address: String(result.deployment?.collector_address || ""),
    source_cidrs: Array.isArray(result.deployment?.source_cidrs) ? result.deployment.source_cidrs : [],
    targets: Array.isArray(result.deployment?.targets) ? result.deployment.targets : [],
  };
  renderSyslogDeployment();
  setSyslogDeploymentStatus(tr("syslogDeploymentSaved"));
  showToast(tr("syslogDeploymentSaved"));
}

function exportSyslogDeployment() {
  if (!hasAnyRole("config")) {
    setSyslogDeploymentStatus(tr("permissionDenied"), true);
    return;
  }
  const sourceCidrs = Array.isArray(syslogDeployment.source_cidrs) ? syslogDeployment.source_cidrs : [];
  if (!sourceCidrs.length) {
    setSyslogDeploymentStatus(tr("syslogSourceCidrsRequired"), true);
    showToast(tr("syslogSourceCidrsRequired"), "error");
    return;
  }
  const content = [
    "# Defensive AI Gateway Syslog deployment values. No credential is included.",
    `DEFENSIVE_AI_SYSLOG_SOURCE_CIDRS=${sourceCidrs.join(",")}`,
    "",
  ].join("\n");
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "defensive-ai-syslog-console.env";
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function updateWorkspaceTitle(name) {
  const title = document.querySelector("[data-i18n='workspaceTitle']");
  if (!title) return;
  const key = {
    monitor: "workspaceTitleMonitor",
    dashboard: activeDashboardSection === "history" ? "workspaceTitleHistory" : "workspaceTitleDashboard",
    triage: "workspaceTitleTriage",
    memory: "workspaceTitleMemory",
    "memory-associations": "workspaceTitleMemoryAssociations",
    adapter: "workspaceTitleAdapter",
    automation: "workspaceTitleAutomation",
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

const renderedMarkup = new WeakMap();

function setHtmlIfChanged(node, markup) {
  if (!node || renderedMarkup.get(node) === markup) return false;
  renderedMarkup.set(node, markup);
  node.innerHTML = markup;
  return true;
}

function setTextIfChanged(node, value) {
  if (!node) return false;
  const next = String(value);
  if (node.textContent === next) return false;
  node.textContent = next;
  return true;
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
    switchButton.setAttribute("aria-label", tr("themeAria"));
    switchButton.setAttribute("aria-pressed", String(normalized === "dark"));
    switchButton.querySelector('[data-theme-icon="moon"]').hidden = normalized === "dark";
    switchButton.querySelector('[data-theme-icon="sun"]').hidden = normalized !== "dark";
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
  scheduleDashboardRefresh({ immediate: !refreshPaused });
}

function updateRefreshModeUi() {
  const button = document.querySelector("#refresh-mode-toggle");
  if (!button) return;
  button.setAttribute("aria-pressed", String(refreshPaused));
  button.classList.toggle("active", refreshPaused);
  const label = button.querySelector("span") || button;
  label.textContent = tr(refreshPaused ? "autoRefreshPaused" : "autoRefreshOn");
}

function monitorViewIsActive() {
  return document.querySelector("#monitor-view")?.classList.contains("active") === true;
}

function clearDashboardRefreshTimer() {
  if (dashboardRefreshTimer) {
    window.clearTimeout(dashboardRefreshTimer);
    dashboardRefreshTimer = null;
  }
}

function scheduleDashboardRefresh({ immediate = false } = {}) {
  clearDashboardRefreshTimer();
  if (refreshPaused || document.hidden || !monitorViewIsActive()) return;
  dashboardRefreshTimer = window.setTimeout(async () => {
    dashboardRefreshTimer = null;
    if (refreshPaused || document.hidden || !monitorViewIsActive()) return;
    try {
      await loadMonitorDashboard({ refreshConfig: false });
    } catch (err) {
      // Automatic refresh is best effort; manual refresh surfaces errors.
    } finally {
      scheduleDashboardRefresh();
    }
  }, immediate ? 0 : DASHBOARD_REFRESH_MS);
}

function distributionRows(items) {
  return (Array.isArray(items) ? items : [])
    .map((item) => [text(item?.value || "unknown").toLowerCase(), Math.max(0, Number(item?.count) || 0)])
    .filter(([, count]) => count > 0);
}

function renderDistribution(containerId, rows, total, labelForValue = (value) => value) {
  const container = document.querySelector(containerId);
  if (!container) return;
  let markup = "";
  if (!rows.length || !total) {
    markup = `<p class="empty">${escapeHtml(tr("noDistribution"))}</p>`;
  } else {
    markup = rows
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
  setHtmlIfChanged(container, markup);
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
  const llmRuntime = llmConfig?.runtime || {};
  const llmCircuit = llmRuntime?.circuit || {};
  const llmCredentialMissing = llmProvider === "gateway" && !Boolean(llmConfig?.api_key_set);
  const llmConfigured = llmProvider === "local" || (Boolean(llmConfig?.endpoint) && !llmCredentialMissing);
  const llmCircuitOpen = llmCircuit.state === "open";
  const llmRetrySeconds = Math.max(1, Math.ceil(Number(llmCircuit.retry_after_seconds || 0)));
  const llmDeferred = Math.max(0, Number(processing?.llm_deferred?.total || 0));
  const llmStatus = !llmConfigured ? "bad" : (llmCircuitOpen || llmDeferred ? "warn" : "ok");
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
      llmStatus,
      tr("healthModel"),
      llmCredentialMissing
        ? tr("modelCredentialMissing")
        : (llmCircuitOpen
          ? tr("modelDurableRetry", { seconds: llmRetrySeconds })
          : (llmDeferred
            ? tr("modelDeferredBacklog", { count: llmDeferred })
            : (llmProvider === "local"
            ? tr("modelLocal")
            : tr("modelRemote", { provider: llmProvider, model: llmConfig?.model || "-" })))),
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
  setTextIfChanged(scoreNode, tr("healthScore", { score }));
  const scoreClass = `health-score ${runtimeStatus}`;
  if (scoreNode.className !== scoreClass) scoreNode.className = scoreClass;
  setHtmlIfChanged(runtime, `
    <span class="runtime-dot ${runtimeStatus}" aria-hidden="true"></span>
    <span>${escapeHtml(runtimeLabel)}</span>
  `);
  setHtmlIfChanged(container, items
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
    .join(""));
}

function renderIntakeHealth(syslogPayload) {
  const container = document.querySelector("#intake-health");
  if (!container) return;
  const external = syslogPayload?.mode === "external_vector";
  const configs = Array.isArray(syslogPayload?.configs) ? syslogPayload.configs : syslogConfigs;
  setHtmlIfChanged(container, `
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
  `);
}

function renderDashboard(health, caseSummary, llmConfig, syslogPayload) {
  const processing = health?.processing || {};
  if (syslogPayload && !syslogPayload.unavailable) setSyslogRuntime(syslogPayload);
  setTextIfChanged(document.querySelector("#alerts"), health?.stats?.alerts ?? 0);
  setTextIfChanged(document.querySelector("#cases"), health?.stats?.open_cases ?? health?.stats?.cases ?? 0);
  setTextIfChanged(document.querySelector("#high"), health?.stats?.high_or_critical_cases ?? 0);
  setTextIfChanged(document.querySelector("#queue-depth"), unfinishedAlertCount(processing));
  const totalCases = Math.max(0, Number(caseSummary?.total) || 0);
  const productRows = distributionRows(caseSummary?.products)
    .map(([product, count]) => [product.toUpperCase(), count]);
  const classificationRows = distributionRows(caseSummary?.classifications);
  renderDistribution("#product-distribution", productRows, totalCases);
  renderDistribution("#classification-distribution", classificationRows, totalCases, (value) => value.replaceAll("_", " "));
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

function hasMeaningfulWhitelistRecommendation(value) {
  if (typeof value === "string") return value.trim().length > 0;
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return Object.values(value).some((item) => {
    if (item === null || item === undefined) return false;
    if (typeof item === "string") return item.trim().length > 0;
    if (Array.isArray(item)) return item.length > 0;
    if (typeof item === "object") return Object.keys(item).length > 0;
    return Boolean(item);
  });
}

function explanationBlock(explanation) {
  const data = explanation || {};
  const dimensions = Array.isArray(data.dimensions) ? data.dimensions : [];
  const whitelist = data.whitelist_recommendation;
  const whitelistHtml =
    hasMeaningfulWhitelistRecommendation(whitelist)
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
          <div class="action-step-head">
            <strong>${escapeHtml(actionStageLabel(item.stage))}</strong>
            <span>${escapeHtml(item.action)}</span>
          </div>
          <small>${escapeHtml(item.rationale || "")}</small>
        </li>
      `,
    )
    .join("");
}

function actionStageLabel(stage) {
  const key = {
    verify: "actionStageVerify",
    coordinate: "actionStageCoordinate",
    contain: "actionStageContain",
    eradicate: "actionStageEradicate",
    recover: "actionStageRecover",
    monitor: "actionStageMonitor",
  }[stage || "verify"];
  return tr(key || "actionStageVerify");
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

function alertDispositionLabel(disposition) {
  const status = disposition?.status || "open";
  if (status === "false_positive") return tr("caseStatusFalsePositive");
  if (status === "closed") return tr("caseStatusClosed");
  return tr("caseStatusOpen");
}

function reviewTools(raw, disposition = null) {
  const alertId = raw.alert_id || "";
  if (!alertId) return "";
  // An alert disposition alone is not proof that the long-term memory write
  // committed. The API supplies this marker only after finding the matching
  // active, human-confirmed product memory for the same alert and Case.
  const confirmed =
    disposition?.status === "false_positive" &&
    Boolean(disposition?.memory_confirmation?.memory_id);
  const allowed = hasAnyRole("analyst", "memory");
  return `
    <div class="review-tools">
      ${confirmed
        ? `<p class="review-status confirmed" data-alert-status="${escapeHtml(alertId)}">${escapeHtml(tr("falsePositiveConfirmed"))}</p>`
        : `<button class="review-button" type="button" data-alert-id="${escapeHtml(alertId)}" ${allowed ? "" : `disabled title="${escapeHtml(tr("permissionDenied"))}"`}>
            ${escapeHtml(tr("confirmFalsePositive"))}
          </button>
          <p class="review-status" data-alert-status="${escapeHtml(alertId)}">${escapeHtml(tr("memoryWriteHint"))}</p>`}
    </div>
  `;
}

function linkedAlertReviewCard(link, includeReview = true) {
  const raw = link?.raw_alert || {};
  const alertId = raw.alert_id || link?.alert_id || "";
  if (!alertId) return "";
  const adapter = raw.payload?.adapter || {};
  const disposition = link.disposition || null;
  return `
    <article class="linked-alert-item">
      <div class="section-title">
        <div class="linked-alert-heading">
          <strong>${escapeHtml(alertId)}</strong>
          <span>${escapeHtml([raw.product, raw.event_type, raw.severity].filter(Boolean).join(" · "))}</span>
        </div>
        <span class="case-status ${escapeHtml(caseStatusClass(disposition?.status || "open"))}">${escapeHtml(alertDispositionLabel(disposition))}</span>
      </div>
      <dl class="kv">
        <dt>${escapeHtml(tr("source"))}</dt><dd>${escapeHtml(raw.source)}</dd>
        <dt>${escapeHtml(tr("product"))}</dt><dd>${escapeHtml(raw.product).toUpperCase()}</dd>
        <dt>${escapeHtml(tr("event"))}</dt><dd>${escapeHtml(raw.event_type)}</dd>
        <dt>${escapeHtml(tr("severity"))}</dt><dd>${escapeHtml(raw.severity)}</dd>
        <dt>${escapeHtml(tr("time"))}</dt><dd>${escapeHtml(raw.timestamp)}</dd>
        <dt>${escapeHtml(tr("adapterProfile"))}</dt><dd>${escapeHtml(adapter.profile_id ? `${adapter.profile_id} / ${adapter.profile_version}` : "direct")}</dd>
      </dl>
      ${includeReview ? reviewTools(raw, disposition) : ""}
    </article>
  `;
}

function alertClusterBasis(signature = {}) {
  return [
    signature.rule_id || signature.event_type,
    signature.app,
    signature.target,
    [signature.method, signature.uri_template || signature.route_template].filter(Boolean).join(" "),
    signature.process_name,
  ].filter(Boolean).join(" · ") || "-";
}

function alertClusterReviewTools(cluster) {
  const clusterId = cluster?.cluster_id || "";
  const confirmed = Boolean(cluster?.confirmed && cluster?.memory_confirmation?.memory_id);
  const allowed = hasAnyRole("analyst", "memory");
  return `
    <div class="review-tools cluster-review-tools">
      ${confirmed
        ? `<p class="review-status confirmed" data-alert-cluster-status="${escapeHtml(clusterId)}">${escapeHtml(tr("clusterFalsePositiveConfirmed", { count: cluster.count || 0 }))}</p>`
        : `<button class="review-button cluster-review-button" type="button" data-cluster-id="${escapeHtml(clusterId)}" ${allowed ? "" : `disabled title="${escapeHtml(tr("permissionDenied"))}"`}>
            ${escapeHtml(tr("confirmClusterFalsePositive"))}
          </button>
          <p class="review-status" data-alert-cluster-status="${escapeHtml(clusterId)}">${escapeHtml(tr("clusterMemoryWriteHint"))}</p>`}
    </div>
  `;
}

function alertClusterReviewCard(cluster) {
  const representative = cluster?.representative || {};
  const raw = representative.raw_alert || {};
  return `
    <article class="linked-alert-item alert-cluster-item">
      <div class="section-title">
        <div class="linked-alert-heading">
          <strong>${escapeHtml(tr("clusterRepeatedAlerts", { count: cluster.count || 0 }))}</strong>
          <span>${escapeHtml(alertClusterBasis(cluster.signature))}</span>
        </div>
        <span class="case-status ${escapeHtml(caseStatusClass(cluster.confirmed ? "false_positive" : "open"))}">${escapeHtml(alertDispositionLabel({ status: cluster.confirmed ? "false_positive" : "open" }))}</span>
      </div>
      <dl class="kv alert-cluster-summary">
        <dt>${escapeHtml(tr("clusterRepresentative"))}</dt><dd>${escapeHtml(cluster.representative_alert_id || "-")}</dd>
        <dt>${escapeHtml(tr("clusterFirstSeen"))}</dt><dd>${escapeHtml(cluster.first_seen || "-")}</dd>
        <dt>${escapeHtml(tr("clusterLastSeen"))}</dt><dd>${escapeHtml(cluster.last_seen || "-")}</dd>
        <dt>${escapeHtml(tr("clusterBasis"))}</dt><dd>${escapeHtml(alertClusterBasis(cluster.signature))}</dd>
      </dl>
      <details class="cluster-representative-detail">
        <summary>${escapeHtml(tr("clusterRepresentative"))} · ${escapeHtml(raw.alert_id || cluster.representative_alert_id || "-")}</summary>
        ${linkedAlertReviewCard(representative, false)}
      </details>
      ${alertClusterReviewTools(cluster)}
    </article>
  `;
}

function linkedAlertsBlock(linked, clusters = []) {
  const cards = (clusters || []).length
    ? clusters.map(alertClusterReviewCard).filter(Boolean)
    : (linked || []).map(linkedAlertReviewCard).filter(Boolean);
  return `
    <section class="detail-card linked-alerts-card">
      <div class="section-title">
        <h3>${escapeHtml(tr("alertClusters"))}</h3>
        <span>${escapeHtml(tr("alertClusterCount", { count: clusters?.length || cards.length }))} · ${escapeHtml(tr("alertCount", { count: linked?.length || 0 }))}</span>
      </div>
      ${cards.length
        ? `<div class="linked-alert-list">${cards.join("")}</div>`
        : `<p class="empty">${escapeHtml(tr("noEvidence"))}</p>`}
    </section>
  `;
}

function validationStatusLabel(status) {
  return tr({ passed: "validationPassed", review: "validationReview", blocked: "validationBlocked" }[status] || "validationReview");
}

function canContinueValidationReview(validation) {
  const findings = validation?.findings || [];
  const checks = validation?.checks || {};
  return (
    validation?.status === "review" &&
    findings.length > 0 &&
    findings.every((item) => item?.code === "prompt_injection_detected") &&
    checks.prompt_injection === false &&
    Object.entries(checks).every(([key, value]) => key === "prompt_injection" || value === true)
  );
}

function promptInjectionFindings(validation) {
  return (validation?.findings || []).filter((item) => item?.code === "prompt_injection_detected");
}

function promptInjectionCluesBlock(validation, caseId) {
  const findings = promptInjectionFindings(validation);
  if (!findings.length) return "";

  const seenClues = new Set();
  const clues = [];
  for (const finding of findings) {
    for (const item of Array.isArray(finding?.evidence_clues) ? finding.evidence_clues : []) {
      if (!item || typeof item !== "object") continue;
      const evidenceRef = String(item.evidence_ref || "");
      const fieldPath = String(item.field_path || "");
      const excerpt = String(item.excerpt || "");
      const clueKey = `${evidenceRef}\u0000${fieldPath}\u0000${excerpt}`;
      if (seenClues.has(clueKey)) continue;
      seenClues.add(clueKey);
      clues.push({ evidenceRef, fieldPath, excerpt });
    }
  }

  const legacyRefs = clues.length
    ? []
    : [...new Set(findings.flatMap((finding) => Array.isArray(finding?.evidence_refs) ? finding.evidence_refs : []))]
      .map((ref) => String(ref || ""))
      .filter(Boolean);
  const evidenceHref = `case-details.html?case_id=${encodeURIComponent(caseId || "")}&section=normalized-evidence`;
  const clueRows = clues.map((clue) => `
    <div class="prompt-injection-clue" role="listitem">
      <dl>
        <div><dt>${escapeHtml(tr("promptInjectionEvidenceRef"))}</dt><dd><code>${escapeHtml(clue.evidenceRef || "-")}</code></dd></div>
        <div><dt>${escapeHtml(tr("promptInjectionFieldPath"))}</dt><dd><code>${escapeHtml(clue.fieldPath || "-")}</code></dd></div>
        <div><dt>${escapeHtml(tr("promptInjectionExcerpt"))}</dt><dd><code>${escapeHtml(clue.excerpt || "-")}</code></dd></div>
      </dl>
    </div>
  `).join("");
  const legacyBlock = legacyRefs.length ? `
    <div class="prompt-injection-legacy">
      <strong>${escapeHtml(tr("promptInjectionLegacyRefs"))}</strong>
      <span>${escapeHtml(tr("promptInjectionLegacyHint"))}</span>
      <div class="prompt-injection-ref-list">${legacyRefs.map((ref) => `<code>${escapeHtml(ref)}</code>`).join("")}</div>
    </div>
  ` : "";
  return `
    <section class="prompt-injection-clues">
      <div class="prompt-injection-clues-head">
        <div class="prompt-injection-clues-title">
          <strong>${escapeHtml(tr("promptInjectionClues"))}</strong>
          <span class="prompt-injection-untrusted">${escapeHtml(tr("promptInjectionUntrustedInput"))}</span>
        </div>
        ${caseId ? `<a class="prompt-injection-evidence-link" href="${escapeHtml(evidenceHref)}">${escapeHtml(tr("promptInjectionViewEvidence"))}</a>` : ""}
      </div>
      <p>${escapeHtml(tr("promptInjectionCluesHint"))}</p>
      ${clueRows ? `<div class="prompt-injection-clue-list" role="list">${clueRows}</div>` : ""}
      ${legacyBlock}
    </section>
  `;
}

function manualReviewContinuation(validation, caseId) {
  const resolution = validation?.manual_review_resolution;
  if (resolution) {
    return `
      <div class="manual-review-resolution">
        <strong>${escapeHtml(tr("manualReviewRecorded"))}</strong>
        <span>${escapeHtml(tr("manualReviewResolvedBy", { actor: resolution.actor || "-", time: fmtTime(resolution.created_at_ms) }))}</span>
        <p>${escapeHtml(resolution.reason || "-")}</p>
      </div>
    `;
  }
  if (!canContinueValidationReview(validation)) return "";
  const allowed = hasAnyRole("analyst");
  return `
    <div class="manual-review-continuation">
      <button
        class="validation-review-continue"
        type="button"
        data-case-id="${escapeHtml(caseId)}"
        data-validation-id="${escapeHtml(validation.validation_id || "")}"
        ${allowed ? "" : `disabled title="${escapeHtml(tr("permissionDenied"))}"`}
      >${escapeHtml(tr("manualReviewContinue"))}</button>
      <p class="manual-review-status" data-manual-review-status="${escapeHtml(validation.validation_id || "")}"></p>
    </div>
  `;
}

function validationBlock(validation, caseId) {
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
      ${promptInjectionCluesBlock(validation, caseId)}
      ${manualReviewContinuation(validation, caseId)}
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

function approvalDecisionMessage(approval, responseTask = null) {
  if (responseTask) {
    return tr("responseTaskCreated", { status: responseStatusLabel(responseTask.status) });
  }
  const count = Number(approval?.vote_count);
  const required = Number(approval?.required_approvals);
  if (Number.isInteger(count) && count >= 0 && Number.isInteger(required) && required > 0) {
    return tr("approvalVoteSaved", { count, required, status: approvalStatusLabel(approval.status) });
  }
  return tr("approvalSaved", { status: approvalStatusLabel(approval.status) });
}

function approvalAutomationPlan(approval, compact = false) {
  const action = approval.action?.execution_action || {};
  const task = approval.response_task || null;
  if (!action.action_type) return compact ? "" : `<p class="approval-automation-empty">${escapeHtml(tr("responseNoActionPlan"))}</p>`;
  const scope = action.scope || {};
  const scopeText = [scope.product, scope.host, scope.path].filter(Boolean).join(" · ") || "-";
  if (compact) {
    return `<small>${escapeHtml(action.object || "-")} · ${escapeHtml(task ? responseStatusLabel(task.status) : tr("approvalPending"))}</small>`;
  }
  return `
    <div class="approval-automation-plan">
      <div><strong>${escapeHtml(tr("responseActionPlan"))}</strong><span class="field-status ${task && ["failed", "rollback_failed"].includes(task.status) ? "needs_review" : "mapped"}">${escapeHtml(task ? responseStatusLabel(task.status) : tr("approvalPending"))}</span></div>
      <dl class="kv">
        <dt>${escapeHtml(tr("responseObject"))}</dt><dd>${escapeHtml(action.object || "-")}</dd>
        <dt>${escapeHtml(tr("responseScope"))}</dt><dd>${escapeHtml(scopeText)}</dd>
        <dt>TTL</dt><dd>${escapeHtml(String(action.duration_seconds || "-"))}s</dd>
      </dl>
      ${task?.last_error ? `<p class="automation-task-error">${escapeHtml(task.last_error)}</p>` : ""}
    </div>
  `;
}

function approvalBlock(approvals, caseId, latestEventId = "") {
  const records = approvals || [];
  const currentEventId = latestEventId || records[0]?.event_id || "";
  const current = currentEventId ? records.filter((item) => item.event_id === currentEventId) : [];
  const history = currentEventId ? records.filter((item) => item.event_id !== currentEventId) : [];
  const historyRounds = new Set(history.map((item) => item.event_id).filter(Boolean)).size;
  const approvalItem = (item, compact = false) => `
    <article class="approval-item ${compact ? "compact" : ""} ${escapeHtml(item.status)}">
      <div class="case-disposition-head">
        <strong>${escapeHtml(approvalStatusLabel(item.status))}</strong>
        <span>${escapeHtml(item.response_task ? responseStatusLabel(item.response_task.status) : item.action?.stage ? actionStageLabel(item.action.stage) : tr("executionNotRun"))}</span>
      </div>
      <p>${escapeHtml(item.action?.action || "")}</p>
      ${compact ? "" : `<small>${escapeHtml(item.action?.rationale || "")}</small>`}
      ${approvalAutomationPlan(item, compact)}
      ${!compact && approvalProgressText(item) ? `<small class="approval-progress">${escapeHtml(approvalProgressText(item))}</small>` : ""}
      ${compact ? `<small>${escapeHtml(fmtTime(item.created_at_ms))} · ${escapeHtml(tr("executionNotRun"))}</small>` : `<dl class="kv"><dt>${escapeHtml(tr("rollbackCondition"))}</dt><dd>${escapeHtml(item.action?.rollback || "-")}</dd></dl>`}
      ${!compact && item.status === "pending" ? `
        <div class="approval-actions">
          <button type="button" class="approval-decision" data-case-id="${escapeHtml(caseId)}" data-approval-id="${escapeHtml(item.approval_id)}" data-decision="approved" ${hasAnyRole("approver") ? "" : `disabled title="${escapeHtml(tr("permissionDenied"))}"`}>${escapeHtml(tr("approveAction"))}</button>
          <button type="button" class="approval-decision" data-case-id="${escapeHtml(caseId)}" data-approval-id="${escapeHtml(item.approval_id)}" data-decision="rejected" ${hasAnyRole("approver") ? "" : `disabled title="${escapeHtml(tr("permissionDenied"))}"`}>${escapeHtml(tr("rejectAction"))}</button>
        </div>
      ` : ""}
    </article>
  `;
  return `
    <div class="approval-queue">
      <h4>${escapeHtml(tr("approvalQueue"))}</h4>
      ${current.length
        ? `<div class="approval-current-head"><strong>${escapeHtml(tr("currentApprovalPlan"))}</strong><span>${escapeHtml(tr("currentApprovalPlanCount", { count: current.length }))}</span></div>${current.map((item) => approvalItem(item)).join("")}`
        : `<p class="empty">${escapeHtml(tr("noApprovals"))}</p>`}
      ${history.length ? `
        <details class="approval-history">
          <summary><strong>${escapeHtml(tr("approvalHistory"))}</strong><span>${escapeHtml(tr("approvalHistorySummary", { rounds: historyRounds, count: history.length }))}</span></summary>
          <div class="approval-history-list">${history.map((item) => approvalItem(item, true)).join("")}</div>
        </details>
      ` : ""}
      <p class="approval-status" data-approval-status="${escapeHtml(caseId)}"></p>
    </div>
  `;
}

function renderDetail(detail) {
  const latestRunRecord = detail.agent_runs?.[0] || {};
  const latestRun = latestRunRecord.result || {};
  const linked = detail.linked_alerts || [];
  const detailCounts = detail.detail_counts || {};
  const missing = latestRun.missing_evidence || [];
  const validation = detail.validation_runs?.[0] || latestRun.explanation?.validation;
  const confidence = Math.round((detail.confidence || 0) * 100);
  const headline = caseFocusSummary(detail);

  return `
    <div class="detail-stack">
      <section class="case-detail-overview">
        <div class="case-detail-heading">
          <div>
            <div class="case-detail-kicker">
              <strong class="case-product">${escapeHtml(detail.product).toUpperCase()}</strong>
              <span class="badge ${escapeHtml(detail.severity)}">${escapeHtml(detail.severity)}</span>
              <span class="case-status ${escapeHtml(caseStatusClass(detail.status))}">${escapeHtml(caseStatusLabel(detail.status))}</span>
            </div>
            <h3>${escapeHtml(headline)}</h3>
            <p class="case-detail-id">Case ID · ${escapeHtml(detail.case_id)}</p>
          </div>
          <div class="case-detail-confidence">
            <span>${escapeHtml(tr("confidence"))}</span>
            <strong>${confidence}%</strong>
          </div>
        </div>
        <div class="case-context-grid">
          <div>
            <span>${escapeHtml(tr("classification"))}</span>
            <strong>${escapeHtml(detail.classification)}</strong>
          </div>
          <div>
            <span>${escapeHtml(tr("triageAlertVolume"))}</span>
            <strong>${escapeHtml(tr("alertCount", { count: linked.length }))}</strong>
          </div>
          <div>
            <span>${escapeHtml(tr("updatedAt"))}</span>
            <strong>${escapeHtml(fmtTime(detail.updated_at_ms))}</strong>
          </div>
        </div>
        ${caseDispositionControls(detail)}
        ${validationBlock(validation, detail.case_id)}
        ${approvalBlock(detail.approvals || [], detail.case_id, latestRunRecord.event_id || "")}
      </section>

      <section class="detail-card">
        <div class="section-title">
          <h3>${escapeHtml(tr("aiAnalysis"))}</h3>
          <span>${escapeHtml(tr("recommendedActions"))}</span>
        </div>
        ${explanationBlock(latestRun.explanation)}
        <h4>${escapeHtml(tr("recommendedActions"))}</h4>
        <ol class="action-list">${actionRows(latestRun.recommended_actions)}</ol>
        <h4>${escapeHtml(tr("missingEvidence"))}</h4>
        <ul class="plain-list">
          ${
            missing.length
              ? missing.map((item) => `<li>${escapeHtml(item)}</li>`).join("")
              : `<li class="empty">${escapeHtml(tr("none"))}</li>`
          }
        </ul>
      </section>

      ${linkedAlertsBlock(linked, detail.alert_clusters || [])}

      <section class="detail-card detailed-information">
        <div class="section-title">
          <div>
            <h3>${escapeHtml(tr("triageDetails"))}</h3>
            <p>${escapeHtml(tr("triageDetailsHint"))}</p>
          </div>
        </div>
        <div class="detail-link-list">
          ${responsePackLink(detail.case_id)}
          ${detailLink(detail.case_id, "raw-alerts", tr("linkedRawAlerts"), tr("detailRawAlertsHint"), tr("alertCount", { count: detailCounts.raw_alerts ?? linked.length }))}
          ${detailLink(detail.case_id, "normalized-evidence", tr("normalizedEvidence"), tr("detailEvidenceHint"), tr("alertCount", { count: detailCounts.normalized_evidence ?? linked.length }))}
          ${detailLink(detail.case_id, "analysis-runs", tr("agentRuns"), tr("detailRunsHint"), tr("runCount", { count: detailCounts.analysis_runs ?? detail.agent_runs?.length ?? 0 }))}
        </div>
      </section>
    </div>
  `;
}

function responsePackLink(caseId) {
  const href = `/case-response.html?${new URLSearchParams({ case_id: caseId }).toString()}`;
  return `
    <a class="detail-link-card response-pack-link" href="${escapeHtml(href)}">
      <span class="detail-link-copy">
        <strong>${escapeHtml(tr("responsePackTitle"))}</strong>
        <span>${escapeHtml(tr("responsePackHint"))}</span>
      </span>
      <span class="detail-link-meta">
        <small>${escapeHtml(tr("responsePackBadge"))}</small>
        <b>${escapeHtml(tr("detailOpen"))} →</b>
      </span>
    </a>
  `;
}

function detailLink(caseId, section, title, description, count) {
  const href = `/case-details.html?${new URLSearchParams({ case_id: caseId, section }).toString()}`;
  return `
    <a class="detail-link-card" data-detail-section="${escapeHtml(section)}" href="${escapeHtml(href)}">
      <span class="detail-link-copy">
        <strong>${escapeHtml(title)}</strong>
        <span>${escapeHtml(description)}</span>
      </span>
      <span class="detail-link-meta">
        <small>${escapeHtml(count)}</small>
        <b>${escapeHtml(tr("detailOpen"))} →</b>
      </span>
    </a>
  `;
}

function pendingQueueCases(cases = queueCases) {
  return (cases || []).filter((item) => !["false_positive", "closed"].includes(text(item?.status).toLowerCase()));
}

function processedQueueCases(cases = queueCases) {
  return (cases || []).filter((item) => ["false_positive", "closed"].includes(text(item?.status).toLowerCase()));
}

function dashboardCaseListId(section = activeDashboardSection) {
  return section === "history" ? "#processed-cases-list" : "#cases-list";
}

function renderCaseList(cases, section, emptyKey) {
  const list = document.querySelector(dashboardCaseListId(section));
  if (!list) return;
  const visible = cases || [];
  const renderKey = JSON.stringify({
    language: currentLanguage,
    cases: visible,
    pagination: casePagination[section],
  });
  if (caseListRenderKeys[section] === renderKey) return;
  caseListRenderKeys[section] = renderKey;
  list.innerHTML = "";
  if (!visible.length) {
    list.innerHTML = `<div class="empty-state">${escapeHtml(tr(emptyKey))}</div>`;
  } else {
    for (const item of visible) {
      list.appendChild(renderCase(item));
    }
  }
  const paginationSelector = section === "history" ? "#processed-cases-pagination" : "#cases-pagination";
  renderPagination(paginationSelector, casePagination[section], `cases-${section}`);
}

function renderQueueList(cases = pendingQueueCases()) {
  renderCaseList(cases, "pending", "triageNoResults");
}

function renderProcessedList(cases = processedQueueCases()) {
  renderCaseList(cases, "history", "processedNoResults");
}

function renderActiveDashboardList() {
  if (activeDashboardSection === "history") renderProcessedList(processedQueueCases());
  else renderQueueList(pendingQueueCases());
}

function renderCase(item) {
  const wrapper = document.createElement("article");
  wrapper.className = "case-item";
  wrapper.dataset.caseId = item.case_id;
  wrapper.innerHTML = `
    <button class="case-card" type="button" aria-label="${escapeHtml(tr("viewCase", { id: item.case_id }))}">
      <span class="case-card-top">
        <span class="case-card-identity">
          <strong class="case-product">${escapeHtml(item.product).toUpperCase()}</strong>
          <span class="badge ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span>
        </span>
        <span class="case-status ${escapeHtml(caseStatusClass(item.status))}">${escapeHtml(caseStatusLabel(item.status))}</span>
      </span>
      <span class="case-summary">${escapeHtml(caseFocusSummary(item))}</span>
      <span class="case-card-meta">
        <span class="linked-count">${escapeHtml(tr("alertCountLong", { count: item.alert_count || 0 }))}</span>
        <small class="case-time">${escapeHtml(fmtTime(item.created_at_ms))}</small>
      </span>
    </button>
  `;
  wrapper.querySelector(".case-card").addEventListener("click", () => {
    openCaseTriage(item.case_id).catch((err) => showToast(tr("detailLoadFailed", { message: err.message || String(err) }), "error"));
  });
  return wrapper;
}

const RASP_RISK_LABELS = [
  [["ognl"], "OGNL 表达式注入"],
  [["spel"], "SpEL 表达式注入"],
  [["jexl"], "JEXL 表达式注入"],
  [["mvel"], "MVEL 表达式注入"],
  [["aviator"], "Aviator 表达式注入"],
  [["jdbc", "sql_connection"], "JDBC 连接"],
  [["jndi"], "JNDI 注入"],
  [["deserial", "fastjson"], "反序列化攻击"],
  [["process_builder", "processbuilder", "cloudrasp_cmd", "command_execution"], "命令执行"],
  [["classloader", "class_loader"], "恶意类加载"],
  [["file_input_stream", "file_read"], "任意文件读取"],
  [["file_write", "file_output_stream"], "任意文件写入"],
  [["ssrf"], "服务端请求伪造"],
  [["xxe"], "XML 实体注入"],
  [["sql_injection"], "SQL 注入"],
];

function caseFocusSummary(item = {}) {
  const summary = text(item.summary).trim();
  if (!summary) return text(item.case_id);
  if (text(item.product).toLowerCase() === "rasp" && /关键实体：|核心依据：|业务影响：/.test(summary)) {
    const normalized = summary.toLowerCase();
    const risk = RASP_RISK_LABELS.find(([needles]) => needles.some((needle) => normalized.includes(needle)))?.[1]
      || "敏感方法调用";
    const classification = text(item.classification).toLowerCase();
    const finding = classification === "malicious"
      ? `确认${risk}`
      : classification === "benign"
        ? `${risk}误报`
        : classification === "suspicious"
          ? `${/^[A-Za-z]/.test(risk) ? "疑似 " : "疑似"}${risk}`
          : `${risk}证据不足`;
    const entityBlock = summary.match(/关键实体：([\s\S]*?)(?:。核心依据：|。业务影响：|$)/)?.[1] || "";
    const entity = (name) => entityBlock.match(new RegExp(`(?:^|,\\s*)${name}=([^,。]+)`))?.[1]?.trim() || "";
    const rawUrl = entity("url");
    let target = entity("host");
    let route = "";
    if (rawUrl) {
      try {
        const parsed = new URL(rawUrl);
        target = parsed.host || target;
        const segments = parsed.pathname.split("/").filter(Boolean).slice(-3);
        route = segments.length ? `/${segments.join("/")}` : "";
      } catch (_error) {
        route = rawUrl.startsWith("/") ? rawUrl : "";
      }
    }
    const request = [entity("method").toUpperCase(), route].filter(Boolean).join(" ");
    const flow = [entity("src_ip"), target].filter(Boolean).join(" → ");
    return [finding, request, flow].filter(Boolean).join("｜");
  }
  const firstLine = summary.replace(/^研判结论[：:]\s*/, "").split(/[。\n]/, 1)[0].trim();
  return firstLine.length > 120 ? `${firstLine.slice(0, 119).replace(/[，,；;：:、｜\s]+$/u, "")}…` : firstLine;
}

function renderSelectedCaseDetail(detail, caseId) {
  const panel = document.querySelector("#case-detail");
  if (!panel || selectedCaseId !== caseId) return;
  panel.innerHTML = renderDetail(detail);
  bindDetailActions(panel, caseId);
}

async function loadTriageCase(caseId) {
  selectedCaseId = caseId;
  const panel = document.querySelector("#case-detail");
  const requestId = ++caseSelectionRequestId;
  if (!panel) return;
  if (detailCache.has(caseId)) {
    renderSelectedCaseDetail(detailCache.get(caseId), caseId);
    return;
  }
  panel.innerHTML = `<div class="loading">${escapeHtml(tr("loadingDetail"))}</div>`;
  try {
    const detail = await json(`/api/cases/${encodeURIComponent(caseId)}`);
    if (requestId !== caseSelectionRequestId || selectedCaseId !== caseId) return;
    detailCache.set(caseId, detail);
    renderSelectedCaseDetail(detail, caseId);
  } catch (err) {
    if (requestId !== caseSelectionRequestId || selectedCaseId !== caseId) return;
    const message = err.message || String(err);
    detailCache.delete(caseId);
    panel.innerHTML = `<div class="empty-state">${escapeHtml(tr("detailLoadFailed", { message }))}</div>`;
    throw err;
  }
}

async function openCaseTriage(caseId) {
  if (!caseId) return;
  setView("triage");
  await loadTriageCase(caseId);
}

function bindDetailActions(panel, caseId) {
  panel.querySelectorAll(".case-disposition-button").forEach((button) => {
    button.addEventListener("click", () => updateCaseDisposition(button, caseId));
  });
  panel.querySelectorAll(".review-button:not(.cluster-review-button)").forEach((button) => {
    button.addEventListener("click", () => confirmBusinessFalsePositive(button, caseId));
  });
  panel.querySelectorAll(".cluster-review-button").forEach((button) => {
    button.addEventListener("click", () => confirmAlertClusterFalsePositive(button, caseId));
  });
  panel.querySelectorAll(".validation-review-continue").forEach((button) => {
    button.addEventListener("click", () => continueValidationReview(button, panel, caseId));
  });
  panel.querySelectorAll(".approval-decision").forEach((button) => {
    button.addEventListener("click", () => decideApproval(button, panel, caseId));
  });
}

function continueValidationReview(button, panel, caseId) {
  const validationId = button.dataset.validationId;
  const dialog = document.querySelector("#manual-review-dialog");
  const reasonInput = document.querySelector("#manual-review-reason");
  const status = document.querySelector("#manual-review-form-status");
  const submitButton = document.querySelector("#manual-review-submit");
  if (!validationId || !dialog || !reasonInput || !status) return;
  pendingManualReview = { button, panel, caseId, validationId };
  reasonInput.value = "";
  status.textContent = "";
  if (submitButton) submitButton.disabled = false;
  if (!dialog.open) dialog.showModal();
  window.setTimeout(() => reasonInput.focus(), 0);
}

function closeManualReviewDialog() {
  const dialog = document.querySelector("#manual-review-dialog");
  if (dialog?.open) dialog.close();
}

async function submitManualReviewContinuation() {
  const pending = pendingManualReview;
  const reasonInput = document.querySelector("#manual-review-reason");
  const formStatus = document.querySelector("#manual-review-form-status");
  const submitButton = document.querySelector("#manual-review-submit");
  if (!pending || !reasonInput) return;
  const reason = reasonInput.value.trim();
  if (reason.length < 8) {
    const message = tr("manualReviewReasonRequired");
    if (formStatus) formStatus.textContent = message;
    showToast(message, "error");
    return;
  }
  const { button, panel, caseId, validationId } = pending;
  const status = panel.querySelector(`[data-manual-review-status="${CSS.escape(validationId)}"]`);
  button.disabled = true;
  if (submitButton) submitButton.disabled = true;
  if (status) status.textContent = tr("manualReviewRecorded");
  if (formStatus) formStatus.textContent = tr("manualReviewRecorded");
  try {
    const result = await json(
      `/api/cases/${encodeURIComponent(caseId)}/validation-reviews/${encodeURIComponent(validationId)}/continue`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: reason.trim() }),
      },
    );
    await loadCases();
    await loadTriageCase(caseId);
    const count = result.approvals?.length || 0;
    pendingManualReview = null;
    closeManualReviewDialog();
    showToast(count ? tr("manualReviewRouted", { count }) : tr("manualReviewNoApprovals"));
  } catch (err) {
    button.disabled = false;
    if (submitButton) submitButton.disabled = false;
    const message = tr("manualReviewFailed", { message: err.message || String(err) });
    if (status) status.textContent = message;
    if (formStatus) formStatus.textContent = message;
    showToast(message, "error");
  }
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
    const updatedApproval = {
      ...result.approval,
      response_task: result.response_task || result.approval.response_task || null,
    };
    detail.approvals = (detail.approvals || []).map((item) => item.approval_id === updatedApproval.approval_id ? updatedApproval : item);
    panel.innerHTML = renderDetail(detail);
    bindDetailActions(panel, caseId);
    const message = approvalDecisionMessage(updatedApproval, result.response_task);
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
    await loadTriageCase(caseId);
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
    await loadTriageCase(caseId);
    showToast(tr("falsePositiveDone", { id: result.memory_id }));
  } catch (err) {
    button.disabled = false;
    const message = err.message || String(err);
    if (status) status.textContent = message;
    showToast(tr("confirmFailed", { message }), "error");
  }
}

async function confirmAlertClusterFalsePositive(button, caseId) {
  const clusterId = button.dataset.clusterId;
  const status = document.querySelector(`[data-alert-cluster-status="${CSS.escape(clusterId)}"]`);
  button.disabled = true;
  if (status) status.textContent = tr("extractingClusterMemory");
  try {
    const result = await json(
      `/api/cases/${encodeURIComponent(caseId)}/alert-clusters/${encodeURIComponent(clusterId)}/confirm-false-positive`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: tr("clusterFalsePositiveReason") }),
      },
    );
    detailCache.delete(caseId);
    if (status) {
      status.textContent = tr("clusterMemoryWritten", {
        count: result.updated_count,
        id: result.memory_id,
      });
    }
    await loadCases();
    await loadTriageCase(caseId);
    showToast(tr("clusterMemoryWritten", {
      count: result.updated_count,
      id: result.memory_id,
    }));
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
  const params = new URLSearchParams({
    include_expired: "true",
    limit: String(memoryPagination.size),
    offset: String((memoryPagination.page - 1) * memoryPagination.size),
  });
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
    renderPagination("#memory-pagination", memoryPagination, "memory-inventory");
    return;
  }
  const start = (memoryPagination.page - 1) * memoryPagination.size + 1;
  const end = Math.min(memoryPagination.total, memoryPagination.page * memoryPagination.size);
  list.innerHTML = `
    <div class="memory-list-count">${escapeHtml(tr("paginationRange", { start, end, total: memoryPagination.total }))}</div>
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
  renderPagination("#memory-pagination", memoryPagination, "memory-inventory");
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
  const items = Array.isArray(matches) ? matches : [];
  if (!items.length) {
    return `<p class="empty-state">${escapeHtml(tr("memoryAssociationsEmpty"))}</p>`;
  }
  return `
    <div class="memory-association-list">
      ${items.map((match) => `
        <article class="memory-association-row">
          <div class="memory-association-heading">
            <span>
              <strong>${escapeHtml(match.alert_id)}</strong>
              <code>${escapeHtml(match.case_id)} · ${escapeHtml(match.event_id)}</code>
            </span>
            <span class="memory-match-decision ${escapeHtml(text(match.decision || match.final_effect || "ignored").replaceAll("_", "-"))}">
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

function memoryAssociationContext() {
  const memory = selectedMemoryDetail?.memory_id === memoryAssociationMemoryId
    ? selectedMemoryDetail
    : memoryItems.find((item) => item.memory_id === memoryAssociationMemoryId);
  const summary = memory ? memoryContentSummary(memory) : "";
  return [summary, memoryAssociationMemoryId].filter(Boolean).join(" · ") || "-";
}

function renderMemoryAssociationPage() {
  const container = document.querySelector("#memory-associations-page-list");
  const context = document.querySelector("#memory-associations-page-context");
  const count = document.querySelector("#memory-associations-page-count");
  if (container) container.innerHTML = renderMemoryAssociations(memoryAssociationItems);
  if (context) {
    context.textContent = memoryAssociationContext();
    context.title = memoryAssociationContext();
  }
  if (count) count.textContent = String(memoryAssociationPagination.total);
  renderPagination(
    "#memory-associations-page-pagination",
    memoryAssociationPagination,
    "memory-associations",
  );
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
      <section class="memory-association-entry">
        <div class="memory-association-entry-copy">
          <div class="memory-association-entry-title">
            <h4>${escapeHtml(tr("memoryAssociations"))}</h4>
            <span>${escapeHtml(String(Number(governance.association_count || 0)))}</span>
          </div>
          <p>${escapeHtml(tr("memoryAssociationsHint"))}</p>
        </div>
        <button type="button" data-memory-associations-id="${escapeHtml(memory.memory_id)}">
          ${escapeHtml(tr("memoryAssociationsOpen"))}
        </button>
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
  container.querySelector("[data-memory-associations-id]")?.addEventListener("click", (event) => {
    openMemoryAssociations(event.currentTarget.dataset.memoryAssociationsId).catch((err) =>
      showToast(tr("refreshFailed", { message: err.message || String(err) }), "error"),
    );
  });
  renderMemoryAudit(governance.events || [], "#memory-detail-audit-list", false);
}

function renderMemoryAudit(events, selector, interactive = true) {
  const container = document.querySelector(selector);
  if (!container) return;
  if (!events.length) {
    container.innerHTML = `<p class="empty-state">${escapeHtml(tr("memoryAuditEmpty"))}</p>`;
    if (selector === "#memory-audit-list") {
      renderPagination("#memory-audit-pagination", memoryAuditPagination, "memory-audit");
    }
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
        memoryPagination.page = 1;
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
  if (selector === "#memory-audit-list") {
    renderPagination("#memory-audit-pagination", memoryAuditPagination, "memory-audit");
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

async function loadMemoryAssociations(options = {}) {
  const memoryId = memoryAssociationMemoryId;
  const container = document.querySelector("#memory-associations-page-list");
  const status = document.querySelector("#memory-associations-page-status");
  if (!memoryId) return;
  const requestId = ++memoryAssociationRequestId;
  if (status) {
    status.textContent = "";
    status.classList.remove("error");
  }
  if (container && !options.quiet) {
    container.innerHTML = `<p class="empty-state">${escapeHtml(tr("memoryLoading"))}</p>`;
  }
  const params = new URLSearchParams({
    memory_id: memoryId,
    limit: String(memoryAssociationPagination.size),
    offset: String((memoryAssociationPagination.page - 1) * memoryAssociationPagination.size),
  });
  try {
    const page = await json(`/api/memory/matches?${params}`);
    if (requestId !== memoryAssociationRequestId || memoryId !== memoryAssociationMemoryId) return;
    applyPaginationPayload(memoryAssociationPagination, page.pagination);
    if (memoryAssociationPagination.page > memoryAssociationPagination.totalPages) {
      memoryAssociationPagination.page = memoryAssociationPagination.totalPages;
      return loadMemoryAssociations(options);
    }
    memoryAssociationItems = page.matches || [];
    renderMemoryAssociationPage();
  } catch (err) {
    if (requestId !== memoryAssociationRequestId || memoryId !== memoryAssociationMemoryId) return;
    const message = err.message || String(err);
    if (container) container.innerHTML = `<p class="empty-state">${escapeHtml(message)}</p>`;
    if (status) {
      status.textContent = message;
      status.classList.add("error");
    }
    throw err;
  }
}

async function openMemoryAssociations(memoryId) {
  if (!memoryId) return;
  if (memoryAssociationMemoryId !== memoryId) {
    memoryAssociationPagination.page = 1;
    memoryAssociationPagination.total = Number(
      selectedMemoryDetail?.memory_id === memoryId
        ? selectedMemoryDetail.governance?.association_count || 0
        : 0,
    );
    memoryAssociationPagination.totalPages = Math.max(
      1,
      Math.ceil(memoryAssociationPagination.total / memoryAssociationPagination.size),
    );
    memoryAssociationItems = [];
  }
  memoryAssociationMemoryId = memoryId;
  setView("memory-associations");
  renderMemoryAssociationPage();
  await loadMemoryAssociations();
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
  applyPaginationPayload(memoryPagination, inventoryResult.value.pagination);
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
    const params = new URLSearchParams({
      limit: String(memoryAuditPagination.size),
      offset: String((memoryAuditPagination.page - 1) * memoryAuditPagination.size),
    });
    const audit = await json(`/api/memory/events?${params}`);
    memoryAuditEvents = audit.events || [];
    applyPaginationPayload(memoryAuditPagination, audit.pagination);
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

function responseStatusLabel(status) {
  const key = {
    waiting_configuration: "responseWaitingConfiguration",
    waiting_dispatch: "responseWaitingDispatch",
    paused: "responsePaused",
    queued: "responseQueued",
    running: "responseRunning",
    retry_wait: "responseRetryWait",
    verified: "responseVerified",
    shadowed: "responseShadowed",
    failed: "responseFailed",
    cancelled: "responseCancelled",
    rollback_queued: "responseRollbackQueued",
    rollback_running: "responseRollbackRunning",
    rollback_retry: "responseRollbackRetry",
    rolled_back: "responseRolledBack",
    rollback_failed: "responseRollbackFailed",
  }[status];
  return tr(key || "responsePaused");
}

function responseModeLabel(mode) {
  return tr({ shadow: "connectorModeShadow", manual: "connectorModeManual", auto: "connectorModeAuto" }[mode] || "connectorModeShadow");
}

function responseActionLabel(actionType) {
  const key = { "network.block_ip": "responseActionBlockSourceIp" }[actionType];
  return key ? tr(key) : String(actionType || "-");
}

function connectorHealthLabel(status) {
  return tr({
    untested: "connectorHealthUntested",
    healthy: "connectorHealthHealthy",
    error: "connectorHealthError",
  }[status] || "connectorHealthUntested");
}

function updateResponseStats(stats = {}) {
  responseTaskStats = stats;
  const active = ["queued", "running", "retry_wait", "rollback_queued", "rollback_running", "rollback_retry"]
    .reduce((total, status) => total + Number(stats[status] || 0), 0);
  const failed = Number(stats.failed || 0) + Number(stats.rollback_failed || 0);
  const values = {
    "#automation-total": Number(stats.total || 0),
    "#automation-active": active,
    "#automation-verified": Number(stats.verified || 0),
    "#automation-failed": failed,
  };
  Object.entries(values).forEach(([selector, value]) => {
    const node = document.querySelector(selector);
    if (node) node.textContent = String(value);
  });
}

function renderResponseTasks() {
  const list = document.querySelector("#automation-task-list");
  if (!list) return;
  if (!responseTasks.length) {
    list.innerHTML = `<p class="empty-state">${escapeHtml(tr("responseTaskEmpty"))}</p>`;
    renderPagination("#automation-pagination", responseTaskPagination, "automation-tasks");
    return;
  }
  list.innerHTML = responseTasks.map((task) => {
    const action = task.action || {};
    const scope = action.scope || {};
    const connector = task.connector_snapshot || {};
    const canDispatch = ["waiting_configuration", "waiting_dispatch", "paused", "retry_wait"].includes(task.status);
    const canRollback = ["verified", "shadowed", "rollback_failed"].includes(task.status)
      || (task.status === "failed" && Boolean(task.remote_rule_id));
    const scopeText = [scope.product, scope.host, scope.path].filter(Boolean).join(" · ") || "-";
    return `
      <article class="automation-task-item ${escapeHtml(task.status)}">
        <div class="automation-task-head">
          <div><strong class="automation-mono">${escapeHtml(action.object || "-")}</strong><span>${escapeHtml(responseActionLabel(task.action_type))}</span></div>
          <span class="field-status ${["failed", "rollback_failed"].includes(task.status) ? "needs_review" : "mapped"}">${escapeHtml(responseStatusLabel(task.status))}</span>
        </div>
        <dl class="automation-task-meta">
          <div><dt>${escapeHtml(tr("responseTaskId"))}</dt><dd class="automation-mono">${escapeHtml(task.task_id)}</dd></div>
          <div><dt>Case</dt><dd class="automation-mono">${escapeHtml(task.case_id)}</dd></div>
          <div><dt>${escapeHtml(tr("responseScope"))}</dt><dd>${escapeHtml(scopeText)}</dd></div>
          <div><dt>${escapeHtml(tr("responseMode"))}</dt><dd>${escapeHtml(responseModeLabel(connector.execution_mode))}</dd></div>
          <div><dt>${escapeHtml(tr("responseRemoteRule"))}</dt><dd class="automation-mono">${escapeHtml(task.remote_rule_id || "-")}</dd></div>
          <div><dt>${escapeHtml(tr("responseExpires"))}</dt><dd>${escapeHtml(task.expires_at_ms ? fmtTime(task.expires_at_ms) : "-")}</dd></div>
        </dl>
        ${task.last_error ? `<p class="automation-task-error">${escapeHtml(task.last_error)}</p>` : ""}
        ${(canDispatch || canRollback) ? `<div class="automation-task-actions">
          ${canDispatch ? `<button type="button" data-response-action="dispatch" data-task-id="${escapeHtml(task.task_id)}" ${hasAnyRole("responder") ? "" : "disabled"}>${escapeHtml(tr("responseDispatch"))}</button>` : ""}
          ${canRollback ? `<button type="button" data-response-action="rollback" data-task-id="${escapeHtml(task.task_id)}" ${hasAnyRole("responder") ? "" : "disabled"}>${escapeHtml(tr("responseRollback"))}</button>` : ""}
        </div>` : ""}
      </article>
    `;
  }).join("");
  renderPagination("#automation-pagination", responseTaskPagination, "automation-tasks");
  applySessionPermissions();
}

async function loadResponseTasks(options = {}) {
  const list = document.querySelector("#automation-task-list");
  if (list && !options.quiet) list.innerHTML = `<p class="empty-state">${escapeHtml(tr("runtimeChecking"))}</p>`;
  const params = new URLSearchParams({
    limit: String(responseTaskPagination.size),
    offset: String((responseTaskPagination.page - 1) * responseTaskPagination.size),
  });
  const status = document.querySelector("#automation-status-filter")?.value || "";
  if (status) params.set("status", status);
  const payload = await json(`/api/automation/tasks?${params}`);
  responseTasks = payload.tasks || [];
  applyPaginationPayload(responseTaskPagination, payload.pagination);
  updateResponseStats(payload.stats || {});
  renderResponseTasks();
  return payload;
}

function resetResponseConnectorForm() {
  document.querySelector("#automation-connector-form")?.reset();
  document.querySelector("#response-connector-id").value = "";
  document.querySelector("#response-connector-mode").value = "shadow";
  document.querySelector("#response-connector-max-ttl").value = "3600";
  document.querySelector("#response-connector-timeout").value = "10";
  document.querySelector("#automation-connector-status").textContent = "";
}

function renderResponseConnectors() {
  const list = document.querySelector("#automation-connector-list");
  if (!list) return;
  if (!responseConnectors.length) {
    list.innerHTML = `<p class="empty-state">${escapeHtml(tr("responseConnectorEmpty"))}</p>`;
    return;
  }
  list.innerHTML = responseConnectors.map((connector) => `
    <article class="automation-connector-item">
      <div class="automation-task-head"><div><strong>${escapeHtml(connector.name)}</strong><span class="automation-mono">${escapeHtml(connector.endpoint)}</span></div><span class="field-status ${connector.health_status === "healthy" ? "mapped" : "needs_review"}">${escapeHtml(connectorHealthLabel(connector.health_status))}</span></div>
      <div class="automation-connector-flags"><span>${escapeHtml(responseModeLabel(connector.execution_mode))}</span><span>${escapeHtml(connector.enabled ? tr("connectorEnabled") : tr("responsePaused"))}</span><span>${escapeHtml(connector.credential_configured || !connector.secret_env ? tr("connectorCredentialReady") : tr("connectorCredentialMissing"))}</span></div>
      ${connector.last_error ? `<p class="automation-task-error">${escapeHtml(connector.last_error)}</p>` : ""}
      <div class="automation-task-actions"><button type="button" data-connector-action="edit" data-connector-id="${escapeHtml(connector.connector_id)}">${escapeHtml(tr("connectorEdit"))}</button><button type="button" data-connector-action="test" data-connector-id="${escapeHtml(connector.connector_id)}">${escapeHtml(tr("connectorTest"))}</button></div>
    </article>
  `).join("");
  applySessionPermissions();
}

function populateResponsePolicy() {
  document.querySelector("#response-policy-enabled").checked = Boolean(responsePolicy.enabled);
  document.querySelector("#response-policy-default-ttl").value = String(responsePolicy.default_ttl_seconds || 1800);
  document.querySelector("#response-policy-max-ttl").value = String(responsePolicy.max_ttl_seconds || 86400);
  document.querySelector("#response-policy-protected-cidrs").value = (responsePolicy.protected_cidrs || []).join("\n");
}

async function loadResponseSummary() {
  const payload = await json("/api/automation/summary");
  responsePolicy = payload.policy || {};
  responseConnectors = payload.connectors || [];
  updateResponseStats(payload.stats || {});
  populateResponsePolicy();
  renderResponseConnectors();
  return payload;
}

function loadAutomation(section = "tasks") {
  if (section === "tasks") return loadResponseTasks();
  return loadResponseSummary();
}

async function saveResponseConnector(event) {
  event.preventDefault();
  const connectorId = document.querySelector("#response-connector-id").value;
  const body = {
    name: document.querySelector("#response-connector-name").value.trim(),
    endpoint: document.querySelector("#response-connector-endpoint").value.trim(),
    secret_env: document.querySelector("#response-connector-secret-env").value.trim(),
    execution_mode: document.querySelector("#response-connector-mode").value,
    max_ttl_seconds: Number(document.querySelector("#response-connector-max-ttl").value),
    timeout_seconds: Number(document.querySelector("#response-connector-timeout").value),
    enabled: document.querySelector("#response-connector-enabled").checked,
  };
  const path = connectorId ? `/api/automation/connectors/${encodeURIComponent(connectorId)}` : "/api/automation/connectors";
  const payload = await json(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  document.querySelector("#automation-connector-status").textContent = tr("connectorSaved");
  resetResponseConnectorForm();
  await loadResponseSummary();
  showToast(tr("connectorSaved"));
  return payload;
}

function editResponseConnector(connectorId) {
  const connector = responseConnectors.find((item) => item.connector_id === connectorId);
  if (!connector) return;
  document.querySelector("#response-connector-id").value = connector.connector_id;
  document.querySelector("#response-connector-name").value = connector.name;
  document.querySelector("#response-connector-endpoint").value = connector.endpoint;
  document.querySelector("#response-connector-secret-env").value = connector.secret_env || "";
  document.querySelector("#response-connector-mode").value = connector.execution_mode;
  document.querySelector("#response-connector-max-ttl").value = String(connector.max_ttl_seconds);
  document.querySelector("#response-connector-timeout").value = String(connector.timeout_seconds);
  document.querySelector("#response-connector-enabled").checked = Boolean(connector.enabled);
  document.querySelector("#response-connector-name").focus();
}

async function testResponseConnector(connectorId) {
  const payload = await json(`/api/automation/connectors/${encodeURIComponent(connectorId)}/test`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  await loadResponseSummary();
  showToast(tr("connectorTested", { status: connectorHealthLabel(payload.connector?.health_status || "error") }), payload.ok ? "info" : "error");
}

async function saveResponsePolicy(event) {
  event.preventDefault();
  const payload = await json("/api/automation/policy", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      enabled: document.querySelector("#response-policy-enabled").checked,
      default_ttl_seconds: Number(document.querySelector("#response-policy-default-ttl").value),
      max_ttl_seconds: Number(document.querySelector("#response-policy-max-ttl").value),
      protected_cidrs: document.querySelector("#response-policy-protected-cidrs").value,
    }),
  });
  responsePolicy = payload.policy || {};
  populateResponsePolicy();
  document.querySelector("#automation-policy-status").textContent = tr("automationPolicySaved");
  showToast(tr("automationPolicySaved"));
}

async function runResponseTaskAction(taskId, action) {
  const payload = await json(`/api/automation/tasks/${encodeURIComponent(taskId)}/${action}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  showToast(tr("responseActionDone", { status: responseStatusLabel(payload.task?.status) }));
  await loadResponseTasks({ quiet: true });
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
    // Promotion can move the source Case from open to under_review. Refresh the
    // queue too, so the two workbenches never show contradictory lifecycle state.
    if (action === "promote") await loadCases();
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
  const target = document.querySelector(`#${name}-view`);
  if (!target) return;
  const navigationView = name === "triage"
    ? "dashboard"
    : name === "memory-associations"
      ? "memory"
      : name;
  document.querySelectorAll(".view").forEach((view) => view.classList.remove("active"));
  target.classList.add("active");
  document.querySelectorAll(".nav-button").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.view === navigationView);
  });
  document.querySelectorAll(".nav-group").forEach((group) => {
    group.classList.toggle("active", group.dataset.viewGroup === navigationView);
  });
  document.querySelectorAll(".nav-subbutton").forEach((btn) => {
    const current = btn.dataset.view === navigationView && btn.classList.contains("active");
    if (current) btn.setAttribute("aria-current", "page");
    else btn.removeAttribute("aria-current");
  });
  updateWorkspaceTitle(name);
  clearDashboardRefreshTimer();
  if (name !== "settings") stopOllamaModelRefresh();
}

function updateTriageBackLabel() {
  const button = document.querySelector("#triage-back");
  if (button) button.textContent = tr(activeDashboardSection === "history" ? "triageBackHistory" : "triageBack");
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
  if (group === "dashboard") {
    activeDashboardSection = name === "history" ? "history" : "pending";
    updateWorkspaceTitle("dashboard");
    updateTriageBackLabel();
  }
}

function activeSecondaryView(group, fallback = "") {
  return document.querySelector(`.nav-subbutton.active[data-secondary-group="${group}"]`)?.dataset.secondaryTarget || fallback;
}

function loadViewData(name) {
  if (name === "triage") return Promise.resolve();
  if (name === "monitor") {
    clearDashboardRefreshTimer();
    return loadMonitorDashboard({ refreshConfig: true }).finally(() => scheduleDashboardRefresh());
  }
  if (name === "dashboard") return loadCases({ section: activeDashboardSection });
  if (name === "settings") {
    if (!canReadRuntimeConfig()) return Promise.resolve();
    return loadLlmConfig().catch((err) => setConfigStatus(err.message || String(err), true));
  }
  if (name === "memory") {
    return loadMemoryGovernance({ section: activeSecondaryView("memory", "inventory") }).catch((err) =>
      showToast(tr("memoryActionFailed", { message: err.message || String(err) }), "error"),
    );
  }
  if (name === "automation") {
    if (!canReadAutomation()) return Promise.resolve();
    return loadAutomation(activeSecondaryView("automation", "tasks")).catch((err) =>
      showToast(err.message || String(err), "error"),
    );
  }
  if (name === "adapter") {
    const section = activeSecondaryView("adapter", "intake");
    const tasks = [];
    if (canReadRuntimeConfig()) {
      tasks.push(
        loadSyslogConfig().catch((err) =>
          setSyslogConfigStatus(tr("syslogConfigLoadFailed", { message: err.message || String(err) }), true),
        ),
        loadSyslogDeployment().catch((err) =>
          setSyslogDeploymentStatus(tr("syslogDeploymentLoadFailed", { message: err.message || String(err) }), true),
        ),
      );
    } else {
      renderSyslogDeployment();
    }
    if (section === "config") {
      tasks.push(loadMappingProfiles().catch((err) => setProfileStatus(err.message || String(err), true)));
    }
    return Promise.all(tasks);
  }
  return Promise.resolve();
}

function refreshCurrentView() {
  const active = document.querySelector(".view.active")?.id.replace(/-view$/, "")
    || document.querySelector(".nav-button.active")?.dataset.view
    || "monitor";
  if (active === "triage") {
    return loadCases({ quiet: true, section: activeDashboardSection }).then(() => selectedCaseId ? loadTriageCase(selectedCaseId) : undefined);
  }
  if (active === "memory-associations") {
    return loadMemoryAssociations({ quiet: true });
  }
  return loadViewData(active);
}

async function loadDashboardRuntime({ refreshConfig = true } = {}) {
  const llmFallback = { provider: "unavailable", model: "-", endpoint: "", unavailable: true };
  const syslogFallback = { configs: syslogConfigs, listeners: [], unavailable: true };
  const llmRequest = canReadRuntimeConfig()
    ? (refreshConfig
      ? json("/api/config/llm").catch(() => dashboardLlmConfig)
      : Promise.resolve(dashboardLlmConfig))
    : Promise.resolve(llmFallback);
  const syslogRequest = canReadRuntimeConfig()
    ? (refreshConfig
      ? json("/api/config/syslog").catch(() => dashboardSyslogPayload)
      : Promise.resolve(dashboardSyslogPayload))
    : Promise.resolve(syslogFallback);
  const [snapshot, llmConfig, syslogPayload] = await Promise.all([
    json("/api/dashboard/snapshot", { acceptStatuses: [503] }),
    llmRequest,
    syslogRequest,
  ]);
  if (canReadRuntimeConfig()) {
    dashboardLlmConfig = llmConfig;
    dashboardSyslogPayload = syslogPayload;
  }
  return {
    health: snapshot.health || {},
    caseSummary: snapshot.case_summary || { total: 0, products: [], classifications: [] },
    llmConfig,
    syslogPayload,
  };
}

async function loadMonitorDashboard(options = {}) {
  if (dashboardRefreshPromise) return dashboardRefreshPromise;
  const request = (async () => {
    const runtime = await loadDashboardRuntime(options);
    renderDashboard(runtime.health, runtime.caseSummary, runtime.llmConfig, runtime.syslogPayload);
    return runtime;
  })();
  dashboardRefreshPromise = request;
  try {
    return await request;
  } finally {
    if (dashboardRefreshPromise === request) dashboardRefreshPromise = null;
  }
}

async function loadCases(options = {}) {
  const section = options.section === "history" ? "history" : options.section === "pending" ? "pending" : activeDashboardSection;
  activeDashboardSection = section;
  const list = document.querySelector(dashboardCaseListId(section));
  try {
    const caseQuery = caseSearchQuery(section);
    const casesData = canReadCases()
      ? await json(`/api/cases?${caseQuery}`)
      : { cases: [], pagination: {} };
    detailCache.clear();
    queueCases = casesData.cases || [];
    applyPaginationPayload(casePagination[section], casesData.pagination || {});
    if (section === "history") renderProcessedList(processedQueueCases(queueCases));
    else renderQueueList(pendingQueueCases(queueCases));
  } catch (err) {
    caseListRenderKeys[section] = "";
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
  const sourceText = document.querySelector("#source-log").value.trim();
  if (sourceText) {
    const validation = await validateMappingProfile(profile, JSON.parse(sourceText));
    document.querySelector("#dry-run-result").textContent = JSON.stringify(validation, null, 2);
    mappingNeedsValidation = !validation.ok;
    if (!validation.ok) throw new Error(validation.errors?.join(", ") || tr("dryRunFailed", { fields: tr("checkResult") }));
  }
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
  const requiredMissing = fields.filter((field) => field.required && !field.mapping).map((field) => field.target);
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
  mappingNeedsValidation = true;
  renderFieldMappingTable({ fields: inferredFields });
  setProfileStatus(tr("dryRunHint"));
}

async function inferMappingProfile(event) {
  event.preventDefault();
  const log = currentLog();
  const product = selectedLogProduct();
  const body = { log };
  if (product) body.product = product;
  const result = await json("/api/mapping-profiles/infer", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  inferredProfile = result.profile;
  inferredFields = result.fields || [];
  setProfileJson(inferredProfile);
  renderFieldMappingTable(result);
  document.querySelector("#dry-run-result").textContent = JSON.stringify(result.quality || result, null, 2);
  mappingNeedsValidation = true;
  const detection = result.product_detection;
  const detectedMessage = detection?.mode === "auto" ? ` ${detection.product.toUpperCase()} (${Math.round((detection.confidence || 0) * 100)}%)` : "";
  setProfileStatus((result.ok ? tr("inferOk") : tr("inferNeedsRequired")) + detectedMessage, !result.ok);
}

async function saveCurrentProfile() {
  const profile = currentProfileForDryRun();
  if (!profile.profile_id) throw new Error(tr("selectProfileFirst"));
  if (mappingNeedsValidation) {
    const validation = await validateMappingProfile(profile);
    if (!validation.ok) throw new Error(validation.errors?.join(", ") || tr("dryRunFailed", { fields: tr("checkResult") }));
  }
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
  const result = await validateMappingProfile(profile, log);
  document.querySelector("#dry-run-result").textContent = JSON.stringify(result, null, 2);
  mappingNeedsValidation = !result.ok;
  const missing = Array.isArray(result.missing_required_fields) ? result.missing_required_fields.join(", ") : "";
  showToast(result.ok ? tr("dryRunOk") : tr("dryRunFailed", { fields: missing || tr("checkResult") }), result.ok ? "success" : "error");
}

async function validateMappingProfile(profile, log = currentLog()) {
  return json("/api/mapping-profiles/dry-run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ profile, log }),
  });
}

async function loadLlmConfig() {
  const cfg = await json("/api/config/llm");
  dashboardLlmConfig = cfg;
  populateLlmForm(cfg);
  setConfigStatus(cfg.api_key_set ? tr("configLoadedWithKey") : tr("configLoadedNoKey"));
  syncOllamaModelRefresh();
  return cfg;
}

function populateLlmForm(cfg) {
  const provider = cfg.provider || "local";
  document.querySelector("#llm-provider").value = provider;
  document.querySelector("#llm-endpoint").value = cfg.endpoint || "";
  // local provider ignores the model field; force the canonical value so the
  // form always reflects the real "local" configuration instead of stale
  // model names left over from a previous ollama session.
  document.querySelector("#llm-model").value =
    provider === "local" ? "local-rule-analyst" : cfg.model || "";
  setLlmModelPlaceholder(provider);
  document.querySelector("#llm-api-key").value = "";
  document.querySelector("#llm-api-key").placeholder = cfg.api_key_set ? tr("keySetKeep") : tr("keyUnset");
  document.querySelector("#llm-api-key-env").value = cfg.api_key_env || "DEFENSIVE_AI_LLM_API_KEY";
  document.querySelector("#llm-timeout").value = cfg.timeout_seconds || 30;
}

function setLlmModelPlaceholder(provider) {
  const placeholders = {
    local: "local-rule-analyst",
    ollama: "请选择已同步的 Ollama 模型",
    gateway: "例如 gpt-5.5",
  };
  document.querySelector("#llm-model").placeholder = placeholders[provider] || placeholders.local;
}

function stopOllamaModelRefresh() {
  if (ollamaModelRefreshTimer) {
    window.clearInterval(ollamaModelRefreshTimer);
    ollamaModelRefreshTimer = 0;
  }
  if (ollamaModelFocusRefreshTimer) {
    window.clearTimeout(ollamaModelFocusRefreshTimer);
    ollamaModelFocusRefreshTimer = 0;
  }
}

function ollamaModelRefreshAllowed() {
  return !document.hidden
    && document.querySelector("#settings-view")?.classList.contains("active") === true
    && document.querySelector("#llm-provider")?.value === "ollama";
}

function syncOllamaModelRefresh() {
  if (ollamaModelRefreshAllowed()) startOllamaModelRefresh();
  else stopOllamaModelRefresh();
}

function startOllamaModelRefresh() {
  if (!ollamaModelRefreshAllowed()) {
    stopOllamaModelRefresh();
    return;
  }
  if (ollamaModelRefreshTimer) return;
  loadOllamaModels().catch((err) => setConfigStatus(err.message || String(err), true));
  ollamaModelRefreshTimer = window.setInterval(() => {
    if (!ollamaModelRefreshAllowed()) {
      stopOllamaModelRefresh();
      return;
    }
    loadOllamaModels({ quiet: true }).catch((err) => setConfigStatus(err.message || String(err), true));
  }, OLLAMA_MODEL_REFRESH_MS);
}

function applyProviderDefaults(provider) {
  const endpoint = document.querySelector("#llm-endpoint");
  const model = document.querySelector("#llm-model");
  const timeout = document.querySelector("#llm-timeout");
  if (provider === "local") {
    stopOllamaModelRefresh();
    document.querySelector("#llm-model").value = "local-rule-analyst";
    setLlmModelPlaceholder(provider);
    timeout.value = 30;
    document.querySelector("#ollama-models").innerHTML = "";
  } else if (provider === "ollama") {
    if (model.value.trim() === "local-rule-analyst") model.value = "";
    setLlmModelPlaceholder(provider);
    if (!endpoint.value.trim()) endpoint.value = "http://127.0.0.1:11434/api/generate";
    if (!timeout.value || Number(timeout.value) < 60) timeout.value = 300;
    startOllamaModelRefresh();
  } else if (provider === "gateway") {
    stopOllamaModelRefresh();
    setLlmModelPlaceholder(provider);
    if (!endpoint.value.trim() || endpoint.value.includes("127.0.0.1:11434")) {
      endpoint.value = "https://kkcoder.com/v1/responses";
    }
    if (!model.value.trim() || model.value.trim() === "local-rule-analyst") {
      model.value = "gpt-5.5";
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
  dashboardLlmConfig = result.llm;
  populateLlmForm(result.llm);
  document.querySelector("#llm-api-key").placeholder = result.llm.api_key_set ? tr("keySetKeep") : tr("keyUnset");
  setConfigStatus(tr("configRestored"));
  syncOllamaModelRefresh();
}

async function loadOllamaModels({ quiet = false } = {}) {
  const datalist = document.querySelector("#ollama-models");
  // Pass the endpoint currently typed in the form so the picker works before
  // the configuration is saved (the backend no longer gates on the saved
  // provider).
  const endpoint = document.querySelector("#llm-endpoint").value.trim();
  const qs = endpoint ? `?endpoint=${encodeURIComponent(endpoint)}` : "";
  const requestId = ++ollamaModelLoadRequestId;
  const result = await json(`/api/config/llm/models${qs}`, { cache: "no-store" });
  if (
    requestId !== ollamaModelLoadRequestId
    || document.querySelector("#llm-provider").value !== "ollama"
    || document.querySelector("#llm-endpoint").value.trim() !== endpoint
  ) {
    return [];
  }
  const models = Array.isArray(result.models) ? result.models : [];
  const current = document.querySelector("#llm-model").value;
  datalist.innerHTML = models.map((name) => `<option value="${escapeHtml(name)}"></option>`).join("");
  if (!result.ok) {
    if (!quiet) setConfigStatus(tr("modelsLoadFailed", { error: result.error || "unknown" }), true);
    return models;
  }
  if (!quiet) {
    if (models.length === 0) {
      setConfigStatus(tr("modelsEmpty", { endpoint: result.endpoint || "" }));
    } else {
      setConfigStatus(tr("modelsLoaded", { count: models.length, endpoint: result.endpoint || "" }));
    }
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
  dashboardLlmConfig = result.llm;
  populateLlmForm(result.llm);
  document.querySelector("#llm-api-key").placeholder = result.llm.api_key_set ? tr("keySetKeep") : tr("keyUnset");
  setConfigStatus(tr("configSaved", { provider: result.llm.provider, model: result.llm.model }));
  syncOllamaModelRefresh();
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

async function resumeDeferredLlmAlerts() {
  const button = document.querySelector("#resume-llm-deferred");
  const originalText = button.textContent;
  button.disabled = true;
  button.textContent = tr("resumingDeferredAlerts");
  try {
    const result = await json("/api/alerts/inbox/release-llm-deferred", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ limit: 100 }),
    });
    const message = result.reason === "remote_model_not_configured"
      ? tr("deferredAlertsNeedRemoteModel")
      : tr("deferredAlertsReleased", { count: Number(result.released || 0) });
    setConfigStatus(message);
    showToast(message);
    await loadCases({ quiet: true, section: activeDashboardSection });
  } catch (err) {
    setConfigStatus(err.message || String(err), true);
  } finally {
    button.textContent = originalText;
    applySessionPermissions();
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

document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    clearDashboardRefreshTimer();
    stopOllamaModelRefresh();
    return;
  }
  if (monitorViewIsActive()) scheduleDashboardRefresh({ immediate: true });
  syncOllamaModelRefresh();
});

document.querySelector("#refresh").addEventListener("click", () => {
  refreshCurrentView().catch((err) => showToast(err.message || String(err), "error"));
});
document.querySelector("#test-llm-connection").addEventListener("click", () => {
  testLlmConnection().catch((err) => setConfigStatus(err.message || String(err), true));
});
document.querySelector("#resume-llm-deferred").addEventListener("click", () => {
  resumeDeferredLlmAlerts().catch((err) => setConfigStatus(err.message || String(err), true));
});
document.querySelector("#triage-back").addEventListener("click", () => {
  setView("dashboard");
  setSecondaryView("dashboard", activeDashboardSection);
  loadCases({ quiet: true, section: activeDashboardSection }).catch((err) => showToast(err.message || String(err), "error"));
});
document.querySelector("#memory-associations-back").addEventListener("click", () => {
  memoryAssociationRequestId += 1;
  setView("memory");
  setSecondaryView("memory", "inventory");
});
document.querySelector("#memory-associations-refresh").addEventListener("click", () => {
  loadMemoryAssociations({ quiet: true }).catch((err) =>
    showToast(tr("refreshFailed", { message: err.message || String(err) }), "error"),
  );
});
document.querySelectorAll(".case-search-form").forEach((form) => {
  const section = form.dataset.caseSearchSection === "history" ? "history" : "pending";
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    casePagination[section].page = 1;
    activeDashboardSection = section;
    setView("dashboard");
    setSecondaryView("dashboard", section);
    loadCases({ section }).catch((err) => showToast(tr("refreshFailed", { message: err.message || String(err) }), "error"));
  });
  form.querySelector("button[type=button]")?.addEventListener("click", () => {
    form.reset();
    if (section === "pending") setPendingCaseSearchCurrentMonth();
    casePagination[section].page = 1;
    activeDashboardSection = section;
    setView("dashboard");
    setSecondaryView("dashboard", section);
    loadCases({ section }).catch((err) => showToast(tr("refreshFailed", { message: err.message || String(err) }), "error"));
  });
});
document.querySelector("#memory-filter-form").addEventListener("submit", (event) => {
  event.preventDefault();
  memoryPagination.page = 1;
  loadMemoryInventory().catch((err) => showToast(tr("memoryActionFailed", { message: err.message || String(err) }), "error"));
});
document.querySelector("#memory-filter-reset").addEventListener("click", () => {
  document.querySelector("#memory-filter-form").reset();
  memoryPagination.page = 1;
  loadMemoryInventory().catch((err) => showToast(tr("memoryActionFailed", { message: err.message || String(err) }), "error"));
});
document.querySelector("#memory-sweep").addEventListener("click", sweepMemory);
document.querySelector("#memory-audit-refresh").addEventListener("click", () => {
  loadMemoryAudit({ quiet: true }).catch((err) =>
    showToast(tr("memoryActionFailed", { message: err.message || String(err) }), "error"),
  );
});
document.querySelector("#automation-refresh").addEventListener("click", () => {
  loadResponseTasks({ quiet: true }).catch((err) => showToast(err.message || String(err), "error"));
});
document.querySelector("#automation-task-filter").addEventListener("submit", (event) => {
  event.preventDefault();
  responseTaskPagination.page = 1;
  loadResponseTasks().catch((err) => showToast(err.message || String(err), "error"));
});
document.querySelector("#automation-connector-form").addEventListener("submit", (event) => {
  saveResponseConnector(event).catch((err) => {
    document.querySelector("#automation-connector-status").textContent = err.message || String(err);
    showToast(err.message || String(err), "error");
  });
});
document.querySelector("#response-connector-reset").addEventListener("click", resetResponseConnectorForm);
document.querySelector("#automation-policy-form").addEventListener("submit", (event) => {
  saveResponsePolicy(event).catch((err) => {
    document.querySelector("#automation-policy-status").textContent = err.message || String(err);
    showToast(err.message || String(err), "error");
  });
});
document.addEventListener("click", (event) => {
  const responseButton = event.target.closest("[data-response-action]");
  if (responseButton && !responseButton.disabled) {
    responseButton.disabled = true;
    runResponseTaskAction(responseButton.dataset.taskId, responseButton.dataset.responseAction)
      .catch((err) => showToast(err.message || String(err), "error"))
      .finally(() => { responseButton.disabled = false; });
    return;
  }
  const connectorButton = event.target.closest("[data-connector-action]");
  if (!connectorButton || connectorButton.disabled) return;
  if (connectorButton.dataset.connectorAction === "edit") {
    editResponseConnector(connectorButton.dataset.connectorId);
    return;
  }
  connectorButton.disabled = true;
  testResponseConnector(connectorButton.dataset.connectorId)
    .catch((err) => showToast(err.message || String(err), "error"))
    .finally(() => { connectorButton.disabled = false; });
});
document.addEventListener("change", (event) => {
  const select = event.target.closest("[data-pagination-size]");
  if (!select) return;
  const state = paginationState(select.dataset.paginationSize);
  const size = Number(select.value);
  if (!state || !PAGE_SIZE_OPTIONS.includes(size)) return;
  state.size = size;
  state.page = 1;
  reloadPagination(select.dataset.paginationSize).catch((err) =>
    showToast(tr("refreshFailed", { message: err.message || String(err) }), "error"),
  );
});
document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-pagination-action]");
  if (!button || button.disabled) return;
  const key = button.dataset.paginationKey;
  const state = paginationState(key);
  if (!state) return;
  const direction = button.dataset.paginationAction === "next" ? 1 : -1;
  state.page = Math.min(state.totalPages, Math.max(1, state.page + direction));
  reloadPagination(key).catch((err) =>
    showToast(tr("refreshFailed", { message: err.message || String(err) }), "error"),
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
document.querySelector("#language-switch").addEventListener("click", () => {
  toggleLanguage();
  refreshCurrentView().catch((err) => showToast(err.message || String(err), "error"));
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
document.querySelector("#llm-model").addEventListener("focus", () => {
  if (document.querySelector("#llm-provider").value !== "ollama") return;
  if (ollamaModelFocusRefreshTimer) window.clearTimeout(ollamaModelFocusRefreshTimer);
  ollamaModelFocusRefreshTimer = window.setTimeout(() => {
    loadOllamaModels({ quiet: true }).catch((err) => setConfigStatus(err.message || String(err), true));
  }, 0);
});
document.querySelector("#profile-form").addEventListener("submit", (event) => {
  saveMappingProfile(event).catch((err) => setProfileStatus(err.message || String(err), true));
});
document.querySelector("#infer-form").addEventListener("submit", (event) => {
  inferMappingProfile(event).catch((err) => setProfileStatus(err.message || String(err), true));
});
document.querySelector("#load-sample-log").addEventListener("click", () => {
  const product = selectedLogProduct() || "waf";
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
  mappingNeedsValidation = true;
  setProfileJson({});
  renderFieldMappingTable(null);
  document.querySelector("#dry-run-result").textContent = tr("dryRunHint");
  setProfileStatus("");
});
document.querySelector("#source-log").addEventListener("input", () => {
  mappingNeedsValidation = true;
});
document.querySelector("#save-inferred-profile").addEventListener("click", () => {
  saveCurrentProfile().catch((err) => setProfileStatus(err.message || String(err), true));
});
document.querySelector("#reload-profiles").addEventListener("click", () => {
  loadMappingProfiles().catch((err) => setProfileStatus(err.message || String(err), true));
});
document.querySelector("#reset-syslog-config").addEventListener("click", fillDefaultSyslogConfigs);
document.querySelector("#syslog-deployment-form").addEventListener("submit", (event) => {
  saveSyslogDeployment(event).catch((err) => {
    const message = err.message || String(err);
    setSyslogDeploymentStatus(message, true);
    showToast(message, "error");
  });
});
document.querySelector("#export-syslog-deployment").addEventListener("click", exportSyslogDeployment);
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
  try {
    return await loadMonitorDashboard({ refreshConfig: true });
  } finally {
    scheduleDashboardRefresh();
  }
}

document.querySelector("#auth-session").addEventListener("click", () => showAuthDialog());
document.querySelector("#auth-close").addEventListener("click", () => document.querySelector("#auth-dialog").close());
document.querySelector("#manual-review-close").addEventListener("click", closeManualReviewDialog);
document.querySelector("#manual-review-cancel").addEventListener("click", closeManualReviewDialog);
document.querySelector("#manual-review-dialog").addEventListener("close", () => {
  pendingManualReview = null;
  document.querySelector("#manual-review-reason").value = "";
  document.querySelector("#manual-review-form-status").textContent = "";
});
document.querySelector("#manual-review-form").addEventListener("submit", (event) => {
  event.preventDefault();
  submitManualReviewContinuation();
});
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

renderLogProductOptions();
setPendingCaseSearchCurrentMonth();
loadApplicationData().catch((err) =>
  showToast(err.message || String(err), "error"),
);
