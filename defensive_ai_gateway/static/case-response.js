const API_TOKEN_KEY = "defensive-ai-api-token";
const LANGUAGE_KEY = "dashboard-language";
const TIMELINE_PAGE_SIZE = 20;
const AGENT_POLL_INTERVAL_MS = 1500;
const AGENT_ACTIVE_STATUSES = new Set([
  "queued", "running", "waiting_input", "paused", "synthesizing", "validating",
]);
const AGENT_POLL_STATUSES = new Set([
  "queued", "running", "synthesizing", "validating",
]);
const AGENT_TERMINAL_STATUSES = new Set([
  "completed", "review", "blocked", "failed", "cancelled", "budget_exhausted",
]);

let caseId = "";
let artifact = null;
let caseContext = {};
let timelinePage = 1;
let requestSequence = 0;
let timelineRequestSequence = 0;
let timelineRenderKey = "";
let timelineRevision = "";
let latestAbortController = null;
let timelineAbortController = null;
let canGenerate = false;
let agentSession = null;
let agentSteps = [];
let agentAfterSequence = 0;
let agentRequestSequence = 0;
let agentAbortController = null;
let agentPollTimer = null;
let agentDrawerOpen = false;
let agentTraceExpanded = true;
let agentTraceMiddleExpanded = false;

const COPY = {
  zh: {
    back: "返回 Case",
    kicker: "AI 驱动响应",
    agentKicker: "响应调查 Agent",
    workbenchTitle: "Case 响应工作台",
    loadingCase: "正在加载 Case…",
    refresh: "刷新",
    generate: "生成新版本",
    generating: "正在生成…",
    loading: "正在加载…",
    notGenerated: "该 Case 尚未生成 Response Pack。",
    loadFailed: "加载失败",
    generated: "Response Pack 已生成。",
    reused: "当前证据快照已有相同版本。",
    stale: "已过期",
    current: "当前版本",
    version: "版本",
    validation: "制品门禁",
    caseId: "Case ID",
    status: "状态",
    severity: "事件等级",
    classification: "研判结论",
    confidence: "置信度",
    asOf: "数据截至",
    evidence: "证据引用",
    facts: "关键事实",
    uncertainties: "证据缺口",
    pending: "待决策",
    empty: "暂无记录",
    draftOnly: "仅草稿",
    approvalRequired: "需审批",
    routingEligible: "可进入既有审批链",
    routingBlocked: "当前门禁不允许流转",
    scopeCapability: "连接器能力",
    enforcedScope: "实际执行边界",
    contextOnly: "仅上下文",
    boundary: "边界说明",
    candidateScope: "候选约束范围",
    gate: "流转门禁",
    actionTarget: "处置对象",
    fineCandidate: "细粒度候选",
    capabilityBlocked: "能力未就绪",
    duration: "时效",
    minutes: "分钟",
    actionTaken: "已核验动作",
    actionPending: "待执行动作",
    simulations: "影子演练",
    exceptions: "执行异常",
    unknowns: "尚待确认",
    nextUpdate: "下次更新触发条件",
    rationale: "处置依据",
    successCriteria: "完成标准",
    rollback: "回滚要求",
    summaryHeading: "Case 摘要",
    containmentHeading: "精细遏制建议",
    playbookHeading: "响应 Playbook",
    communicationHeading: "内部事件沟通草稿",
    timelineHeading: "事件时间线",
    copyReport: "复制汇报内容",
    copied: "汇报内容已复制。",
    copyFailed: "无法复制汇报内容",
    reportDraft: "内部安全事件通报（草稿）",
    reportType: "通报性质",
    reportAudience: "通报对象",
    reportPrepared: "编制时间",
    reportVersion: "草稿版本",
    incidentOverview: "一、事件概述",
    currentAssessment: "当前判断",
    businessImpact: "业务影响",
    confirmedFacts: "二、已确认事实",
    treatmentProgress: "三、处置进展",
    pendingApprovals: "待审批事项",
    risksUnknowns: "四、风险与待确认事项",
    followUp: "五、后续安排",
    reportNotice: "本通报由系统根据当前 Case 证据生成，仅供内部研判与汇报，尚未自动发送或执行任何处置动作。",
    impactReviewNotice: "基于当前研判形成，发布前需由事件负责人复核。",
    actor: "操作人",
    overviewLabel: "Case 响应概览",
    timelinePaginationLabel: "事件时间线分页",
    noKnownFacts: "暂无可确认事实。",
    noVerifiedActions: "暂无已核验的生产处置动作。",
    noPendingActions: "暂无已进入执行流程的待办任务。",
    noSimulations: "暂无影子演练记录。",
    noExceptions: "暂无执行异常。",
    noUnknowns: "暂无新增待确认事项。",
    noApprovals: "暂无待审批事项。",
    eventRecord: "事件记录",
    decisionItem: (value) => `审批单 ${value} 待处理`,
    occurred: "发生时间",
    recorded: "系统记录",
    reportedTime: "设备上报时间",
    fallbackTime: "入库时间回退",
    systemTime: "系统时间",
    previous: "上一页",
    next: "下一页",
    page: (current, total, count) => `第 ${current} / ${total} 页 · 共 ${count} 条`,
    agentOpen: "唤起调查 Agent",
    agentTitle: "深度响应调查",
    expandAgent: "展开调查工作台",
    collapseAgent: "收起为侧边栏",
    closeAgent: "关闭",
    agentGoal: "调查目标",
    agentDefaultGoal: "基于当前 Case 的受治理证据，完成深入调查并形成可审计的完整结论。",
    agentStart: "开始调查",
    agentStarting: "正在启动…",
    agentRerun: "重新执行",
    agentRerunning: "正在重新执行…",
    agentLoading: "正在加载调查会话…",
    agentNoSession: "当前 Case 尚无调查会话。",
    agentSession: "调查会话",
    agentPlan: "调查计划",
    agentTrace: "调查轨迹",
    agentTraceCount: (count) => `${count} 步`,
    agentTraceShow: "展开调查轨迹",
    agentTraceHide: "收起调查轨迹",
    agentTraceFirst: "首次轨迹",
    agentTraceLatest: "最新轨迹",
    agentTraceOnly: "首次轨迹 · 当前最新",
    agentTraceMiddle: (count) => `中间 ${count} 条调查记录`,
    agentReport: "深度调查报告",
    agentExecutiveSummary: "执行摘要",
    agentTurns: "轮次",
    agentTools: "工具调用",
    agentElapsed: "活动时长",
    agentSeconds: "秒",
    agentPause: "暂停",
    agentResume: "继续",
    agentCancel: "取消",
    agentInput: "补充信息",
    agentInputSubmit: "提交并继续",
    agentStale: "当前 Case 已出现新证据，本会话和报告基于旧快照。",
    agentReadOnly: "Agent 可执行受治理的数据库只读调查与原始日志溯源，不会直接执行生产处置。",
    agentGate: "报告门禁",
    agentConclusion: "完整结论",
    agentRiskAssessment: "风险研判",
    agentRiskLevel: "风险等级",
    agentAttackStatus: "攻击状态",
    agentLikelihood: "发生可能性",
    agentImpactLevel: "影响等级",
    agentAggravatingFactors: "风险加剧因素",
    agentMitigatingFactors: "风险缓解因素",
    agentAttackChain: "攻击活动时间线",
    agentRelatedActivity: "同源/同目标关联活动",
    agentRelationship: "关联依据",
    agentSource: "来源",
    agentTarget: "目标",
    agentFindings: "关键发现",
    agentHypotheses: "调查假设验证",
    agentHypothesisSupport: "支持证据",
    agentHypothesisAgainst: "反证/不一致证据",
    agentHypothesisMissing: "仍缺证据",
    agentCorrelation: "跨源关联分析",
    agentCorrelationPivots: "关联支点",
    agentScope: "影响范围界定",
    agentObservedEntities: "已观测实体",
    agentCoveredDomains: "已覆盖取证域",
    agentUnresolvedDomains: "未解决取证域",
    agentImpact: "影响分析",
    agentForensics: "深度取证流程",
    agentTechnicalAppendix: "技术取证附录",
    agentTechnicalAppendixOpen: "展开查看取证覆盖与关联明细",
    agentForensicSources: "现有证据源",
    agentCollectionSteps: "补充采集步骤",
    agentForensicAssessment: "调查判断",
    agentForensicObservations: "已取得结果",
    agentAlternativeExplanations: "替代解释",
    agentNextPivots: "下一调查支点",
    agentEvidenceMore: (count) => `→ 其余 ${count} 条`,
    agentGaps: "证据缺口",
    agentResponsePlan: "响应计划",
    agentFinalAssessment: "最终判断",
    agentEmptyFindings: "暂无结构化发现。",
    agentEmptyForensics: "暂无取证流程。",
    agentEmptyGaps: "暂无新增证据缺口。",
    agentEmptyPlan: "暂无响应步骤。",
    agentCommandFailed: "Agent 操作失败",
    agentWaitingInput: "Agent 正在等待分析员补充信息。",
  },
  en: {
    back: "Back to Case",
    kicker: "Respond powered by AI",
    agentKicker: "Response Agent",
    workbenchTitle: "Case Response Workbench",
    loadingCase: "Loading Case…",
    refresh: "Refresh",
    generate: "Generate version",
    generating: "Generating…",
    loading: "Loading…",
    notGenerated: "No Response Pack has been generated for this Case.",
    loadFailed: "Unable to load",
    generated: "Response Pack generated.",
    reused: "The current evidence snapshot already has this version.",
    stale: "Stale",
    current: "Current",
    version: "Version",
    validation: "Artifact gate",
    caseId: "Case ID",
    status: "Status",
    severity: "Severity",
    classification: "Assessment",
    confidence: "Confidence",
    asOf: "Data current as of",
    evidence: "Evidence references",
    facts: "Key facts",
    uncertainties: "Evidence gaps",
    pending: "Pending decisions",
    empty: "No records",
    draftOnly: "Draft only",
    approvalRequired: "Approval required",
    routingEligible: "Eligible for the existing approval path",
    routingBlocked: "Current gate prevents routing",
    scopeCapability: "Connector capability",
    enforcedScope: "Enforced boundary",
    contextOnly: "Context only",
    boundary: "Boundary",
    candidateScope: "Candidate constraint scope",
    gate: "Routing gate",
    actionTarget: "Response target",
    fineCandidate: "Fine-grained candidate",
    capabilityBlocked: "Capability unavailable",
    duration: "Duration",
    minutes: "minutes",
    actionTaken: "Verified actions",
    actionPending: "Pending actions",
    simulations: "Shadow simulations",
    exceptions: "Execution exceptions",
    unknowns: "Unknowns",
    nextUpdate: "Next update trigger",
    rationale: "Rationale",
    successCriteria: "Completion criteria",
    rollback: "Rollback requirement",
    summaryHeading: "Case summary",
    containmentHeading: "Fine-grained containment",
    playbookHeading: "Response playbook",
    communicationHeading: "Internal incident communication draft",
    timelineHeading: "Incident timeline",
    copyReport: "Copy report",
    copied: "Report content copied.",
    copyFailed: "Unable to copy report content",
    reportDraft: "Internal Security Incident Notification (Draft)",
    reportType: "Document type",
    reportAudience: "Audience",
    reportPrepared: "Prepared at",
    reportVersion: "Draft version",
    incidentOverview: "1. Incident overview",
    currentAssessment: "Current assessment",
    businessImpact: "Business impact",
    confirmedFacts: "2. Confirmed facts",
    treatmentProgress: "3. Response progress",
    pendingApprovals: "Pending approvals",
    risksUnknowns: "4. Risks and open questions",
    followUp: "5. Follow-up",
    reportNotice: "This draft is generated from the current Case evidence for internal review and reporting. It has not been sent and has not executed any response action.",
    impactReviewNotice: "Based on the current assessment and subject to incident-owner review before publication.",
    actor: "Actor",
    overviewLabel: "Case response overview",
    timelinePaginationLabel: "Incident timeline pagination",
    noKnownFacts: "No facts have been confirmed.",
    noVerifiedActions: "No production response action has been verified.",
    noPendingActions: "No pending task has entered the execution workflow.",
    noSimulations: "No shadow simulation has been recorded.",
    noExceptions: "No execution exception has been recorded.",
    noUnknowns: "No additional open question has been recorded.",
    noApprovals: "No approval is pending.",
    eventRecord: "Event record",
    decisionItem: (value) => `Approval ${value} is pending`,
    occurred: "Occurred",
    recorded: "Recorded",
    reportedTime: "Device-reported time",
    fallbackTime: "Ingest-time fallback",
    systemTime: "System time",
    previous: "Previous",
    next: "Next",
    page: (current, total, count) => `Page ${current} of ${total} · ${count} entries`,
    agentOpen: "Open investigation agent",
    agentTitle: "Deep response investigation",
    expandAgent: "Expand investigation workbench",
    collapseAgent: "Collapse to side panel",
    closeAgent: "Close",
    agentGoal: "Investigation goal",
    agentDefaultGoal: "Investigate the governed Case evidence and produce a complete, auditable conclusion.",
    agentStart: "Start investigation",
    agentStarting: "Starting…",
    agentRerun: "Run again",
    agentRerunning: "Starting a new run…",
    agentLoading: "Loading investigation session…",
    agentNoSession: "This Case has no investigation session.",
    agentSession: "Investigation session",
    agentPlan: "Investigation plan",
    agentTrace: "Investigation trace",
    agentTraceCount: (count) => `${count} steps`,
    agentTraceShow: "Expand investigation trace",
    agentTraceHide: "Collapse investigation trace",
    agentTraceFirst: "First trace",
    agentTraceLatest: "Latest trace",
    agentTraceOnly: "First trace · latest",
    agentTraceMiddle: (count) => `${count} intermediate investigation records`,
    agentReport: "Deep investigation report",
    agentExecutiveSummary: "Executive summary",
    agentTurns: "Turns",
    agentTools: "Tool calls",
    agentElapsed: "Active time",
    agentSeconds: "sec",
    agentPause: "Pause",
    agentResume: "Resume",
    agentCancel: "Cancel",
    agentInput: "Additional information",
    agentInputSubmit: "Submit and continue",
    agentStale: "New Case evidence exists; this session and report use an older snapshot.",
    agentReadOnly: "The Agent can run governed read-only database and raw-log investigations. It never executes a production response directly.",
    agentGate: "Report gate",
    agentConclusion: "Conclusion",
    agentRiskAssessment: "Risk assessment",
    agentRiskLevel: "Risk level",
    agentAttackStatus: "Attack status",
    agentLikelihood: "Likelihood",
    agentImpactLevel: "Impact level",
    agentAggravatingFactors: "Aggravating factors",
    agentMitigatingFactors: "Mitigating factors",
    agentAttackChain: "Attack activity timeline",
    agentRelatedActivity: "Same-source / same-target activity",
    agentRelationship: "Relationship",
    agentSource: "Source",
    agentTarget: "Target",
    agentFindings: "Key findings",
    agentHypotheses: "Investigation hypothesis testing",
    agentHypothesisSupport: "Supporting evidence",
    agentHypothesisAgainst: "Contradicting/inconsistent evidence",
    agentHypothesisMissing: "Evidence still required",
    agentCorrelation: "Cross-source correlation",
    agentCorrelationPivots: "Correlation pivots",
    agentScope: "Impact scope",
    agentObservedEntities: "Observed entities",
    agentCoveredDomains: "Covered forensic domains",
    agentUnresolvedDomains: "Unresolved forensic domains",
    agentImpact: "Impact",
    agentForensics: "Deep forensic workstreams",
    agentTechnicalAppendix: "Technical forensic appendix",
    agentTechnicalAppendixOpen: "Expand forensic coverage and correlation details",
    agentForensicSources: "Available evidence sources",
    agentCollectionSteps: "Additional collection steps",
    agentForensicAssessment: "Investigation assessment",
    agentForensicObservations: "Results obtained",
    agentAlternativeExplanations: "Alternative explanations",
    agentNextPivots: "Next investigation pivots",
    agentEvidenceMore: (count) => `→ ${count} more`,
    agentGaps: "Evidence gaps",
    agentResponsePlan: "Response plan",
    agentFinalAssessment: "Final assessment",
    agentEmptyFindings: "No structured findings.",
    agentEmptyForensics: "No forensic workstreams.",
    agentEmptyGaps: "No additional evidence gaps.",
    agentEmptyPlan: "No response steps.",
    agentCommandFailed: "Agent operation failed",
    agentWaitingInput: "The agent is waiting for analyst input.",
  },
};

const ENUM_LABELS = {
  zh: {
    audience: {
      internal_soc_and_business_owner: "内部 SOC 与业务负责人",
    },
    actionType: {
      "network.block_ip": "临时封禁来源 IP",
    },
    capability: {
      "network.source_ip": "来源 IP + TTL",
      "waf.host_path.source_ip": "WAF Host + Path + 来源 IP",
    },
    stage: {
      verify: "证据核验",
      coordinate: "协同通报",
      contain: "风险遏制",
      eradicate: "根因清除",
      recover: "业务恢复",
      monitor: "持续监测",
    },
    mode: {
      observe: "人工观察",
      automated_read_only: "自动只读核验",
      read_only: "只读核验",
      approve_required: "审批后执行",
      draft_only: "仅草稿",
    },
    claimState: {
      confirmed: "已确认",
      inferred: "推断",
      unverified: "未验证",
    },
    hypothesisDisposition: {
      supported: "已支持",
      partially_supported: "部分支持",
      not_supported: "不支持",
      unresolved: "未解决",
    },
    correlationStrength: {
      multi_source: "多源交叉印证",
      single_source: "单一来源",
      no_correlation: "未取得关联结果",
    },
    attackStatus: {
      confirmed_compromise: "已确认失陷",
      likely_compromise: "很可能已失陷",
      malicious_activity: "已确认恶意活动",
      attempted_attack: "攻击尝试",
      suspicious: "可疑活动",
      benign: "良性活动",
      insufficient_evidence: "证据不足",
    },
    likelihood: {
      high: "高",
      medium: "中",
      low: "低",
      unknown: "未知",
    },
    forensicConclusion: {
      corroborated: "已交叉印证",
      single_source: "单源线索",
      unresolved: "尚未解决",
    },
    kind: {
      security_event: "安全告警",
      analysis_replay: "重新研判",
      analysis: "AI 研判",
      validation: "制品校验",
      approval_request: "审批申请",
      approval_vote: "审批意见",
      approval_decision: "审批结论",
      response_task: "处置任务",
      response_attempt: "执行尝试",
      response_task_state: "任务状态",
      governance: "治理操作",
    },
    governance: {
      escalate_case_review: "升级人工复核",
      confirm_case_attack: "确认真实攻击",
      close_case: "关闭 Case",
      reopen_case: "重新打开 Case",
      manual_validation_review_continued: "继续人工校验",
      analysis_replay_requested: "发起重新研判",
      analysis_replay_completed: "重新研判完成",
      case_response_pack_generated: "生成响应草稿",
      case_response_pack_reused: "复用响应草稿",
    },
    state: {
      current: "当前",
      stale: "已过期",
      passed: "通过",
      verified: "已核验",
      approved: "已批准",
      pending: "待处理",
      review: "待复核",
      suspicious: "可疑",
      malicious: "恶意",
      benign: "良性",
      trusted: "可信",
      blocked: "已阻断",
      failed: "失败",
      rejected: "已拒绝",
      cancelled: "已取消",
      critical: "严重",
      high: "高危",
      medium: "中危",
      low: "低危",
      info: "提示",
      closed: "已关闭",
      false_positive: "误报",
      under_review: "复核中",
      queued: "已排队",
      running: "执行中",
      waiting_input: "等待补充",
      synthesizing: "生成报告中",
      validating: "报告校验中",
      budget_exhausted: "预算已耗尽",
      retry_wait: "等待重试",
      waiting_configuration: "等待配置",
      waiting_dispatch: "等待下发",
      paused: "已暂停",
      shadowed: "影子演练",
      rolled_back: "已回滚",
      rollback_queued: "等待回滚",
      rollback_running: "回滚中",
      rollback_retry: "等待回滚重试",
      rollback_failed: "回滚失败",
      completed: "已完成",
      evidence_available: "证据可用",
      partial: "部分覆盖",
      collection_required: "需要补采",
      created: "已创建",
      success: "成功",
      error: "异常",
      not_sent: "未发送",
    },
  },
  en: {
    audience: {
      internal_soc_and_business_owner: "Internal SOC and business owner",
    },
    actionType: {
      "network.block_ip": "Temporarily block source IP",
    },
    capability: {
      "network.source_ip": "Source IP + TTL",
      "waf.host_path.source_ip": "WAF Host + Path + source IP",
    },
    stage: {
      verify: "Verify",
      coordinate: "Coordinate",
      contain: "Contain",
      eradicate: "Eradicate",
      recover: "Recover",
      monitor: "Monitor",
    },
    mode: {
      observe: "Human observation",
      automated_read_only: "Automated read-only check",
      read_only: "Read-only check",
      approve_required: "Execute after approval",
      draft_only: "Draft only",
    },
    claimState: {
      confirmed: "Confirmed",
      inferred: "Inferred",
      unverified: "Unverified",
    },
    hypothesisDisposition: {
      supported: "Supported",
      partially_supported: "Partially supported",
      not_supported: "Not supported",
      unresolved: "Unresolved",
    },
    correlationStrength: {
      multi_source: "Cross-source corroboration",
      single_source: "Single source",
      no_correlation: "No correlation result",
    },
    attackStatus: {
      confirmed_compromise: "Confirmed compromise",
      likely_compromise: "Likely compromise",
      malicious_activity: "Confirmed malicious activity",
      attempted_attack: "Attempted attack",
      suspicious: "Suspicious activity",
      benign: "Benign activity",
      insufficient_evidence: "Insufficient evidence",
    },
    likelihood: {
      high: "High",
      medium: "Medium",
      low: "Low",
      unknown: "Unknown",
    },
    forensicConclusion: {
      corroborated: "Corroborated",
      single_source: "Single-source lead",
      unresolved: "Unresolved",
    },
    kind: {
      security_event: "Security alert",
      analysis_replay: "Analysis replay",
      analysis: "AI analysis",
      validation: "Artifact validation",
      approval_request: "Approval request",
      approval_vote: "Approval vote",
      approval_decision: "Approval decision",
      response_task: "Response task",
      response_attempt: "Execution attempt",
      response_task_state: "Task state",
      governance: "Governance action",
    },
    governance: {
      escalate_case_review: "Escalate for human review",
      confirm_case_attack: "Confirm attack",
      close_case: "Close Case",
      reopen_case: "Reopen Case",
      manual_validation_review_continued: "Continue manual validation",
      analysis_replay_requested: "Request analysis replay",
      analysis_replay_completed: "Complete analysis replay",
      case_response_pack_generated: "Generate response draft",
      case_response_pack_reused: "Reuse response draft",
    },
    state: {
      current: "Current",
      stale: "Stale",
      passed: "Passed",
      verified: "Verified",
      approved: "Approved",
      pending: "Pending",
      review: "Review required",
      suspicious: "Suspicious",
      malicious: "Malicious",
      benign: "Benign",
      trusted: "Trusted",
      blocked: "Blocked",
      failed: "Failed",
      rejected: "Rejected",
      cancelled: "Cancelled",
      critical: "Critical",
      high: "High",
      medium: "Medium",
      low: "Low",
      info: "Informational",
      closed: "Closed",
      false_positive: "False positive",
      under_review: "Under review",
      queued: "Queued",
      running: "Running",
      waiting_input: "Waiting for input",
      synthesizing: "Synthesizing report",
      validating: "Validating report",
      budget_exhausted: "Budget exhausted",
      retry_wait: "Waiting to retry",
      waiting_configuration: "Waiting for configuration",
      waiting_dispatch: "Waiting for dispatch",
      paused: "Paused",
      shadowed: "Shadow simulation",
      rolled_back: "Rolled back",
      rollback_queued: "Rollback queued",
      rollback_running: "Rollback running",
      rollback_retry: "Rollback retry pending",
      rollback_failed: "Rollback failed",
      completed: "Completed",
      evidence_available: "Evidence available",
      partial: "Partial coverage",
      collection_required: "Collection required",
      created: "Created",
      success: "Succeeded",
      error: "Error",
      not_sent: "Not sent",
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

function tr(key, ...args) {
  const value = COPY[language()][key];
  return typeof value === "function" ? value(...args) : value;
}

function humanize(value) {
  const text = String(value || "").trim().replaceAll("_", " ");
  if (!text) return "-";
  const normalized = language() === "en"
    ? `${text.charAt(0).toUpperCase()}${text.slice(1)}`
    : text;
  return normalized.length > 48 ? `${normalized.slice(0, 45)}...` : normalized;
}

function enumLabel(group, value) {
  const key = String(value || "");
  return ENUM_LABELS[language()]?.[group]?.[key] || humanize(key);
}

function applyLocalizedStaticText() {
  document.querySelector("#case-response-back").textContent = tr("back");
  document.querySelector("#case-response-kicker").textContent = tr("kicker");
  document.querySelector("#case-response-title").textContent = tr("workbenchTitle");
  document.querySelector("#case-response-subtitle").textContent = tr("loadingCase");
  document.querySelector("#case-response-refresh").textContent = tr("refresh");
  document.querySelector("#case-response-generate").textContent = tr("generate");
  document.querySelector("#case-response-copy-report").textContent = tr("copyReport");
  document.querySelector("#response-summary-heading").textContent = tr("summaryHeading");
  document.querySelector("#response-containment-heading").textContent = tr("containmentHeading");
  document.querySelector("#response-playbook-heading").textContent = tr("playbookHeading");
  document.querySelector("#response-communication-heading").textContent = tr("communicationHeading");
  document.querySelector("#response-timeline-heading").textContent = tr("timelineHeading");
  document.querySelector("#case-response-agent-open").textContent = tr("agentOpen");
  document.querySelector("#response-agent-kicker").textContent = tr("agentKicker");
  document.querySelector("#response-agent-title").textContent = tr("agentTitle");
  document.querySelector("#response-agent-expand").setAttribute("aria-label", tr("expandAgent"));
  document.querySelector("#response-agent-expand").title = tr("expandAgent");
  document.querySelector("#response-agent-close").setAttribute("aria-label", tr("closeAgent"));
  document.querySelector("#response-agent-close").title = tr("closeAgent");
  document.querySelector("#response-agent-goal-label").textContent = tr("agentGoal");
  document.querySelector("#response-agent-goal").value = tr("agentDefaultGoal");
  document.querySelector("#response-agent-start").textContent = tr("agentStart");
  document.querySelector("#response-agent-rerun").textContent = tr("agentRerun");
  document.querySelector("#response-agent-session-label").textContent = tr("agentSession");
  document.querySelector("#response-agent-plan-title").textContent = tr("agentPlan");
  document.querySelector("#response-agent-trace-title").textContent = tr("agentTrace");
  document.querySelector("#response-agent-report-title").textContent = tr("agentReport");
  document.querySelector("#response-agent-input-label").textContent = tr("agentInput");
  document.querySelector("#response-agent-input-submit").textContent = tr("agentInputSubmit");
  document.querySelector("#response-agent-pause").textContent = tr("agentPause");
  document.querySelector("#response-agent-resume").textContent = tr("agentResume");
  document.querySelector("#response-agent-cancel").textContent = tr("agentCancel");
  document.querySelector("#case-response-overview").setAttribute("aria-label", tr("overviewLabel"));
  document.querySelector("#case-response-timeline-pagination").setAttribute(
    "aria-label",
    tr("timelinePaginationLabel"),
  );
}

function stateTone(value) {
  const state = String(value || "").toLowerCase();
  if ([
    "current", "passed", "verified", "approved", "completed", "success", "benign", "trusted",
    "rolled_back",
  ].includes(state)) return "tone-success";
  if ([
    "review", "stale", "pending", "queued", "running", "retry_wait", "waiting_configuration",
    "waiting_dispatch", "paused", "shadowed", "under_review", "suspicious", "medium",
    "rollback_queued", "rollback_running", "rollback_retry", "cancelled", "waiting_input",
    "synthesizing", "validating",
  ].includes(state)) return "tone-warning";
  if ([
    "blocked", "failed", "rejected", "malicious", "critical", "high", "error", "rollback_failed",
    "budget_exhausted",
  ].includes(state)) return "tone-risk";
  return "tone-neutral";
}

function kindTone(value) {
  const kind = String(value || "");
  if (["analysis", "analysis_replay", "validation"].includes(kind)) return "kind-analysis";
  if (["approval_request", "approval_vote", "approval_decision"].includes(kind)) return "kind-approval";
  if (["response_task", "response_attempt", "response_task_state"].includes(kind)) return "kind-response";
  if (kind === "governance") return "kind-governance";
  return "kind-alert";
}

function fmtConfidence(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "-";
  const percent = number <= 1 ? number * 100 : number;
  return `${Math.round(percent)}%`;
}

function escapeHtml(value) {
  return String(value ?? "-")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function fmtTime(value) {
  const timestamp = Number(value);
  return Number.isFinite(timestamp) && timestamp > 0
    ? new Date(timestamp).toLocaleString(language() === "en" ? "en-US" : "zh-CN", {
      hour12: false,
    })
    : "-";
}

function token() {
  try {
    return sessionStorage.getItem(API_TOKEN_KEY) || "";
  } catch (err) {
    return "";
  }
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (token()) headers.Authorization = `Bearer ${token()}`;
  const response = await fetch(path, { ...options, headers });
  let payload = {};
  try {
    payload = await response.json();
  } catch (err) {
    payload = {};
  }
  if (!response.ok) {
    const error = new Error(payload.error || `${response.status}`);
    error.status = response.status;
    throw error;
  }
  return payload;
}

async function loadSession() {
  const payload = await api("/api/session");
  const roles = Array.isArray(payload.roles) ? payload.roles.map(String) : [];
  canGenerate = roles.includes("analyst");
  const button = document.querySelector("#case-response-generate");
  button.hidden = !canGenerate;
  button.disabled = !canGenerate;
}

function refs(values) {
  const items = [...new Set((values || []).map(String).filter(Boolean))];
  if (!items.length) return "";
  return `<div class="case-response-refs"><span>${escapeHtml(tr("evidence"))}</span>${items.map((item) => `<code>${escapeHtml(item)}</code>`).join("")}</div>`;
}

function factPresentation(fact) {
  const dimension = String(fact?.dimension || "").trim();
  let text = String(fact?.text || "").trim();
  if (dimension) {
    for (const separator of ["：", ":"]) {
      const prefix = `${dimension}${separator}`;
      if (text.startsWith(prefix)) {
        text = text.slice(prefix.length).trim();
        break;
      }
    }
  }
  return {
    label: dimension || tr("eventRecord"),
    text,
  };
}

function list(items, renderItem, empty = tr("empty")) {
  if (!Array.isArray(items) || !items.length) {
    return `<p class="case-response-empty">${escapeHtml(empty)}</p>`;
  }
  return `<div class="case-response-list">${items.map(renderItem).join("")}</div>`;
}

function renderOverview() {
  const container = document.querySelector("#case-response-overview");
  if (!artifact) {
    container.innerHTML = `<p class="case-response-empty">${escapeHtml(tr("notGenerated"))}</p>`;
    return;
  }
  const pack = artifact.content || {};
  const summary = pack.case_summary || {};
  const stale = Boolean(artifact.freshness?.is_stale);
  const validationStatus = String(artifact.validation_status || "-");
  const evidenceBlock = refs(summary.headline_evidence_refs);
  container.innerHTML = `
    <div class="case-response-overview-main">
      <strong>${escapeHtml(summary.headline || caseId)}</strong>
      <span>${escapeHtml(summary.current_assessment || "-")}</span>
    </div>
    <dl>
      <div><dt>${escapeHtml(tr("caseId"))}</dt><dd><code>${escapeHtml(caseId)}</code></dd></div>
      <div><dt>${escapeHtml(tr("version"))}</dt><dd>v${escapeHtml(artifact.version)}</dd></div>
      <div><dt>${escapeHtml(tr("validation"))}</dt><dd><span class="case-response-state ${stateTone(validationStatus)}">${escapeHtml(enumLabel("state", validationStatus))}</span></dd></div>
      <div><dt>${escapeHtml(tr("status"))}</dt><dd><span class="case-response-state ${stateTone(stale ? "stale" : "current")}">${escapeHtml(stale ? tr("stale") : tr("current"))}</span></dd></div>
      <div><dt>${escapeHtml(tr("classification"))}</dt><dd><span class="case-response-state ${stateTone(summary.classification)}">${escapeHtml(enumLabel("state", summary.classification))}</span></dd></div>
      <div><dt>${escapeHtml(tr("confidence"))}</dt><dd>${escapeHtml(fmtConfidence(summary.confidence))}</dd></div>
      <div><dt>${escapeHtml(tr("asOf"))}</dt><dd>${escapeHtml(fmtTime(summary.as_of_ms))}</dd></div>
    </dl>
    ${evidenceBlock ? `<div class="case-response-overview-evidence">${evidenceBlock}</div>` : ""}
  `;
}

function renderSummary() {
  const summary = artifact?.content?.case_summary;
  const container = document.querySelector("#case-response-summary");
  if (!summary) {
    container.innerHTML = `<p class="case-response-empty">${escapeHtml(tr("notGenerated"))}</p>`;
    return;
  }
  const factBlock = list(summary.key_facts, (fact, index) => {
    const presentation = factPresentation(fact);
    return `
      <article class="case-response-fact">
        <div class="case-response-fact-title">
          <span>${String(index + 1).padStart(2, "0")}</span>
          <div>
            <small>
              ${escapeHtml(presentation.label)}
              ${fact.status ? ` · ${escapeHtml(enumLabel("state", fact.status))}` : ""}
            </small>
            <strong>${escapeHtml(presentation.text)}</strong>
          </div>
        </div>
        <span>${escapeHtml(fmtTime(fact.occurred_at_ms))} · ${escapeHtml(timeBasisLabel(fact.time_basis))}</span>
      </article>
    `;
  }, tr("noKnownFacts"));
  const gaps = list(summary.uncertainties, (item, index) => `<div class="case-response-line"><strong>${index + 1}.</strong> ${escapeHtml(item)}</div>`, tr("noUnknowns"));
  const decisions = list(summary.pending_decisions, (item, index) => `<div class="case-response-line"><strong>${index + 1}.</strong> ${escapeHtml(tr("decisionItem", item))}</div>`, tr("noApprovals"));
  container.innerHTML = `
    <div class="case-response-summary-grid">
      <div class="case-response-summary-panel case-response-summary-facts"><span>${escapeHtml(tr("facts"))}</span>${factBlock}</div>
      <div class="case-response-summary-panel case-response-summary-uncertainties"><span>${escapeHtml(tr("uncertainties"))}</span>${gaps}</div>
      <div class="case-response-summary-panel case-response-summary-pending"><span>${escapeHtml(tr("pending"))}</span>${decisions}</div>
    </div>
  `;
}

function renderContainment() {
  const containment = artifact?.content?.containment;
  const options = containment?.options || [];
  const candidate = containment?.fine_grained_candidate;
  document.querySelector("#case-response-containment-state").textContent = containment ? tr("draftOnly") : "";
  const routedOptions = list(options, (item) => {
    const scope = item.scope || {};
    const enforced = scope.enforced || {};
    const context = scope.context_only || {};
    const enforcedText = [enforced.source_ip, enforced.cidr].filter(Boolean).join(" · ");
    const contextText = [context.product, context.host, context.path].filter(Boolean).join(" · ");
    const gateState = item.routing_eligible ? "pending" : "blocked";
    return `
      <article class="case-response-containment-item">
        <div class="case-response-item-heading">
          <div><strong>${escapeHtml(enumLabel("actionType", item.action_type))}</strong><code>${escapeHtml(item.object)}</code></div>
          <span class="case-response-state ${stateTone(gateState)}">${escapeHtml(item.routing_eligible ? tr("approvalRequired") : tr("routingBlocked"))}</span>
        </div>
        <dl>
          <div><dt>${escapeHtml(tr("enforcedScope"))}</dt><dd>${escapeHtml(enforcedText || "-")}</dd></div>
          <div><dt>${escapeHtml(tr("contextOnly"))}</dt><dd>${escapeHtml(contextText || "-")}</dd></div>
          <div><dt>${escapeHtml(tr("duration"))}</dt><dd>${escapeHtml(Math.round(Number(item.duration_seconds || 0) / 60))} ${escapeHtml(tr("minutes"))}</dd></div>
          <div><dt>${escapeHtml(tr("scopeCapability"))}</dt><dd>${escapeHtml(enumLabel("capability", item.required_connector_capability))}</dd></div>
          <div><dt>${escapeHtml(tr("gate"))}</dt><dd>${escapeHtml(item.routing_eligible ? tr("routingEligible") : tr("routingBlocked"))}</dd></div>
          <div><dt>${escapeHtml(tr("boundary"))}</dt><dd>${escapeHtml(item.boundary_note || "-")}</dd></div>
          ${item.rollback ? `<div><dt>${escapeHtml(tr("rollback"))}</dt><dd>${escapeHtml(item.rollback)}</dd></div>` : ""}
        </dl>
        ${refs(item.evidence_refs)}
      </article>
    `;
  });
  const fineGrained = candidate ? `
    <article class="case-response-containment-item capability-blocked">
      <div class="case-response-item-heading">
        <div><strong>${escapeHtml(tr("fineCandidate"))}</strong><code>${escapeHtml(enumLabel("capability", candidate.required_connector_capability))}</code></div>
        <span class="case-response-state tone-risk">${escapeHtml(tr("capabilityBlocked"))}</span>
      </div>
      <dl>
        <div><dt>${escapeHtml(tr("candidateScope"))}</dt><dd>${escapeHtml([candidate.scope?.source_ip, candidate.scope?.host, candidate.scope?.path].filter(Boolean).join(" · ") || "-")}</dd></div>
        <div><dt>${escapeHtml(tr("duration"))}</dt><dd>${escapeHtml(Math.round(Number(candidate.duration_seconds || 0) / 60))} ${escapeHtml(tr("minutes"))}</dd></div>
        <div><dt>${escapeHtml(tr("gate"))}</dt><dd>${escapeHtml(tr("routingBlocked"))}</dd></div>
        <div><dt>${escapeHtml(tr("boundary"))}</dt><dd>${escapeHtml(candidate.blocked_reason || "-")}</dd></div>
      </dl>
      ${refs(candidate.evidence_refs)}
    </article>
  ` : "";
  document.querySelector("#case-response-containment").innerHTML = `${routedOptions}${fineGrained}`;
}

function renderPlaybook() {
  const steps = artifact?.content?.playbook?.steps || [];
  document.querySelector("#case-response-playbook").innerHTML = list(steps, (step, index) => `
    <article class="case-response-playbook-step">
      <span class="case-response-step-index">${String(index + 1).padStart(2, "0")}</span>
      <div>
        <div class="case-response-item-heading">
          <div class="case-response-playbook-title">
            <span class="case-response-stage">${escapeHtml(enumLabel("stage", step.stage))}</span>
            <strong>${escapeHtml(step.action)}</strong>
          </div>
          <span class="case-response-state ${step.mode === "approve_required" ? "tone-warning" : "tone-neutral"}">${escapeHtml(enumLabel("mode", step.mode))}</span>
        </div>
        <dl class="case-response-playbook-details">
          <div><dt>${escapeHtml(tr("rationale"))}</dt><dd>${escapeHtml(step.rationale || "-")}</dd></div>
          <div><dt>${escapeHtml(tr("successCriteria"))}</dt><dd>${escapeHtml(step.success_criteria || "-")}</dd></div>
          ${step.rollback ? `<div><dt>${escapeHtml(tr("rollback"))}</dt><dd>${escapeHtml(step.rollback)}</dd></div>` : ""}
        </dl>
      </div>
    </article>
  `);
}

function communicationList(items, empty, { ordered = false, showTime = false } = {}) {
  if (!Array.isArray(items) || !items.length) {
    return `<p class="case-response-report-empty">${escapeHtml(empty)}</p>`;
  }
  const tag = ordered ? "ol" : "ul";
  return `<${tag} class="case-response-report-list">${items.map((item) => {
    const value = typeof item === "object" && item ? item : { text: item };
    return `
      <li>
        <div>
          <strong>${escapeHtml(value.text || "-")}</strong>
          ${showTime && value.occurred_at_ms ? `<span>${escapeHtml(fmtTime(value.occurred_at_ms))} · ${escapeHtml(timeBasisLabel(value.time_basis))}</span>` : ""}
          ${value.state ? `<span>${escapeHtml(enumLabel("state", value.state))}</span>` : ""}
        </div>
      </li>
    `;
  }).join("")}</${tag}>`;
}

function reportProgressGroup(title, items, empty) {
  return `
    <section class="case-response-report-group">
      <h5>${escapeHtml(title)}</h5>
      ${communicationList(items, empty)}
    </section>
  `;
}

function renderCommunication() {
  const draft = artifact?.content?.incident_communication;
  const summary = artifact?.content?.case_summary || {};
  const copyButton = document.querySelector("#case-response-copy-report");
  document.querySelector("#case-response-communication-state").textContent = draft ? tr("draftOnly") : "";
  copyButton.disabled = !draft || document.querySelector(".case-response-main").getAttribute("aria-busy") === "true";
  const container = document.querySelector("#case-response-communication");
  if (!draft) {
    container.innerHTML = `<p class="case-response-empty">${escapeHtml(tr("notGenerated"))}</p>`;
    return;
  }
  const pendingApprovals = (summary.pending_decisions || []).map((item) => tr("decisionItem", item));
  container.innerHTML = `
    <article class="case-response-report" aria-label="${escapeHtml(tr("reportDraft"))}">
      <header class="case-response-report-header">
        <div class="case-response-report-flags">
          <span class="case-response-state tone-warning">${escapeHtml(tr("draftOnly"))}</span>
          <span>${escapeHtml(enumLabel("audience", draft.audience))}</span>
        </div>
        <h3>${escapeHtml(draft.subject)}</h3>
        <dl class="case-response-report-meta">
          <div><dt>${escapeHtml(tr("caseId"))}</dt><dd><code>${escapeHtml(caseId)}</code></dd></div>
          <div><dt>${escapeHtml(tr("reportPrepared"))}</dt><dd>${escapeHtml(fmtTime(summary.as_of_ms || artifact.created_at_ms))}</dd></div>
          <div><dt>${escapeHtml(tr("reportVersion"))}</dt><dd>v${escapeHtml(artifact.version)}</dd></div>
          <div><dt>${escapeHtml(tr("status"))}</dt><dd>${escapeHtml(enumLabel("state", caseContext.status))}</dd></div>
          <div><dt>${escapeHtml(tr("severity"))}</dt><dd>${escapeHtml(enumLabel("state", summary.severity))}</dd></div>
          <div><dt>${escapeHtml(tr("classification"))}</dt><dd>${escapeHtml(enumLabel("state", summary.classification))} · ${escapeHtml(fmtConfidence(summary.confidence))}</dd></div>
        </dl>
      </header>

      <section class="case-response-report-section">
        <h4>${escapeHtml(tr("incidentOverview"))}</h4>
        <p class="case-response-report-lead">${escapeHtml(draft.situation || "-")}</p>
        <div class="case-response-report-assessment">
          <div><span>${escapeHtml(tr("currentAssessment"))}</span><strong>${escapeHtml(summary.current_assessment || "-")}</strong></div>
          <div>
            <span>${escapeHtml(tr("businessImpact"))}</span>
            <strong>${escapeHtml(draft.business_impact || "-")}</strong>
            <small>${escapeHtml(tr("impactReviewNotice"))}</small>
          </div>
        </div>
      </section>

      <section class="case-response-report-section">
        <h4>${escapeHtml(tr("confirmedFacts"))}</h4>
        ${communicationList(draft.known_facts, tr("noKnownFacts"), { ordered: true, showTime: true })}
      </section>

      <section class="case-response-report-section">
        <h4>${escapeHtml(tr("treatmentProgress"))}</h4>
        <div class="case-response-report-progress">
          ${reportProgressGroup(tr("actionTaken"), draft.actions_taken, tr("noVerifiedActions"))}
          ${reportProgressGroup(tr("actionPending"), draft.actions_pending, tr("noPendingActions"))}
          ${reportProgressGroup(tr("pendingApprovals"), pendingApprovals, tr("noApprovals"))}
          ${reportProgressGroup(tr("simulations"), draft.simulations_not_production_actions, tr("noSimulations"))}
        </div>
      </section>

      <section class="case-response-report-section">
        <h4>${escapeHtml(tr("risksUnknowns"))}</h4>
        <div class="case-response-report-progress">
          ${reportProgressGroup(tr("exceptions"), draft.execution_exceptions, tr("noExceptions"))}
          ${reportProgressGroup(tr("unknowns"), draft.unknowns, tr("noUnknowns"))}
        </div>
      </section>

      <section class="case-response-report-section case-response-report-follow-up">
        <h4>${escapeHtml(tr("followUp"))}</h4>
        <p><strong>${escapeHtml(tr("nextUpdate"))}：</strong>${escapeHtml(draft.next_update_trigger || "-")}</p>
      </section>

      <footer id="case-response-report-boundary" class="case-response-report-notice">${escapeHtml(tr("reportNotice"))}</footer>
    </article>
  `;
}

function reportTextItems(items, empty) {
  if (!Array.isArray(items) || !items.length) return `- ${empty}`;
  return items.map((item) => {
    const value = typeof item === "object" && item ? item : { text: item };
    const state = value.state ? ` (${enumLabel("state", value.state)})` : "";
    return `- ${value.text || "-"}${state}`;
  }).join("\n");
}

function buildCommunicationReportText() {
  const draft = artifact?.content?.incident_communication;
  const summary = artifact?.content?.case_summary || {};
  if (!draft) return "";
  const factLines = Array.isArray(draft.known_facts) && draft.known_facts.length
    ? draft.known_facts.map((item, index) => `${index + 1}. ${item.text || "-"}${item.occurred_at_ms ? ` (${fmtTime(item.occurred_at_ms)})` : ""}`).join("\n")
    : `- ${tr("noKnownFacts")}`;
  const pendingApprovals = (summary.pending_decisions || []).map((item) => tr("decisionItem", item));
  const separator = language() === "en" ? ": " : "：";
  const field = (label, value) => `${label}${separator}${value}`;
  return [
    tr("reportDraft"),
    draft.subject || "-",
    "",
    field(tr("caseId"), caseId),
    field(tr("reportPrepared"), fmtTime(summary.as_of_ms || artifact.created_at_ms)),
    field(tr("reportVersion"), `v${artifact.version}`),
    field(tr("reportAudience"), enumLabel("audience", draft.audience)),
    field(tr("status"), enumLabel("state", caseContext.status)),
    field(tr("severity"), enumLabel("state", summary.severity)),
    field(tr("classification"), `${enumLabel("state", summary.classification)} (${fmtConfidence(summary.confidence)})`),
    "",
    tr("incidentOverview"),
    draft.situation || "-",
    field(tr("currentAssessment"), summary.current_assessment || "-"),
    field(tr("businessImpact"), draft.business_impact || "-"),
    tr("impactReviewNotice"),
    "",
    tr("confirmedFacts"),
    factLines,
    "",
    tr("treatmentProgress"),
    field(tr("actionTaken"), `\n${reportTextItems(draft.actions_taken, tr("noVerifiedActions"))}`),
    field(tr("actionPending"), `\n${reportTextItems(draft.actions_pending, tr("noPendingActions"))}`),
    field(tr("pendingApprovals"), `\n${reportTextItems(pendingApprovals, tr("noApprovals"))}`),
    field(tr("simulations"), `\n${reportTextItems(draft.simulations_not_production_actions, tr("noSimulations"))}`),
    "",
    tr("risksUnknowns"),
    field(tr("exceptions"), `\n${reportTextItems(draft.execution_exceptions, tr("noExceptions"))}`),
    field(tr("unknowns"), `\n${reportTextItems(draft.unknowns, tr("noUnknowns"))}`),
    "",
    tr("followUp"),
    field(tr("nextUpdate"), draft.next_update_trigger || "-"),
    "",
    tr("reportNotice"),
  ].join("\n");
}

async function copyCommunicationReport() {
  const text = buildCommunicationReportText();
  if (!text) return;
  try {
    if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(text);
  } catch (err) {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.className = "case-response-clipboard-buffer";
    document.body.appendChild(textarea);
    textarea.select();
    const copied = document.execCommand("copy");
    textarea.remove();
    if (!copied) {
      setStatus(`${tr("copyFailed")}: ${err.message}`, "error");
      return;
    }
  }
  setStatus(tr("copied"), "success");
}

function timeBasisLabel(value) {
  if (value === "reported") return tr("reportedTime");
  if (value === "ingest_fallback") return tr("fallbackTime");
  return tr("systemTime");
}

function timelineTitle(item) {
  const kind = String(item.kind || "");
  if (["security_event", "analysis"].includes(kind)) return item.title || enumLabel("kind", kind);
  if (kind === "analysis_replay") return enumLabel("kind", kind);
  if (kind === "response_task") {
    const actionType = String(item.title || "").split(":").pop().trim();
    return `${enumLabel("kind", kind)} · ${enumLabel("actionType", actionType)}`;
  }
  if (kind === "governance") {
    const action = String(item.title || "").split(":").pop().trim();
    return `${enumLabel("kind", kind)} · ${enumLabel("governance", action)}`;
  }
  const state = item.state ? ` · ${enumLabel("state", item.state)}` : "";
  return `${enumLabel("kind", kind)}${state}`;
}

function renderTimeline(payload) {
  const items = payload.items || [];
  const pagination = payload.pagination || {};
  const currentPage = Number(pagination.page || timelinePage);
  const totalPages = Number(pagination.total_pages || 1);
  const total = Number(pagination.total || 0);
  timelinePage = currentPage;
  const nextRenderKey = `${payload.timeline_revision || ""}:${currentPage}:${items.map((item) => `${item.entry_id}:${item.state}`).join("|")}`;
  if (nextRenderKey === timelineRenderKey) return;
  timelineRenderKey = nextRenderKey;
  document.querySelector("#case-response-timeline-count").textContent = tr("page", currentPage, totalPages, total);
  document.querySelector("#case-response-timeline").innerHTML = list(items, (item) => `
    <article class="case-response-timeline-entry">
      <span class="case-response-timeline-marker" aria-hidden="true"></span>
      <div>
        <div class="case-response-timeline-head">
          <strong>${escapeHtml(timelineTitle(item))}</strong>
          <div class="case-response-timeline-badges">
            <span class="case-response-kind ${kindTone(item.kind)}">${escapeHtml(enumLabel("kind", item.kind))}</span>
            ${item.state ? `<span class="case-response-state ${stateTone(item.state)}">${escapeHtml(enumLabel("state", item.state))}</span>` : ""}
          </div>
        </div>
        <div class="case-response-time">
          <span><small>${escapeHtml(tr("occurred"))}</small><strong>${escapeHtml(fmtTime(item.occurred_at_ms))}</strong></span>
          <span><small>${escapeHtml(tr("recorded"))}</small><strong>${escapeHtml(fmtTime(item.recorded_at_ms))}</strong></span>
          ${item.actor ? `<span><small>${escapeHtml(tr("actor"))}</small><strong>${escapeHtml(item.actor)}</strong></span>` : ""}
          <span class="case-response-time-basis">${escapeHtml(timeBasisLabel(item.time_basis))}</span>
        </div>
        ${refs(item.evidence_refs)}
      </div>
    </article>
  `);
  const pageLabel = tr("page", currentPage, totalPages, total);
  document.querySelector("#case-response-timeline-pagination").innerHTML = totalPages > 1 ? `
    <button id="case-response-previous" type="button" ${currentPage <= 1 ? "disabled" : ""}>${escapeHtml(tr("previous"))}</button>
    <strong>${escapeHtml(pageLabel)}</strong>
    <button id="case-response-next" type="button" ${currentPage >= totalPages ? "disabled" : ""}>${escapeHtml(tr("next"))}</button>
  ` : "";
  document.querySelector("#case-response-previous")?.addEventListener("click", () => {
    if (document.querySelector(".case-response-main").getAttribute("aria-busy") !== "true") {
      loadTimeline(currentPage - 1, { focusHeading: true });
    }
  });
  document.querySelector("#case-response-next")?.addEventListener("click", () => {
    if (document.querySelector(".case-response-main").getAttribute("aria-busy") !== "true") {
      loadTimeline(currentPage + 1, { focusHeading: true });
    }
  });
}

function renderArtifact() {
  renderOverview();
  renderSummary();
  renderContainment();
  renderPlaybook();
  renderCommunication();
}

function setStatus(message, state = "") {
  const target = document.querySelector("#case-response-status");
  target.textContent = message || "";
  target.dataset.state = state;
}

function setBusy(busy) {
  const generate = document.querySelector("#case-response-generate");
  const refresh = document.querySelector("#case-response-refresh");
  const copyReport = document.querySelector("#case-response-copy-report");
  document.querySelector(".case-response-main").setAttribute("aria-busy", busy ? "true" : "false");
  generate.disabled = busy || !canGenerate;
  refresh.disabled = busy;
  copyReport.disabled = busy || !artifact?.content?.incident_communication;
  generate.textContent = busy ? tr("generating") : tr("generate");
}

async function fetchLatestArtifact(signal) {
  try {
    const payload = await api(`/api/cases/${encodeURIComponent(caseId)}/response-pack/latest`, { signal });
    return payload.artifact || null;
  } catch (err) {
    if (err.status === 404) return null;
    throw err;
  }
}

function fetchTimelinePage(page, signal) {
  return api(`/api/cases/${encodeURIComponent(caseId)}/timeline?${new URLSearchParams({
    limit: String(TIMELINE_PAGE_SIZE),
    offset: String((page - 1) * TIMELINE_PAGE_SIZE),
  })}`, { signal });
}

function timelinePageMustReset(payload, requestedPage) {
  const pagination = payload.pagination || {};
  const totalPages = Math.max(1, Number(pagination.total_pages || 1));
  const revision = String(payload.timeline_revision || "");
  const revisionChanged = Boolean(
    requestedPage > 1 && timelineRevision && revision && revision !== timelineRevision,
  );
  return requestedPage > totalPages || revisionChanged;
}

async function fetchStableTimelinePage(page, signal) {
  const requestedPage = Math.max(1, Number(page) || 1);
  let payload = await fetchTimelinePage(requestedPage, signal);
  if (timelinePageMustReset(payload, requestedPage)) {
    payload = await fetchTimelinePage(1, signal);
  }
  return payload;
}

function applyTimelinePayload(payload) {
  const previousStatus = caseContext.status;
  caseContext = payload.case || {};
  timelineRevision = String(payload.timeline_revision || "");
  renderTimeline(payload);
  document.querySelector("#case-response-subtitle").textContent = `${caseContext.product?.toUpperCase() || "-"} · ${enumLabel("state", caseContext.severity)} · ${enumLabel("state", caseContext.status)} · ${caseId}`;
  if (previousStatus !== caseContext.status && artifact) renderCommunication();
}

async function loadTimeline(page = 1, { focusHeading = false } = {}) {
  const timelineRequestId = ++timelineRequestSequence;
  timelineAbortController?.abort();
  const controller = new AbortController();
  timelineAbortController = controller;
  const timeline = document.querySelector("#case-response-timeline");
  const pagination = document.querySelector("#case-response-timeline-pagination");
  timeline.setAttribute("aria-busy", "true");
  pagination.setAttribute("aria-busy", "true");
  try {
    const payload = await fetchStableTimelinePage(page, controller.signal);
    if (timelineRequestId !== timelineRequestSequence) return;
    applyTimelinePayload(payload);
    if (focusHeading) document.querySelector("#response-timeline-heading").focus();
  } catch (err) {
    if (err.name !== "AbortError" && timelineRequestId === timelineRequestSequence) {
      setStatus(`${tr("loadFailed")}: ${err.message}`, "error");
    }
  } finally {
    if (timelineRequestId === timelineRequestSequence) {
      timelineAbortController = null;
      timeline.setAttribute("aria-busy", "false");
      pagination.setAttribute("aria-busy", "false");
    }
  }
}

async function loadAll() {
  const requestId = ++requestSequence;
  const timelineRequestId = ++timelineRequestSequence;
  latestAbortController?.abort();
  timelineAbortController?.abort();
  const latestController = new AbortController();
  const nextTimelineController = new AbortController();
  latestAbortController = latestController;
  timelineAbortController = nextTimelineController;
  setBusy(true);
  setStatus(tr("loading"));
  try {
    const [nextArtifact, timelinePayload] = await Promise.all([
      fetchLatestArtifact(latestController.signal),
      fetchStableTimelinePage(timelinePage, nextTimelineController.signal),
    ]);
    if (requestId !== requestSequence || timelineRequestId !== timelineRequestSequence) return;
    artifact = nextArtifact;
    caseContext = timelinePayload.case || {};
    renderArtifact();
    applyTimelinePayload(timelinePayload);
    if (!artifact) setStatus(tr("notGenerated"), "empty");
    else if (artifact.freshness?.is_stale) setStatus(tr("stale"), "warning");
    else setStatus("");
  } catch (err) {
    if (requestId !== requestSequence || err.name === "AbortError") return;
    setStatus(`${tr("loadFailed")}: ${err.message}`, "error");
  } finally {
    if (requestId === requestSequence) {
      if (latestAbortController === latestController) latestAbortController = null;
      if (timelineAbortController === nextTimelineController) timelineAbortController = null;
      setBusy(false);
    }
  }
}

async function generate() {
  if (!canGenerate) return;
  requestSequence += 1;
  timelineRequestSequence += 1;
  latestAbortController?.abort();
  timelineAbortController?.abort();
  setBusy(true);
  setStatus(tr("generating"));
  try {
    const payload = await api(`/api/cases/${encodeURIComponent(caseId)}/response-pack/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    artifact = payload.artifact || null;
    renderArtifact();
    setStatus(payload.created ? tr("generated") : tr("reused"), "success");
    await loadTimeline(1);
  } catch (err) {
    setStatus(`${tr("loadFailed")}: ${err.message}`, "error");
  } finally {
    setBusy(false);
  }
}

function setAgentNotice(message, state = "") {
  const notice = document.querySelector("#response-agent-notice");
  notice.textContent = message || "";
  notice.dataset.state = state;
}

function agentEvidenceRefs(values) {
  return (values || []).map((value) => (
    typeof value === "object" ? value?.ref_id : value
  )).map(String).filter(Boolean);
}

function compactAgentRefs(values) {
  const items = [...new Set(agentEvidenceRefs(values))];
  if (!items.length) return "";
  const remaining = items.slice(1);
  const collapsed = remaining.length
    ? `<details class="response-agent-evidence-more">
        <summary>${escapeHtml(tr("agentEvidenceMore", remaining.length))}</summary>
        <div class="response-agent-evidence-more-list">
          ${remaining.map((item) => `<code>${escapeHtml(item)}</code>`).join("")}
        </div>
      </details>`
    : "";
  return `<div class="case-response-refs response-agent-evidence-refs">
    <span>${escapeHtml(tr("evidence"))}</span>
    <code>${escapeHtml(items[0])}</code>
    ${collapsed}
  </div>`;
}

function compactAgentSources(values) {
  const items = (values || [])
    .map((source) => `${source.product || "-"} · ${source.alert_id || "-"}`);
  if (!items.length) return "";
  const remaining = items.slice(1);
  return `<div class="response-agent-source-summary">
    <small>${escapeHtml(tr("agentForensicSources"))}: ${escapeHtml(items[0])}</small>
    ${remaining.length
      ? `<details class="response-agent-evidence-more">
          <summary>${escapeHtml(tr("agentEvidenceMore", remaining.length))}</summary>
          <div class="response-agent-source-more-list">
            ${remaining.map((item) => `<small>${escapeHtml(item)}</small>`).join("")}
          </div>
        </details>`
      : ""}
  </div>`;
}

function renderAgentPlan() {
  const target = document.querySelector("#response-agent-plan");
  const plan = agentSession?.plan || [];
  target.innerHTML = plan.length ? `<div class="response-agent-plan-list">${plan.map((item, index) => `
    <div class="response-agent-plan-row">
      <span class="response-agent-plan-index">${String(index + 1).padStart(2, "0")}</span>
      <strong>${escapeHtml(item.title || item.id)}</strong>
      <span class="case-response-state ${stateTone(item.status)}">${escapeHtml(enumLabel("state", item.status))}</span>
    </div>
  `).join("")}</div>` : `<p class="case-response-empty">${escapeHtml(tr("empty"))}</p>`;
}

function renderAgentTraceStep(step, role, roleLabel) {
  const detail = step.detail || {};
  const summary = detail.summary || detail.question || detail.message || "";
  const liveAttributes = ["latest", "only"].includes(role)
    ? ' aria-live="polite" aria-atomic="true"'
    : "";
  return `
    <article
      class="response-agent-trace-row response-agent-trace-row-${escapeHtml(role)}"
      data-sequence="${Number(step.sequence || 0)}"
      ${liveAttributes}
    >
      <div class="response-agent-trace-row-head">
        ${roleLabel ? `<span class="response-agent-trace-role">${escapeHtml(roleLabel)}</span>` : ""}
        <span class="response-agent-trace-time">${String(Number(step.sequence || 0)).padStart(2, "0")} · ${escapeHtml(fmtTime(step.created_at_ms))}</span>
      </div>
      <strong>${escapeHtml(step.title || step.phase)}</strong>
      ${step.rationale ? `<p>${escapeHtml(step.rationale)}</p>` : ""}
      ${summary ? `<p>${escapeHtml(summary)}</p>` : ""}
      ${compactAgentRefs(step.evidence_refs)}
    </article>
  `;
}

function renderAgentTrace() {
  const target = document.querySelector("#response-agent-trace");
  document.querySelector("#response-agent-trace-count").textContent = tr(
    "agentTraceCount",
    agentSteps.length,
  );
  if (!agentSteps.length) {
    target.innerHTML = `<p class="case-response-empty">${escapeHtml(tr("empty"))}</p>`;
    setAgentTraceExpanded(agentTraceExpanded);
    return;
  }

  const first = agentSteps[0];
  const latest = agentSteps[agentSteps.length - 1];
  const middle = agentSteps.slice(1, -1);
  const firstRole = agentSteps.length === 1 ? "only" : "first";
  const firstLabel = tr(agentSteps.length === 1 ? "agentTraceOnly" : "agentTraceFirst");
  const middleMarkup = middle.length ? `
    <details class="response-agent-trace-middle" ${agentTraceMiddleExpanded ? "open" : ""}>
      <summary>
        <span class="response-agent-trace-middle-chevron" aria-hidden="true"></span>
        <span>${escapeHtml(tr("agentTraceMiddle", middle.length))}</span>
      </summary>
      <div class="response-agent-trace-middle-list">
        ${middle.map((step) => renderAgentTraceStep(step, "middle", "")).join("")}
      </div>
    </details>
  ` : "";
  target.innerHTML = `
    <div class="response-agent-trace-list">
      ${renderAgentTraceStep(first, firstRole, firstLabel)}
      ${middleMarkup}
      ${agentSteps.length > 1 ? renderAgentTraceStep(latest, "latest", tr("agentTraceLatest")) : ""}
    </div>
  `;
  const middleDetails = target.querySelector(".response-agent-trace-middle");
  middleDetails?.addEventListener("toggle", () => {
    agentTraceMiddleExpanded = middleDetails.open;
  });
  setAgentTraceExpanded(agentTraceExpanded);
}

function setAgentTraceExpanded(expanded) {
  const toggle = document.querySelector("#response-agent-trace-toggle");
  const target = document.querySelector("#response-agent-trace");
  agentTraceExpanded = Boolean(expanded);
  toggle.setAttribute("aria-expanded", String(agentTraceExpanded));
  const label = tr(agentTraceExpanded ? "agentTraceHide" : "agentTraceShow");
  toggle.setAttribute("aria-label", label);
  toggle.title = label;
  target.hidden = !agentTraceExpanded;
}

function reportItems(items, renderItem, emptyText, sectionNumber) {
  if (!Array.isArray(items) || !items.length) {
    return `<p class="case-response-empty">${escapeHtml(emptyText)}</p>`;
  }
  return `<ol class="response-agent-report-list">${items.map((item, index) => `
    <li>
      <span class="response-agent-report-item-number" aria-hidden="true">${sectionNumber}.${index + 1}</span>
      <div class="response-agent-report-item-content">${renderItem(item, index)}</div>
    </li>
  `).join("")}</ol>`;
}

function agentDetailList(label, values) {
  const items = (values || []).filter(Boolean);
  if (!items.length) return "";
  return `<div class="response-agent-investigation-detail">
    <strong>${escapeHtml(label)}</strong>
    <ol class="response-agent-report-sublist">
      ${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
    </ol>
  </div>`;
}

function agentReportSection(number, title, body, extraClass = "") {
  return `
    <section class="response-agent-report-section ${escapeHtml(extraClass)}">
      <div class="response-agent-report-section-heading">
        <span class="response-agent-report-section-number" aria-hidden="true">${number}</span>
        <h4>${escapeHtml(title)}</h4>
      </div>
      <div class="response-agent-report-section-content">${body}</div>
    </section>
  `;
}

function renderAgentReport() {
  const band = document.querySelector("#response-agent-report-band");
  const target = document.querySelector("#response-agent-report");
  const report = agentSession?.report;
  if (!report?.content) {
    band.hidden = true;
    target.innerHTML = "";
    return;
  }
  band.hidden = false;
  const content = report.content;
  const conclusion = content.conclusion || {};
  const risk = content.risk_assessment || {};
  const correlation = content.cross_source_correlation || {};
  const scope = content.scope_assessment || {};
  const validation = report.validation || {};
  target.innerHTML = `
    <article class="response-agent-report">
      ${agentReportSection(1, tr("agentExecutiveSummary"), `
        <h5 class="response-agent-report-document-title">${escapeHtml(content.title || tr("agentReport"))}</h5>
        <p>${escapeHtml(content.executive_summary || "-")}</p>
      `)}
      ${agentReportSection(2, tr("agentRiskAssessment"), `
        <p><strong>${escapeHtml(enumLabel("state", conclusion.classification))} · ${escapeHtml(fmtConfidence(conclusion.confidence))}</strong></p>
        <p>${escapeHtml(conclusion.statement || "-")}</p>
        ${risk.risk_level ? `<div class="response-agent-risk-grid">
          <small><strong>${escapeHtml(tr("agentRiskLevel"))}</strong>${escapeHtml(enumLabel("state", risk.risk_level))}</small>
          <small><strong>${escapeHtml(tr("agentAttackStatus"))}</strong>${escapeHtml(enumLabel("attackStatus", risk.attack_status))}</small>
          <small><strong>${escapeHtml(tr("agentLikelihood"))}</strong>${escapeHtml(enumLabel("likelihood", risk.likelihood))}</small>
          <small><strong>${escapeHtml(tr("agentImpactLevel"))}</strong>${escapeHtml(enumLabel("state", risk.impact))}</small>
        </div>` : ""}
        ${risk.rationale ? `<p>${escapeHtml(risk.rationale)}</p>` : ""}
        ${agentDetailList(tr("agentAggravatingFactors"), risk.aggravating_factors)}
        ${agentDetailList(tr("agentMitigatingFactors"), risk.mitigating_factors)}
        ${compactAgentRefs(risk.evidence_refs)}
      `, "response-agent-report-conclusion")}
      ${agentReportSection(3, tr("agentAttackChain"), reportItems(
        content.attack_chain,
        (item) => `
            <strong>${escapeHtml(item.timestamp || item.stage || "-")}</strong>
            ${item.timestamp && item.stage ? `<small>${escapeHtml(item.stage)}</small>` : ""}
            <p>${escapeHtml(item.statement || "-")}</p>
            ${item.assessment ? `<small>${escapeHtml(item.assessment)}</small>` : ""}
            ${compactAgentRefs(item.evidence_refs)}
        `,
        tr("agentEmptyFindings"),
        3,
      ))}
      ${agentReportSection(4, tr("agentFindings"), reportItems(
        content.findings,
        (item) => `
            ${item.title ? `<strong>${escapeHtml(item.title)}</strong>` : ""}
            <p>${escapeHtml(item.statement || "-")}</p>
            <small>${escapeHtml(enumLabel("claimState", item.claim_state))}${item.severity ? ` · ${escapeHtml(enumLabel("state", item.severity))}` : ""}</small>
            ${item.significance ? `<small>${escapeHtml(item.significance)}</small>` : ""}
            ${compactAgentRefs(item.evidence_refs)}
        `,
        tr("agentEmptyFindings"),
        4,
      ))}
      ${agentReportSection(5, tr("agentRelatedActivity"), reportItems(
        content.related_activity,
        (item) => `
            <strong>${escapeHtml(item.timestamp || item.alert_id || "-")}</strong>
            <small>${escapeHtml([item.product, item.severity, item.alert_id].filter(Boolean).join(" · "))}</small>
            <p>${escapeHtml(item.activity || "-")}</p>
            ${(item.source || item.target) ? `<small>${escapeHtml(tr("agentSource"))}: ${escapeHtml(item.source || "-")} · ${escapeHtml(tr("agentTarget"))}: ${escapeHtml(item.target || "-")}</small>` : ""}
            ${item.relationship ? `<small><strong>${escapeHtml(tr("agentRelationship"))}</strong> ${escapeHtml(item.relationship)}</small>` : ""}
            ${item.assessment ? `<small>${escapeHtml(item.assessment)}</small>` : ""}
            ${compactAgentRefs(item.evidence_refs)}
        `,
        tr("agentEmptyFindings"),
        5,
      ))}
      ${agentReportSection(6, tr("agentHypotheses"), reportItems(
        content.hypothesis_assessment,
        (item) => `
            <strong>${escapeHtml(item.title || item.hypothesis_id || "-")}</strong>
            <small>${escapeHtml(enumLabel("hypothesisDisposition", item.disposition))} · ${escapeHtml(fmtConfidence(item.confidence))}</small>
            <p>${escapeHtml(item.rationale || "-")}</p>
            ${agentDetailList(tr("agentHypothesisMissing"), item.missing_evidence)}
            ${(item.supporting_evidence_refs || []).length
              ? `<small><strong>${escapeHtml(tr("agentHypothesisSupport"))}</strong></small>${compactAgentRefs(item.supporting_evidence_refs)}`
              : ""}
            ${(item.contradicting_evidence_refs || []).length
              ? `<small><strong>${escapeHtml(tr("agentHypothesisAgainst"))}</strong></small>${compactAgentRefs(item.contradicting_evidence_refs)}`
              : ""}
        `,
        tr("agentEmptyFindings"),
        6,
      ))}
      ${agentReportSection(7, tr("agentScope"), `
        <p>${escapeHtml(scope.blast_radius_assessment || "-")}</p>
        <p><strong>${escapeHtml(tr("agentImpact"))}</strong></p>
        <p>${escapeHtml(content.impact || "-")}</p>
        ${agentDetailList(
          tr("agentObservedEntities"),
          (scope.observed_entities || []).map((item) => `${item.type || "-"}: ${item.value || "-"}`),
        )}
        ${agentDetailList(tr("agentCoveredDomains"), scope.evidence_covered_domains)}
        ${agentDetailList(tr("agentUnresolvedDomains"), scope.unresolved_domains)}
        ${compactAgentRefs(scope.evidence_refs)}
      `)}
      ${agentReportSection(8, tr("agentResponsePlan"), reportItems(
        content.response_plan,
        (item) => `
            <strong>${escapeHtml(item.action || "-")}</strong>
            <small>${escapeHtml(enumLabel("mode", item.mode))} · ${escapeHtml(item.stage || "-")}</small>
            ${item.rationale ? `<small>${escapeHtml(item.rationale)}</small>` : ""}
            ${compactAgentRefs(item.evidence_refs)}
        `,
        tr("agentEmptyPlan"),
        8,
      ))}
      ${agentReportSection(9, tr("agentGaps"), reportItems(
        content.evidence_gaps,
        (item) => `<p>${escapeHtml(item)}</p>`,
        tr("agentEmptyGaps"),
        9,
      ))}
      ${agentReportSection(10, tr("agentTechnicalAppendix"), `
        <details class="response-agent-technical-appendix">
          <summary>${escapeHtml(tr("agentTechnicalAppendixOpen"))}</summary>
          <div class="response-agent-technical-appendix-content">
            <div class="response-agent-technical-block">
              <strong>${escapeHtml(tr("agentCorrelation"))}</strong>
              <p>${escapeHtml(correlation.summary || "-")}</p>
              <small>${escapeHtml(enumLabel("correlationStrength", correlation.strength))}</small>
              ${agentDetailList(
                tr("agentCorrelationPivots"),
                (correlation.correlation_pivots || []).map((item) => `${item.field || "-"}: ${item.value || "-"}`),
              )}
            </div>
            ${reportItems(
              content.forensic_workstreams,
              (item) => {
                const result = item.investigation_result || {};
                return `
                    <strong>${escapeHtml(item.title || item.workstream_id || "-")}</strong>
                    <small>${escapeHtml(enumLabel("state", item.status))} · ${escapeHtml(item.coverage_summary || "-")}</small>
                    <small>${escapeHtml(enumLabel("forensicConclusion", result.conclusion_state))}</small>
                    ${compactAgentSources(item.evidence_sources)}
                    ${result.assessment ? `<div class="response-agent-investigation-detail"><strong>${escapeHtml(tr("agentForensicAssessment"))}</strong><small>${escapeHtml(result.assessment)}</small></div>` : ""}
                    ${agentDetailList(tr("agentForensicObservations"), result.observations)}
                    ${agentDetailList(tr("agentAlternativeExplanations"), result.alternative_explanations)}
                    ${agentDetailList(tr("agentNextPivots"), result.next_pivots)}
                    ${agentDetailList(tr("agentCollectionSteps"), item.collection_steps)}
                    ${compactAgentRefs(item.evidence_refs)}
                `;
              },
              tr("agentEmptyForensics"),
              10,
            )}
          </div>
        </details>
      `)}
      ${agentReportSection(11, tr("agentFinalAssessment"), `
        <p>${escapeHtml(content.final_assessment || "-")}</p>
        <p><strong>${escapeHtml(tr("agentGate"))}</strong> <span class="case-response-state ${stateTone(report.validation_status)}">${escapeHtml(enumLabel("state", report.validation_status))}</span></p>
        ${(validation.warnings || []).length ? `<small>${escapeHtml(validation.warnings.join(" · "))}</small>` : ""}
      `)}
    </article>
  `;
}

function renderAgentSession() {
  const startPanel = document.querySelector("#response-agent-start-panel");
  const sessionPanel = document.querySelector("#response-agent-session-panel");
  const controls = document.querySelector("#response-agent-controls");
  const startButton = document.querySelector("#response-agent-start");
  const goal = document.querySelector("#response-agent-goal");
  if (!agentSession) {
    startPanel.hidden = false;
    sessionPanel.hidden = true;
    controls.hidden = true;
    startButton.hidden = !canGenerate;
    goal.disabled = !canGenerate;
    renderAgentReport();
    return;
  }

  startPanel.hidden = true;
  sessionPanel.hidden = false;
  document.querySelector("#response-agent-session-id").textContent = agentSession.session_id || "-";
  const status = document.querySelector("#response-agent-status");
  status.textContent = enumLabel("state", agentSession.status);
  status.className = `case-response-state ${stateTone(agentSession.status)}`;
  const usage = agentSession.usage || {};
  const budget = agentSession.budget || {};
  document.querySelector("#response-agent-metrics").innerHTML = `
    <div><dt>${escapeHtml(tr("agentTurns"))}</dt><dd>${Number(usage.turns || 0)} / ${Number(budget.max_turns || 0)}</dd></div>
    <div><dt>${escapeHtml(tr("agentTools"))}</dt><dd>${Number(usage.tool_calls || 0)} / ${Number(budget.max_tool_calls || 0)}</dd></div>
    <div><dt>${escapeHtml(tr("agentElapsed"))}</dt><dd>${formatAgentElapsed(agentSession.elapsed_seconds)}</dd></div>
  `;
  renderAgentPlan();
  renderAgentTrace();
  renderAgentReport();

  const active = AGENT_ACTIVE_STATUSES.has(agentSession.status);
  const rerunnable = AGENT_TERMINAL_STATUSES.has(agentSession.status);
  controls.hidden = !canGenerate || (!active && !rerunnable);
  document.querySelector("#response-agent-pause").hidden = ![
    "queued", "running", "synthesizing", "validating",
  ].includes(agentSession.status);
  document.querySelector("#response-agent-resume").hidden = agentSession.status !== "paused";
  document.querySelector("#response-agent-cancel").hidden = !active;
  document.querySelector("#response-agent-rerun").hidden = !(
    canGenerate && rerunnable
  );
  document.querySelector("#response-agent-input-form").hidden = !(
    canGenerate && agentSession.status === "waiting_input"
  );

  if (agentSession.freshness?.is_stale) {
    setAgentNotice(tr("agentStale"), "warning");
  } else if (agentSession.status === "waiting_input") {
    setAgentNotice(tr("agentWaitingInput"), "warning");
  } else if (agentSession.last_error) {
    setAgentNotice(agentSession.last_error, agentSession.status === "failed" ? "error" : "warning");
  } else if (["completed", "review", "blocked"].includes(agentSession.status)) {
    setAgentNotice(`${tr("agentGate")}: ${enumLabel("state", agentSession.report?.validation_status || agentSession.status)}`, agentSession.status === "completed" ? "success" : "warning");
  } else {
    setAgentNotice(tr("agentReadOnly"));
  }
}

function formatAgentElapsed(seconds) {
  const value = Number(seconds);
  const unit = escapeHtml(tr("agentSeconds"));
  if (!Number.isFinite(value) || value <= 0) return `0 ${unit}`;
  if (value < 1) return `&lt;1 ${unit}`;
  return `${Math.max(1, Math.round(value))} ${unit}`;
}

function mergeAgentSession(next, replaceSteps = false) {
  const previousSessionId = agentSession?.session_id || "";
  const previousStatus = agentSession?.status || "";
  if (previousSessionId !== next.session_id) {
    agentTraceExpanded = !AGENT_TERMINAL_STATUSES.has(next.status);
    agentTraceMiddleExpanded = false;
  } else if (
    !AGENT_TERMINAL_STATUSES.has(previousStatus)
    && AGENT_TERMINAL_STATUSES.has(next.status)
  ) {
    agentTraceExpanded = false;
    agentTraceMiddleExpanded = false;
  }
  const incoming = Array.isArray(next.steps) ? next.steps : [];
  if (replaceSteps || !agentSession || agentSession.session_id !== next.session_id) {
    agentSteps = incoming;
  } else {
    const byId = new Map(agentSteps.map((step) => [step.step_id, step]));
    incoming.forEach((step) => byId.set(step.step_id, step));
    agentSteps = [...byId.values()].sort((left, right) => Number(left.sequence) - Number(right.sequence));
  }
  agentAfterSequence = agentSteps.reduce(
    (maximum, step) => Math.max(maximum, Number(step.sequence || 0)),
    0,
  );
  agentSession = { ...next, steps: agentSteps };
  renderAgentSession();
}

function stopAgentPolling() {
  if (agentPollTimer) window.clearTimeout(agentPollTimer);
  agentPollTimer = null;
}

function scheduleAgentPolling() {
  stopAgentPolling();
  if (!agentDrawerOpen || !agentSession || !AGENT_POLL_STATUSES.has(agentSession.status)) return;
  agentPollTimer = window.setTimeout(() => refreshAgentSession({ incremental: true }), AGENT_POLL_INTERVAL_MS);
}

async function refreshAgentSession({ incremental = false } = {}) {
  if (!agentDrawerOpen) return;
  const requestId = ++agentRequestSequence;
  agentAbortController?.abort();
  const controller = new AbortController();
  agentAbortController = controller;
  try {
    let payload;
    if (incremental && agentSession?.session_id) {
      payload = await api(`/api/response-agent/sessions/${encodeURIComponent(agentSession.session_id)}?after_sequence=${agentAfterSequence}`, {
        signal: controller.signal,
      });
    } else {
      payload = await api(`/api/cases/${encodeURIComponent(caseId)}/response-agent/latest`, {
        signal: controller.signal,
      });
    }
    if (requestId !== agentRequestSequence) return;
    mergeAgentSession(payload.session, !incremental);
  } catch (err) {
    if (err.name === "AbortError" || requestId !== agentRequestSequence) return;
    if (err.status === 404 && !incremental) {
      agentSession = null;
      agentSteps = [];
      agentAfterSequence = 0;
      agentTraceExpanded = true;
      agentTraceMiddleExpanded = false;
      renderAgentSession();
      setAgentNotice(tr("agentNoSession"));
    } else {
      setAgentNotice(`${tr("agentCommandFailed")}: ${err.message}`, "error");
    }
  } finally {
    if (requestId === agentRequestSequence) {
      agentAbortController = null;
      scheduleAgentPolling();
    }
  }
}

async function openResponseAgent() {
  const drawer = document.querySelector("#response-agent-drawer");
  const backdrop = document.querySelector("#response-agent-backdrop");
  agentDrawerOpen = true;
  setResponseAgentExpanded(false);
  drawer.hidden = false;
  backdrop.hidden = false;
  drawer.setAttribute("aria-hidden", "false");
  document.body.classList.add("response-agent-open");
  setAgentNotice(tr("agentLoading"));
  drawer.querySelector("#response-agent-close").focus();
  await refreshAgentSession();
}

function setResponseAgentExpanded(expanded) {
  const drawer = document.querySelector("#response-agent-drawer");
  const button = document.querySelector("#response-agent-expand");
  const expandIcon = button.querySelector(".response-agent-expand-icon-expand");
  const collapseIcon = button.querySelector(".response-agent-expand-icon-collapse");
  const label = tr(expanded ? "collapseAgent" : "expandAgent");
  drawer.classList.toggle("is-expanded", expanded);
  button.dataset.action = expanded ? "collapse" : "expand";
  button.setAttribute("aria-expanded", String(expanded));
  button.setAttribute("aria-pressed", String(expanded));
  button.setAttribute("aria-label", label);
  button.title = label;
  expandIcon.hidden = expanded;
  collapseIcon.hidden = !expanded;
}

function closeResponseAgent() {
  agentDrawerOpen = false;
  stopAgentPolling();
  agentAbortController?.abort();
  document.querySelector("#response-agent-drawer").hidden = true;
  document.querySelector("#response-agent-drawer").setAttribute("aria-hidden", "true");
  document.querySelector("#response-agent-backdrop").hidden = true;
  document.body.classList.remove("response-agent-open");
  document.querySelector("#case-response-agent-open").focus();
}

async function startResponseAgent({ rerun = false } = {}) {
  if (!canGenerate) return;
  const button = document.querySelector(
    rerun ? "#response-agent-rerun" : "#response-agent-start",
  );
  const goal = rerun
    ? (agentSession?.goal || document.querySelector("#response-agent-goal").value)
    : document.querySelector("#response-agent-goal").value;
  button.disabled = true;
  button.textContent = tr(rerun ? "agentRerunning" : "agentStarting");
  setAgentNotice(tr(rerun ? "agentRerunning" : "agentStarting"));
  try {
    const payload = await api(`/api/cases/${encodeURIComponent(caseId)}/response-agent/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ goal, language: language() }),
    });
    mergeAgentSession(payload.session, true);
    await loadAll();
    scheduleAgentPolling();
  } catch (err) {
    setAgentNotice(`${tr("agentCommandFailed")}: ${err.message}`, "error");
  } finally {
    button.disabled = false;
    button.textContent = tr(rerun ? "agentRerun" : "agentStart");
  }
}

async function agentCommand(command, body = {}) {
  if (!canGenerate || !agentSession?.session_id) return;
  stopAgentPolling();
  try {
    const payload = await api(`/api/response-agent/sessions/${encodeURIComponent(agentSession.session_id)}/${command}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    mergeAgentSession(payload.session);
  } catch (err) {
    setAgentNotice(`${tr("agentCommandFailed")}: ${err.message}`, "error");
  } finally {
    scheduleAgentPolling();
  }
}

function returnToCase(section) {
  const params = new URLSearchParams({
    case_id: caseId,
    case_section: section === "history" ? "history" : "pending",
  });
  window.location.replace(`/?${params.toString()}`);
}

function initialize() {
  const params = new URLSearchParams(window.location.search);
  caseId = params.get("case_id") || "";
  const returnSection = params.get("return_section") === "history" ? "history" : "pending";
  document.documentElement.lang = language() === "en" ? "en" : "zh-CN";
  applyLocalizedStaticText();
  if (!caseId) {
    setStatus(`${tr("loadFailed")}: Case ID`, "error");
    setBusy(true);
    return;
  }
  document.title = `${tr("workbenchTitle")} · ${caseId}`;
  document.querySelector("#case-response-back").addEventListener("click", () => {
    returnToCase(returnSection);
  });
  document.querySelector("#case-response-refresh").addEventListener("click", () => loadAll());
  document.querySelector("#case-response-generate").addEventListener("click", generate);
  document.querySelector("#case-response-copy-report").addEventListener("click", copyCommunicationReport);
  document.querySelector("#case-response-agent-open").addEventListener("click", openResponseAgent);
  document.querySelector("#response-agent-expand").addEventListener("click", () => {
    const drawer = document.querySelector("#response-agent-drawer");
    setResponseAgentExpanded(!drawer.classList.contains("is-expanded"));
  });
  document.querySelector("#response-agent-close").addEventListener("click", closeResponseAgent);
  document.querySelector("#response-agent-backdrop").addEventListener("click", closeResponseAgent);
  document.querySelector("#response-agent-start").addEventListener("click", startResponseAgent);
  document.querySelector("#response-agent-rerun").addEventListener("click", () => {
    startResponseAgent({ rerun: true });
  });
  document.querySelector("#response-agent-trace-toggle").addEventListener("click", () => {
    setAgentTraceExpanded(!agentTraceExpanded);
  });
  document.querySelector("#response-agent-pause").addEventListener("click", () => agentCommand("pause"));
  document.querySelector("#response-agent-resume").addEventListener("click", () => agentCommand("resume"));
  document.querySelector("#response-agent-cancel").addEventListener("click", () => agentCommand("cancel"));
  document.querySelector("#response-agent-input-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = document.querySelector("#response-agent-input");
    const message = input.value.trim();
    if (!message) return;
    await agentCommand("input", { message });
    input.value = "";
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && agentDrawerOpen) closeResponseAgent();
  });
  loadSession()
    .catch(() => {
      canGenerate = false;
      const button = document.querySelector("#case-response-generate");
      button.hidden = true;
      button.disabled = true;
    })
    .finally(() => loadAll());
}

initialize();
