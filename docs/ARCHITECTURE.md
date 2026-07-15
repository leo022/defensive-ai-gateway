# Defensive AI Gateway — 完整架构图

```mermaid
flowchart TB
    %% ═══════════════════════════════════════════════════════════════
    %% 1) 告警输入层 — 三大入口
    %% ═══════════════════════════════════════════════════════════════

    subgraph INPUT["🔔 告警输入层"]
        direction LR
        WAF_DEV["WAF 设备<br/>JSON/Syslog"]
        HIPS_DEV["HIPS 设备<br/>JSON/Syslog"]
        NDR_DEV["NDR 设备<br/>JSON/Syslog"]
        RASP_DEV["RASP 设备<br/>JSON/Syslog"]
        SIEM_DEV["SIEM 平台<br/>JSON/Syslog"]
        DEMO["Demo 样本<br/>sample_alerts.py"]
    end

    %% ═══════════════════════════════════════════════════════════════
    %% 2) 传输与路由层
    %% ═══════════════════════════════════════════════════════════════

    subgraph TRANSPORT["📡 传输层 (app.py / syslog_receiver.py)"]
        direction TB

        subgraph SYSLOG["Syslog TCP/UDP 接收器"]
            SRM["SyslogReceiverManager<br/>per-product listener<br/>15140 WAF · 15141 HIPS<br/>15142 NDR · 15143 RASP<br/>15144 SIEM"]
        end

        subgraph HTTP["HTTP REST API"]
            HTTP_HANDLER["GatewayHandler<br/>POST /api/alerts<br/>GET /api/health ..."]
        end
    end

    subgraph ROUTE["🔀 路由 & 识别层 (syslog_router.py / app.py:alert_from_payload)"]
        direction TB
        SPR["SyslogPortRouter<br/>port → product 映射<br/>+ Syslog 报文 JSON 解析"]
        AFP["alert_from_payload()<br/>1. 显式 profile=? 参数 → LogAdapter<br/>2. 显式 product 字段 → 快速路径<br/>3. fingerprint_product() 指纹识别<br/>4. 标准告警启发式 → 兜底 siem"]
    end

    %% ═══════════════════════════════════════════════════════════════
    %% 3) 日志适配层
    %% ═══════════════════════════════════════════════════════════════

    subgraph ADAPTER["🔄 日志适配层 (log_adapter.py)"]
        direction TB
        LA["LogAdapter"]
        MP["MappingProfile<br/>JSONPath 映射规则<br/>$.rule.id → rule_id<br/>$.items[0].attack_type → event_type<br/>transform: rasp_sink_from_stacktrace …"]
        INFER["infer_mapping_profile()<br/>自动字段识别<br/>+ 候选路径排序"]
        DRY["dry_run()<br/>映射预览 / 验证"]
        AUTO["AUTO_PROFILE<br/>指纹命中 → 自动套用<br/>如 cloudrasp → auto-rasp-json"]
    end

    %% ═══════════════════════════════════════════════════════════════
    %% 4) 异步处理队列
    %% ═══════════════════════════════════════════════════════════════

    subgraph QUEUE["⚙️ 持久接入队列 (database.py / processing.py)"]
        direction LR
        INBOX["durable_alert_inbox<br/>返回 202 前提交<br/>pending · retry · processing<br/>completed · dead_letter"]
        AP["AlertProcessor<br/>bounded execution queue<br/>worker pool<br/>bounded shutdown"]
        STATS["Operational Stats<br/>queued / processed / retried<br/>dead_lettered / rejected / inflight"]
        INBOX --> AP --> STATS
    end

    %% ═══════════════════════════════════════════════════════════════
    %% 5) 核心编排引擎
    %% ═══════════════════════════════════════════════════════════════

    subgraph ORCH["🧠 Orchestrator (orchestrator.py)"]
        direction TB
        O["Orchestrator.handle_alert(alert)"]
        step1["① EventNormalizer.normalize(alert) → NormalizedEvent"]
        step2["② 原子事务写入: audit_log + raw_alerts + normalized_events"]
        step3["③ 按实体 + 1h 时间窗解析 Case<br/>终态 Case 自动滚动新建"]
        step4["④ build_agent(product, llm, policy)→SecurityAgent"]
        step5["⑤ 加载分层记忆 + 确定性相似度<br/>+ 15m 跨产品实体关联"]
        step6["⑥ agent.analyze(case_id, event, memory_context)→AgentResult"]
        step7["⑦ Validator 门禁后原子提交<br/>Case + Run + Match + Approval + Audit<br/>非 passed 禁止写可消费记忆"]
        step8["⑧ LLM 失败降级: LocalHeuristicLLM fallback"]
        O --> step1 --> step2 --> step3 --> step4 --> step5 --> step6 --> step7
        O -.-> step8
    end

    %% ═══════════════════════════════════════════════════════════════
    %% 6) Agent 层 — 五个产品专用 Agent
    %% ═══════════════════════════════════════════════════════════════

    subgraph AGENTS["🤖 Agent 层 (agents/)"]
        direction TB
        BASE["SecurityAgent (ABC) 基类<br/>┣ system_prompt() — 产品专用系统提示词<br/>┣ analysis_focus() — 分析关注点<br/>┣ report_outline() — 报告结构<br/>┣ _build_prompt() — 构建完整 prompt<br/>┣ _ensure_explainable_result() — LLM 结果调和<br/>┗ _reconcile_model_result() — 模型输出校验"]

        subgraph CONCRETE["5 个产品 Agent"]
            RA["RaspAgent<br/>SQL注入·JNDI·命令执行<br/>→ system_prompt_rasp()"]
            WA["WafAgent<br/>SQLi·XSS·路径穿越·协议异常<br/>→ system_prompt_waf()"]
            HA["HipsAgent<br/>进程链·凭证访问·横向移动<br/>→ system_prompt_hips()"]
            NA["NdrAgent<br/>C2 beacon·外传·TLS指纹<br/>→ system_prompt_ndr()"]
            SA["SiemAgent<br/>多源关联·攻击链·时间线<br/>→ system_prompt_siem()"]
        end

        REG["registry.py<br/>build_agent(product) → agent<br/>AGENT_TYPES map<br/>未知 product → SiemAgent 兜底"]

        EVID["evidence_helpers.py<br/>fact() / join_facts()<br/>normalize_classification()<br/>short_text() / strip_terminal()"]
    end

    BASE --> CONCRETE
    REG --> CONCRETE

    %% ═══════════════════════════════════════════════════════════════
    %% 7) LLM 后端层 — 三套后端
    %% ═══════════════════════════════════════════════════════════════

    subgraph LLM["🌐 LLM 后端 (llm.py / policy.py)"]
        direction TB

        subgraph LLM_BACKENDS["LLMClient 抽象 → 3 个后端"]
            LOCAL["LocalHeuristicLLM<br/>确定性规则分析器<br/>仅对当前告警做关键词评分<br/>+ 样本 evidence_assessment 解析<br/>is_deterministic = True"]
            OLLAMA["OllamaLLM<br/>仅回环地址<br/>JSON Schema 约束输出<br/>响应上限 · 重试 · 熔断<br/>禁止 HTTP 重定向"]
            GW_LLM["GatewayLLM<br/>HTTPS + host allowlist<br/>JSON-over-HTTP 适配<br/>响应上限 · 重试 · 熔断<br/>模型来源写入每次 Run"]
        end

        PE["PolicyEngine<br/>← 上下文必经的单一掐点<br/>┣ redact() — 敏感字段/模式脱敏<br/>┣ sanitize_context() — 大小裁剪 + 脱敏<br/>┣ truncate_prompt_payload() — Prompt 截断<br/>┗ action_mode() — 只读/审批/自动 模式判定"]
    end

    %% ═══════════════════════════════════════════════════════════════
    %% 8) 多层记忆系统
    %% ═══════════════════════════════════════════════════════════════

    subgraph MEMORY["🧩 多层记忆系统 (memory.py)"]
        direction TB
        MM["MemoryManager"]
        L1["① case_short_term<br/>namespace: case/{case_id}<br/>自动归档 24h TTL<br/>status: active → expired"]
        L2["② product_long_term<br/>namespace: product/{product}<br/>pending_approval → 5门晋升<br/>季度复核 · 自动过期 · 冲突检测"]
        L3["③ asset_profile<br/>namespace: asset/{asset_id}<br/>低信任运营上下文<br/>季度过期"]
        L4["④ org_knowledge<br/>namespace: org/{scope}<br/>治理团队维护<br/>Playbook · 策略 · 沟通模板<br/>只读默认值自动播种"]
        L5["⑤ evidence<br/>不可变证据引用<br/>read-only · desensitized<br/>load_evidence_refs()"]

        GOV["记忆治理 (Governance)"]
        PROMO["5-Gate 晋升规则<br/>① evidence_traceable<br/>② analyst_approved<br/>③ scope_clear<br/>④ expiry_set<br/>⑤ no_sensitive_leak"]
        OPS["运维操作<br/>promote() · reject() · quarantine()<br/>expire_due() · detect_conflicts()<br/>archive_case() · review_overdue()<br/>confirm_business_false_positive()"]
    end

    %% ═══════════════════════════════════════════════════════════════
    %% 9) 持久化层
    %% ═══════════════════════════════════════════════════════════════

    subgraph DB["🗄️ Repository / SQLite (database.py)"]
        direction LR
        subgraph TABLES["核心表"]
            T_RA["raw_alerts"]
            T_NE["normalized_events<br/>(evidence_hash 防篡改)"]
            T_CS["cases"]
            T_AR["agent_runs"]
            T_CAL["case_alert_links"]
            T_ME["memory_entries<br/>(5层 memory)"]
            T_MEV["memory_events<br/>(审计追踪)"]
            T_AUDIT["audit_log"]
            T_MP["mapping_profiles"]
            T_MM["memory_matches"]
            T_VAL["validation_runs"]
            T_APP["action_approvals<br/>+ approval_votes"]
            T_INBOX["durable_alert_inbox"]
            T_OPS["runtime_settings<br/>+ alert_dispositions"]
        end
        TX["_Transaction 上下文管理器<br/>可重入 · 原子提交/回滚<br/>RLock 串行化并发"]
    end

    %% ═══════════════════════════════════════════════════════════════
    %% 10) Dashboard + API
    %% ═══════════════════════════════════════════════════════════════

    subgraph UI["🖥️ Dashboard & API"]
        direction TB
        DASH["static/index.html<br/>Cases · Alerts · Memory<br/>LLM Config · Syslog Config<br/>Mapping Profiles"]
        API_ROUTES["REST API<br/>┣ /api/session — 服务端身份与角色<br/>┣ /api/alerts — 告警提交<br/>┣ /api/alerts/inbox — 队列与 DLQ<br/>┣ /api/cases — Case 列表/详情/处置<br/>┣ /api/approvals — distinct actor 审批<br/>┣ /api/memory — 治理与相似度记录<br/>┣ /api/config/llm — 模型配置/测试/reload<br/>┣ /api/config/syslog — 本地或外部 Vector 状态<br/>┣ /api/mapping-profiles — 五产品日志适配<br/>┣ /api/alerts/{id}/confirm-false-positive<br/>┗ /api/health — 健康检查 + 统计"]
    end

    %% ═══════════════════════════════════════════════════════════════
    %% 11) 配置层
    %% ═══════════════════════════════════════════════════════════════

    subgraph CONFIG["⚙️ 配置 (config.py)"]
        direction LR
        CFG["GatewayConfig<br/>┣ ServerConfig (连接/超时/限流)<br/>┣ LLMConfig (provider/allowlist/limits)<br/>┣ PolicyConfig (脱敏/双签)<br/>┣ AuthConfig (admin/ingest/operator/approver)<br/>┣ ProcessingConfig (inbox/retry/workers)<br/>┣ OperationsConfig (清理/恢复/到期)<br/>┗ SyslogConfig (embedded/Vector/profiles)"]
        YAML["config/dev.yaml<br/>config/prod.example.yaml<br/>+ parse_simple_yaml()<br/>+ 环境变量覆盖"]
    end

    %% ═══════════════════════════════════════════════════════════════
    %% 12) 外围脚本
    %% ═══════════════════════════════════════════════════════════════

    subgraph SCRIPTS["🔧 脚本 (scripts/)"]
        direction LR
        SEND["send_demo_alerts.py<br/>send_sample.py"]
        SIM["simulate_syslog_ports.py"]
        RESET["reset_and_seed_alerts.py<br/>clean_alerts_and_memory.py"]
        HARNESS["run_harness.py"]
    end

    %% ═══════════════════════════════════════════════════════════════
    %% 连接线
    %% ═══════════════════════════════════════════════════════════════

    WAF_DEV --> SYSLOG
    HIPS_DEV --> SYSLOG
    NDR_DEV --> SYSLOG
    RASP_DEV --> SYSLOG
    SIEM_DEV --> SYSLOG
    DEMO --> HTTP

    SYSLOG --> SPR
    HTTP --> AFP

    SPR --> AFP
    AFP --> LA
    LA --> MP
    LA --> INFER
    LA --> DRY
    LA -.-> AUTO

    AFP --> QUEUE
    QUEUE --> ORCH

    ORCH --> AGENTS
    ORCH --> MEMORY
    AGENTS --> LLM
    LLM --> PE
    MEMORY --> DB

    ORCH --> DB
    AGENTS --> DB
    MEMORY --> DB

    UI --> HTTP_HANDLER
    UI --> API_ROUTES
    SCRIPTS --> HTTP

    CONFIG --> ORCH
    CONFIG --> LLM
    CONFIG --> DB
    CONFIG --> QUEUE
    CONFIG --> MEMORY
```

---

## 数据流全景（单条告警的完整生命周期）

```mermaid
sequenceDiagram
    autonumber
    participant SRC as 🔔 安全产品
    participant TRANS as 📡 传输层<br/>HTTP / Syslog TCP-UDP
    participant ROUTE as 🔀 路由层<br/>SyslogPortRouter<br/>alert_from_payload()
    participant ADAPT as 🔄 LogAdapter<br/>MappingProfile
    participant QUEUE as ⚙️ AlertProcessor
    participant ORCH as 🧠 Orchestrator
    participant NORM as 📋 EventNormalizer
    participant AGENT as 🤖 SecurityAgent<br/>(RASP/WAF/HIPS/NDR/SIEM)
    participant LLM as 🌐 LLM Backend
    participant PE as 🛡️ PolicyEngine
    participant MEM as 🧩 MemoryManager
    participant DB as 🗄️ SQLite

    SRC->>TRANS: 原始告警 (JSON / Syslog 报文)
    TRANS->>ROUTE: Raw bytes + port / HTTP body

    alt Syslog 路径
        ROUTE->>ROUTE: port → product 映射<br/>Syslog 报文 JSON 解析
    else HTTP 直接提交
        ROUTE->>ROUTE: profile=? 参数 → LogAdapter<br/>或 product 字段快速路径<br/>或 fingerprint_product() 指纹识别
    end

    ROUTE->>ADAPT: MappingProfile 适配 (如需)
    ADAPT->>ADAPT: JSONPath 字段映射<br/>severity/product 归一化<br/>evidence_fields 提取
    ADAPT-->>ROUTE: RawAlert

    alt 异步模式 (production)
        ROUTE->>QUEUE: submit(alert)
        QUEUE->>ORCH: handle_alert(alert)
    else 同步模式
        ROUTE->>ORCH: handle_alert(alert)
    end

    ORCH->>NORM: normalize(alert)
    NORM->>PE: redact(payload) — 敏感字段脱敏
    NORM->>NORM: _flatten() → 展平嵌套结构
    NORM->>NORM: _extract_entities() → host/user/src_ip/url...
    NORM->>NORM: _build_evidence() → 结构化证据列表 (≤18条)
    NORM->>NORM: _sensitivity_tags() → credential/personal_data...
    NORM-->>ORCH: NormalizedEvent

    ORCH->>DB: 原子事务: 写入 raw_alert + normalized_event + audit_log

    ORCH->>ORCH: _case_id(event) — 确定性 case ID<br/>case_{product}_{host}_{rule}

    ORCH->>AGENT: build_agent(product, llm, policy)
    ORCH->>MEM: load_context(product, case_id, asset_id)
    MEM->>DB: 查询 4 层记忆
    MEM-->>ORCH: memory_context<br/>{case_short_term, product_long_term,<br/> asset_profile, org_knowledge, evidence_refs}

    ORCH->>MEM: load_match_candidates(product, limit)
    ORCH->>ORCH: MemoryMatcher<br/>硬过滤 + 加权结构化 + 哈希向量余弦 + 检索键<br/>只注入达到复核阈值的 Top-K

    ORCH->>AGENT: agent.analyze(case_id, event, memory_context)

    rect rgb(240, 248, 255)
        Note over AGENT,PE: === Prompt 构建 & LLM 调用 ===
        AGENT->>AGENT: 组装 context<br/>{product, severity, event_type, entities,<br/> evidence, memory, focus, report_outline}
        AGENT->>PE: sanitize_context(context)<br/>深脱敏 + 大小裁剪 (max_context_bytes)
        AGENT->>AGENT: _build_prompt(context)<br/>system_prompt() + 银行 SOC 指令<br/>+ 多层 memory 说明<br/>+ 输出 JSON 契约<br/>+ truncate_prompt_payload()

        AGENT->>LLM: analyze(prompt, sanitized_context)

        alt LocalHeuristicLLM
            LLM->>LLM: 关键词评分 (RCE/SQL/XSS/C2...)
            LLM->>LLM: _sample_assessment() 解析 evidence_assessment
            LLM-->>AGENT: 确定性分析结果 dict
        else OllamaLLM
            LLM->>LLM: POST /api/generate + JSON Schema 约束
            LLM->>LLM: <think> 剥离 → JSON 解析
            LLM->>LLM: _validate_result_shape()
            LLM-->>AGENT: 模型输出 dict
        else GatewayLLM
            LLM->>LLM: POST JSON {model, prompt, context}
            LLM->>LLM: _validate_result_shape() → 中文分类归一化
            LLM-->>AGENT: LLM Gateway 响应 dict
        end

        ORCH->>ORCH: 统一 reconcile<br/>高分可支持 suspicious→benign<br/>malicious 攻击证据拥有否决权
        ORCH->>DB: 写 memory_matches 分项得分与最终影响

        alt LLM 调用异常
            AGENT->>LLM: LocalHeuristicLLM 降级
            LLM-->>AGENT: 确定性分析结果 + "[LLM 降级为本地启发式]"
        end

        AGENT->>AGENT: _ensure_explainable_result()<br/>模型输出与结构化证据调和<br/>_reconcile_model_result():<br/> ① structured ground truth 优先<br/> ② 维度与分类一致性校验<br/> ③ 无真值时合成维度
        AGENT->>AGENT: _format_verdict() → 三类结论标签<br/>【真实攻击/误报/需人工复核】- 原因
        AGENT-->>ORCH: AgentResult
    end

    ORCH->>DB: 原子事务:<br/>upsert_case() + link_case_alert()<br/>+ insert_agent_run() + audit_log

    ORCH->>MEM: record_case_summary(product, result, asset_id)
    rect rgb(255, 250, 240)
        Note over MEM,DB: === 记忆写入 (3 层) ===
        MEM->>DB: ① case_short_term (TTL 24h)
        MEM->>DB: ② product_long_term (pending_approval)
        MEM->>DB: ③ asset_profile (季度过期)
    end

    ORCH-->>QUEUE: AgentResult → case 记录
    QUEUE-->>TRANS: 返回 case_id + 状态
    TRANS-->>SRC: HTTP 202 / 200
```

---

## LLM Prompt 构建详细流程

```mermaid
flowchart LR
    subgraph PROMPT_BUILD["Agent._build_prompt() 构建过程"]
        direction TB
        SYS["① system_prompt()<br/>产品专用系统提示词<br/>如 RASP: 运行时应用自我保护专家"]
        SOC["② 银行 SOC 角色指令<br/>· 全程简体中文<br/>· 只基于输入证据<br/>· 不输出攻击步骤/payload/凭证"]
        MEM_HINT["③ 多层记忆使用说明<br/>· case_short_term → 本案短期参考<br/>· product_long_term → 产品长期经验<br/>· asset_profile → 资产画像<br/>· org_knowledge → 组织知识/Playbook<br/>· evidence_refs → 只读, 不可外泄敏感字段"]
        CONTRACT["④ 输出 JSON 契约<br/>· classification: malicious/suspicious/benign/insufficient_evidence<br/>· verdict:【真实攻击/误报/需人工复核】- 原因<br/>· analysis_dimensions: [{title, status, evidence}]<br/>· whitelist_recommendation<br/>· reason · recommended_next_steps<br/>· missing_evidence · business_impact"]
        PAYLOAD["⑤ 输入上下文<br/>product + severity + event_type<br/>entities + evidence + memory<br/>focus + report_outline<br/>→ PolicyEngine.truncate_prompt_payload() 截断"]
    end

    subgraph SANITIZE["前置: PolicyEngine.sanitize_context()"]
        direction TB
        REDACT_CTX["redact() 深脱敏<br/>· 配置 redact_fields 按 key 脱敏<br/>· SECRET_PATTERNS regex 脱敏<br/> (Bearer token, API key, password)<br/>· 身份证号 pattern 脱敏"]
        BOUND["上下文大小裁剪<br/>· max_context_bytes (default 20KB)<br/>· evidence/memory 超限时尾删<br/>· 极端溢出时只保留核心标量字段<br/> (product, severity, event_type, entities)"]
    end

    SANITIZE --> PROMPT_BUILD
```

---

## 多层记忆架构

```mermaid
flowchart TB
    subgraph MEM_ARCH["5 层记忆 + 治理"]
        direction TB

        subgraph LAYERS["记忆层"]
            L5_E["⑤ evidence<br/>不可变 · 只读<br/>evidence_hash 防篡改<br/>仅出脱敏引用"]
            L4_O["④ org_knowledge<br/>namespace: org/{scope}<br/>治理团队维护 · trust=high<br/>Playbook · 策略 · 沟通模板"]
            L3_A["③ asset_profile<br/>namespace: asset/{asset_id}<br/>trust=low · 季度过期<br/>上次 case 结论 · 资产上下文"]
            L2_P["② product_long_term<br/>namespace: product/{product}<br/>pending → promotion → active<br/>五门晋升 · 季度复核"]
            L1_C["① case_short_term<br/>namespace: case/{case_id}<br/>24h TTL · 自动归档<br/>本次分析结论 + 证据维度"]
        end

        subgraph PROMO["晋升五门 (promotion_check)"]
            G1["① evidence_traceable<br/>必须有 source_case + evidence refs"]
            G2["② analyst_approved<br/>必须有审批人"]
            G3["③ scope_clear<br/>必须限定范围"]
            G4["④ expiry_set<br/>必须设过期时间"]
            G5["⑤ no_sensitive_leak<br/>policy.redact() 不能改变内容"]
        end

        subgraph OPS_MEM["记忆运维"]
            FP["confirm_business_false_positive()<br/>分析师确认误报 → product_long_term"]
            PROMOTE["promote()<br/>pending → active · 5门校验"]
            REJECT["reject()<br/>pending → revoked"]
            QUARANTINE["quarantine()<br/>疑似投毒 → trust=low"]
            SWEEP["expire_due()<br/>到期自动 deweight"]
            CONFLICT["detect_conflicts()<br/>重复记忆隔离"]
            ARCHIVE["archive_case()<br/>case 关闭 → 压缩归档"]
        end
    end

    L1_C -->|propose| L2_P
    L2_P -->|5门通过| L2_P
    L5_E --> G1
```

---

## Agent 注册与分发

```mermaid
flowchart LR
    ORCH[Orchestrator] -->|event.product| BUILD[build_agent()]
    BUILD --> REG{AGENT_TYPES map}

    REG -->|"hips"| HIPS[HipsAgent]
    REG -->|"rasp"| RASP[RaspAgent]
    REG -->|"ndr"| NDR[NdrAgent]
    REG -->|"waf"| WAF[WafAgent]
    REG -->|"siem" 或未知| SIEM[SiemAgent]

    HIPS --> BASE[SecurityAgent ABC]
    RASP --> BASE
    NDR --> BASE
    WAF --> BASE
    SIEM --> BASE

    BASE --> LLM[LLMClient]
    BASE --> POL[PolicyEngine]

    subgraph DIFF["各 Agent 差异点"]
        direction TB
        SYS["system_prompt() — 产品知识注入"]
        FOCUS["analysis_focus() — 分析关注点列表"]
        OUTLINE["report_outline() — 报告章节标题"]
    end
```

---

## 核心模块速查表

| 模块 | 文件 | 职责 |
|------|------|------|
| **入口** | `__main__.py` | 启动 HTTP 服务器 |
| **HTTP 服务** | `app.py` | REST API + Dashboard 静态文件 + 告警接收/路由 |
| **编排引擎** | `orchestrator.py` | `handle_alert()` 主流程：归一化 → Agent分析 → 记忆写入 |
| **配置** | `config.py` | YAML 解析 + 环境变量覆盖 + 7 个子配置 |
| **数据模型** | `models.py` | RawAlert, NormalizedEvent, AgentResult, RecommendedAction |
| **数据库** | `database.py` | SQLite WAL + `Repository` + `_Transaction` 原子事务 |
| **LLM 后端** | `llm.py` | 3 套后端 + JSON Schema 约束 + 结果校验 |
| **策略引擎** | `policy.py` | 敏感字段脱敏 · 上下文裁剪 · 动作模式 · prompt 截断 |
| **归一化器** | `normalizer.py` | 原始告警 → NormalizedEvent (实体提取 + 证据构建 + 敏感标签) |
| **异步队列** | `processing.py` | 有界 worker pool 解耦接收与分析 |
| **系统日志** | `syslog_receiver.py` | TCP/UDP 多产品监听器管理 |
| **Syslog路由** | `syslog_router.py` | 端口 → 产品映射 + JSON 解析 |
| **日志适配** | `log_adapter.py` | MappingProfile · LogAdapter · 字段推断 · 自动适配 |
| **记忆管理** | `memory.py` | 5层记忆 · 晋升 · 治理 · 过期 · 误报确认 |
| **Agent 基类** | `agents/base.py` | SecurityAgent ABC · prompt构建 · 结果调和 · 综合降级 |
| **Agent 注册** | `agents/registry.py` | `build_agent()` · AGENT_TYPES 映射 |
| **5个Agent** | `agents/{rasp,waf,hips,ndr,siem}.py` | 产品专用 system_prompt + analysis_focus |
| **证据助手** | `agents/evidence_helpers.py` | fact/join_facts/normalize_classification 工具函数 |
| **样本生成** | `sample_alerts.py` | 5产品 × 3场景(attack/fp/suspicious) 随机样本 |
