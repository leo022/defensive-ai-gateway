# 离线迁移步骤

## 1. 外网环境打包

```bash
cd defensive-ai-gateway
python3 -m pytest
python3 scripts/run_harness.py --samples samples --fail-on-low-confidence 0.5
tar --exclude "data" --exclude "__pycache__" -czf defensive-ai-gateway.tar.gz .
```

如需完全固定 Python 版本，建议在外网构建基础镜像并经企业镜像扫描后导入内网镜像仓库。

## 2. 内网验收前检查

- 代码安全扫描：确认无硬编码密钥、无外联域名、无危险命令执行。
- 配置审查：`config/prod.example.yaml` 复制为内网配置，确认 LLM Gateway endpoint、数据库路径和监听地址。
- 数据分级：确认哪些字段允许进入 prompt，哪些字段只能以 evidence_ref 形式引用。
- 权限审查：服务账号只授予只读查询权限。
- 架构审查：对照 `docs/DEMO_ARCHITECTURE.md`、`docs/MEMORY.md`、`docs/HARNESS.md` 确认接入点、记忆治理和回放门禁。
- 日志适配审查：为每类内网真实日志准备 Mapping Profile，使用 Dashboard dry-run 或 `scripts/run_harness.py --mapping-profile-file` 验证字段映射、严重级别、产品路由和必填字段门禁。

## 3. 内网启动

```bash
tar -xzf defensive-ai-gateway.tar.gz -C /opt/defensive-ai-gateway
cd /opt/defensive-ai-gateway
bash install.sh
python3 -m defensive_ai_gateway --config config/prod.yaml
```

Dashboard 默认由同一服务提供静态页面，可通过生产配置中的监听地址访问。当前页面支持 Case 展开、日志适配 Profile 配置与 dry-run、LLM 配置、浅色/深色模式和人工确认业务误报。

如需用 systemd 托管服务，可在解压目录执行：

```bash
sudo bash install.sh --systemd --enable --start
```

## 4. 迁移后第一批测试

1. 提交脱敏样例 WAF 告警，确认敏感字段不会出现在 Agent 输出。
2. 提交 SIEM 聚合样例，确认使用 `siem-fusion-agent`。
3. 断开 LLM Gateway，确认系统能失败可见，而不是静默成功。
4. 检查 `audit_log` 表，确认每次事件均有 `alert_received` 和 `analysis_completed`。
5. 在 Dashboard 展开 Case，确认 raw alert、normalized evidence、agent_runs 和建议动作均可追溯。
6. 对确认的业务误报执行一次 Dashboard 误报确认，检查 `memory_entries` 与 `memory_events` 是否写入。
7. 粘贴一条脱敏 RASP 真实日志运行 Mapping Profile dry-run，确认 `RawAlert`、`NormalizedEvent`、Agent 路由、缺失字段提示和适配状态均符合预期。
