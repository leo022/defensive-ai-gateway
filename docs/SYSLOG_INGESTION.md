# Syslog Ingestion

本项目推荐用独立 collector 接收 syslog，再转发到网关现有 HTTP 入口：

```text
Security Product -> Syslog product ports -> Collector -> POST /api/alerts -> Defensive AI Gateway
```

这样网关主进程继续只处理稳定的 HTTP JSON，syslog 的协议兼容、缓冲、重试、格式差异由 collector 承担。

为了避免高峰期不同安全系统共用一个入口后只能靠内容猜测来源，demo/生产模板推荐按产品拆分 syslog 端口：

| 产品 | 默认端口 | 协议 | 路由 |
|------|----------|------|------|
| WAF | `15140` | TCP 优先 | `product=waf` → `auto-waf-json` |
| HIPS | `15141` | TCP 优先 | `product=hips` → `auto-hips-json` |
| NDR | `15142` | TCP 优先 | `product=ndr` → `auto-ndr-json` |
| RASP | `15143` | **TCP；UDP 仅迁移兼容** | `product=rasp` → `auto-rasp-json` |
| SIEM | `15144` | TCP 优先 | `product=siem` → `auto-siem-json` |

端口路由优先级高于日志内容字段；如果日志内容声明了另一个 product，collector 应记录 mismatch 但不覆盖端口路由。

## k3s 部署

部署网关和 syslog collector：

```bash
cp .env.example .env
chmod 600 .env
# 设置四个角色 Token、TLS/来源 CIDR，并至少设置：
# DEFENSIVE_AI_SYSLOG_SOURCE_CIDRS=10.20.0.0/16
bash install.sh --with-syslog
```

源清单包含构建期镜像与安装期 CIDR 占位符，不能直接 `kubectl apply`。生产安装器
校验不可变镜像、TLS Secret 和受限 `loadBalancerSourceRanges` 后才渲染清单；空值、
`0.0.0.0/0` 和 `::/0` 均失败关闭。

控制台的「日志接入 > 告警接入 > Syslog 接入部署」可保存 collector 对外地址和设备
来源 CIDR，并下载不含凭据的 `defensive-ai-syslog-console.env`。将该文件带到部署主机后，
用以下命令同步到 `syslog-collector` Service 和其 NetworkPolicy：

```bash
bash install.sh --with-syslog --syslog-console-config defensive-ai-syslog-console.env
```

控制台不会直接取得 Kubernetes 写权限，也不会保存或显示 ingest Token。

`syslog-collector-vector` 从 `defensive-ai-gateway-secrets` 只挂载 `DEFENSIVE_AI_INGEST_TOKEN`，并在每个 HTTP sink 请求中发送该 Bearer Token。它不会取得管理员、运营或审批 Token。生产安装器要求四个角色 Token 都不同，避免 collector 被攻陷后获得配置或记忆治理权限。

安全设备侧配置：

- 目的地址：k3s 节点 IP，或 `syslog-collector` Service 的 LoadBalancer IP
- 端口：按产品使用 `15140`-`15144`
- 协议：RASP 控制台必须使用 TCP；其他产品优先 TCP。为避免在未知旧配置下主动断流，collector 暂时仍接收 `15143/UDP`，并在每条告警写入 `legacy_udp_best_effort` 标记；该入口仅用于迁移，不能作为连续投递保证。RASP 控制台必须填写 collector 对外 IP/LoadBalancer IP 与端口 `15143`，不能填写 Gateway 的 HTTP `8080`。
- 格式：RFC3164 或 RFC5424 syslog；message 最好是 JSON
- RASP TCP 帧上限：`2 MiB`。Vector 显式配置该上限，避免其默认 `100 KiB` 缓冲截断调用栈；超过上限的设备必须先经企业 Syslog relay 分流或缩短单条日志，不能依赖截断后的日志研判。UDP 受网络数据报大小与无确认语义限制，不能安全承载长 RASP 事件，必须完成 TCP 迁移。

不建议第一版直接使用 `514`，因为低端口通常需要额外 Linux capability 或 root 权限。

## 本地端口路由模拟

先启动网关：

```bash
python3 -m defensive_ai_gateway --config config/dev.yaml
```

再运行 TCP syslog 端口模拟：

```bash
python3 scripts/simulate_syslog_ports.py --config config/dev.yaml
```

脚本会检查 `GET /api/health`，把 `samples_syslog/<product>/<product>_alert.json` 作为不同设备发来的 syslog 报文发送到 `15140`-`15144`，并确认每条都按目标端口路由到正确 product。`config/dev.yaml` 的内嵌监听模式会直接复用已经启动的五个监听器并轮询持久 inbox，直到每条记录变为 `completed`；外置 collector 模式仍验证 HTTP 入口返回 `202`、`status=queued` 和 `durable=true`。

内嵌 TCP 接收器兼容 RFC6587 八位计数、单行换行分帧，以及本仓库 Demo 使用的完整多行 JSON 文档；每帧和每连接仍受配置的字节上限保护。

## 高 QPS 入口削峰

网关 HTTP 入口默认启用异步告警队列：

```yaml
processing:
  async_enabled: true
  queue_max_size: 5000
  workers: 4
```

`POST /api/alerts` 完成鉴权、字段映射和 product 路由后，先写入 SQLite 持久 inbox，再返回 `202`；后台 worker 执行 Agent 分析、记忆加载和 Case 写入。进程崩溃后未完成项可恢复，有限重试终止的条目进入 DLQ。远程 LLM 不可达时，告警进入独立 `deferred` 状态而非普通 `retry`，因此调度器不会反复调用不可用模型；定时维护会按批次释放到 `retry`，分析师也可通过 `/api/alerts/inbox/release-llm-deferred` 手工恢复。若当前配置已切到本地规则分析器，释放会被拒绝，避免把远程模型待处理告警静默降级为本地结论。`GET /api/alerts/inbox?status=deferred` 与 `?status=dead_letter` 可查询待恢复或失败记录，`GET /api/health` 提供 queued、processing、deferred、failed/dead-letter 等指标。持久 inbox 达到上限时返回 `429`，让 Vector 磁盘 buffer 持续重试并施加回压。

## Collector 输出格式

`deploy/k3s/syslog-collector-vector.yaml` 会把 syslog 转成当前网关已支持的标准告警 JSON：

```json
{
  "alert_id": "device:event:timestamp",
  "source": "security-product",
  "product": "siem",
  "event_type": "syslog_event",
  "severity": "medium",
  "timestamp": "2026-06-25T10:00:00+08:00",
  "payload": {
    "syslog_message": "...",
    "syslog": {}
  }
}
```

如果 syslog 的 message 是 JSON，collector 会优先读取这些字段：

- `alert_id` 或 `id`
- `product`，支持 `hips`、`rasp`、`ndr`、`waf`、`siem`
- `event_type`、`event.type` 或 `type`
- `severity` 或 `level`

无法识别的 `product` 会降级为 `siem`，未知严重级别会降级为 `medium`。

## 产品原生 JSON 与 Mapping Profile

如果某个安全产品把原生 JSON 放在 syslog message 中，并且你希望复用 Dashboard 里的 Mapping Profile，部署清单 `deploy/k3s/syslog-collector-vector.yaml` 已经内置按来源自动分类：

1. `classify_source` 识别来源 product（优先 syslog `appname` 标签，其次日志内容指纹，例如 cloudrasp 的 `data_type=attack_event` → `rasp`）。
2. 把 product 映射到 Dashboard 中已保存的 profile_id，写入 `gateway_profile`。
3. `route_by_profile` 分流：
   - `profiled`（有 profile）→ 透传 `{"log": structured, "profile_id": "..."}`，由网关侧 profile 做字段语义映射。
   - `standard`（未配置 profile）→ collector 侧归一化为标准告警 JSON 直送 `/api/alerts`，不会被丢弃。

网关启动时会为 WAF、HIPS、NDR、RASP 和 SIEM 置入 `auto-<product>-json` 内置 Profile，Vector 的 `classify_source` 与这五个 ID 直接对齐，不再需要手工取消注释。运营人员仍可以在 Dashboard「日志自动适配」中用脱敏样本执行 infer + dry-run，再创建厂商专用 Profile；更换 ID 时必须同步更新 Vector 路由。无法识别产品的来源仍安全回落到 `standard` 路径。

## 运维注意事项

- RASP collector 以 TCP `15143` 为正式通道，并把实际 `protocol`、传输保证级别、原始 Syslog 指纹和解析后 RASP 日志指纹写入告警完整性摘要。为无中断迁移保留的 UDP `15143` 会标记为 `legacy_udp_best_effort`，应在观测到稳定 TCP 后移除。
- TCP Syslog 仍没有设备到 Gateway 的业务级确认。Vector 对已接收事件使用磁盘 buffer，并对网络和服务端可重试故障使用高重试上限；Gateway 在持久 inbox 落库后才接受。当前生产 Vector `0.46.x` 将认证/格式类 `4xx` 视为不可重试，因此轮换 ingest Token 时必须先停止 collector、更新 Gateway 与同一份环境文件，再恢复 collector，避免认证窗口丢弃请求。必须监控 Vector 的丢弃/错误指标、磁盘 buffer 与 Gateway inbox/DLQ，不能把 TCP 当作绝对端到端投递证明。
- k3s 单节点加 SQLite 时，网关 Deployment 保持 `replicas: 1`。
- Collector 默认使用 2 GiB PVC 和每个 sink 512 MiB 磁盘 buffer；监控 PVC 容量、HTTP 重试与网关 inbox/DLQ，不要只看 Pod 存活。
- Collector 的 `LoadBalancer` 已使用安装期 `loadBalancerSourceRanges`，生产安装器还会生成同源 CIDR 的 NetworkPolicy，阻止集群内部绕过 Service 直接注入；仍应在边界防火墙重复限制安全设备网段。传统 UDP/TCP syslog 没有端到端机密性，应置于设备专网/VPN，或先接企业 TLS syslog relay。
- 先用脱敏样例验证字段映射，再接入真实生产日志。
