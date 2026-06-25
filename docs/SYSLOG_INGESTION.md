# Syslog Ingestion

本项目推荐用独立 collector 接收 syslog，再转发到网关现有 HTTP 入口：

```text
Security Product -> Syslog UDP/TCP 1514 -> Vector -> POST /api/alerts -> Defensive AI Gateway
```

这样网关主进程继续只处理稳定的 HTTP JSON，syslog 的协议兼容、缓冲、重试、格式差异由 collector 承担。

## k3s 部署

部署网关和 syslog collector：

```bash
kubectl apply -f deploy/k3s/gateway.yaml
kubectl apply -f deploy/k3s/syslog-collector-vector.yaml
```

安全设备侧配置：

- 目的地址：k3s 节点 IP，或 `syslog-collector` Service 的 LoadBalancer IP
- 端口：`1514`
- 协议：优先 TCP，设备只支持 UDP 时使用 UDP
- 格式：RFC3164 或 RFC5424 syslog；message 最好是 JSON

不建议第一版直接使用 `514`，因为低端口通常需要额外 Linux capability 或 root 权限。

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

如果某个安全产品把原生 JSON 放在 syslog message 中，并且你希望复用 Dashboard 里的 Mapping Profile，可以把 Vector sink 改为：

```toml
uri = "http://defensive-ai-gateway:8080/api/alerts?profile=demo-rasp-json"
```

并把 remap 的最终输出改成：

```text
. = { "log": structured }
```

生产环境建议为每类设备保存独立 profile，例如：

- `waf-syslog-json`
- `rasp-syslog-json`
- `hips-syslog-json`
- `ndr-syslog-json`
- `siem-syslog-json`

这样 collector 负责协议接入，网关的 Mapping Profile 负责字段语义映射。

## 运维注意事项

- TCP syslog 优先于 UDP syslog；UDP 无传输确认，峰值时可能丢包。
- k3s 单节点加 SQLite 时，网关 Deployment 保持 `replicas: 1`。
- 如果 syslog 峰值较高，给 Vector 配置磁盘 buffer，再扩展网关为外部数据库。
- 对 collector 的 `LoadBalancer` 来源地址做防火墙限制，只允许安全设备网段访问。
- 先用脱敏样例验证字段映射，再接入真实生产日志。
