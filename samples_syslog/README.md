# Syslog 告警样本（原始厂商格式）

本目录存放安全产品**原始格式**的告警 JSON 样本，用于 syslog 接入与 Mapping Profile 字段映射的脱敏验证。

## 与 `samples/` 的区别

| 目录 | 格式 | 用途 |
|------|------|------|
| [`samples/`](../samples/) | 网关标准归一化格式（`alert_id` / `product` / `event_type` / `severity` / `timestamp` / `payload`） | 可直接 `POST /api/alerts` 回放 |
| `samples_syslog/` | 安全产品原生日志（OpenRASP、WAF、HIPS、NDR、SIEM 等） | 需经 syslog collector 转发 + Mapping Profile 映射后进入网关 |

接入流程与运维细节见 [docs/SYSLOG_INGESTION.md](../docs/SYSLOG_INGESTION.md)。

## 目录结构

按产品类型分目录，文件名体现产品与场景：

```
samples_syslog/
├── rasp/   # 运行时应用自保护（RASP）
│   └── rasp_alert.json   # Fastjson 反序列化 → JNDI/LDAP 注入
├── waf/    # Web 应用防火墙
├── hips/   # 主机入侵防护
├── ndr/    # 网络检测与响应
└── siem/   # 安全信息与事件管理
```

## 回放验证

样本需以 `{"log": <样本JSON>}` 包裹后，通过 Mapping Profile 映射。内置 `demo-rasp-json` profile 可直接消费本目录的 RASP 样本。

**Dry-run**（仅查看映射结果，不入库）：

```bash
curl -X POST http://127.0.0.1:8080/api/mapping-profiles/dry-run \
  -H 'Content-Type: application/json' \
  -d "{\"profile_id\":\"demo-rasp-json\",\"log\":$(cat samples_syslog/rasp/rasp_alert.json)}"
```

**自动推断** Mapping Profile：

```bash
curl -X POST http://127.0.0.1:8080/api/mapping-profiles/infer \
  -H 'Content-Type: application/json' \
  -d "{\"log\":$(cat samples_syslog/rasp/rasp_alert.json)}"
```

**正式接入**（经 profile 映射后进入网关）：

```bash
curl -X POST 'http://127.0.0.1:8080/api/alerts?profile=demo-rasp-json' \
  -H 'Content-Type: application/json' \
  -d "{\"log\":$(cat samples_syslog/rasp/rasp_alert.json)}"
```

## 约定

- 所有样本必须为**脱敏**数据，不得包含真实生产敏感信息。
- 新增样本按产品归入对应子目录，文件名应体现产品与场景，便于检索。
- 样本应保留原始字段结构，**不要手工归一化**——字段语义映射由 Mapping Profile 负责。
