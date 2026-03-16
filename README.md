# Firewall API 文档

本文档描述当前项目的 HTTP API、认证方式、请求参数和返回结构。

## 部署脚本

仓库内置部署脚本 [deploy.sh](deploy.sh)，支持安装和卸载。

安装或更新：

```bash
bash deploy.sh install
```

卸载：

```bash
bash deploy.sh uninstall
```

说明：

- `install` 会自动检测系统和 CPU 架构，补齐 Go 与系统依赖，并使用仓库中的 `go.mod` / `go.sum` 进行可重复构建
- `install` 不会覆盖已经存在的 `/opt/firewall-api/config.yaml`
- `uninstall` 会停止并移除 systemd 服务、删除安装目录，并询问是否删除数据库文件

## 基本信息

- 默认监听地址由 [config.yaml](config.yaml) 的 `server.listen` 控制
- 当 [config.yaml](config.yaml) 中 `panel.enabled=true` 时，根路径 `/` 默认返回控制面板
- 所有 `/api/*` 接口都需要 `Bearer Token`
- 返回类型默认是 `application/json; charset=utf-8`

## 控制面板配置

配置示例：

```yaml
panel:
  enabled: true
```

说明：

- `true`：启用内嵌控制面板，访问 `/` 返回面板页面
- `false`：禁用控制面板，访问 `/` 返回 404，API 仍可继续使用

## 认证

请求头：

```http
Authorization: Bearer <token>
```

未携带或错误时返回：

```json
{
  "error": "missing bearer token"
}
```

或：

```json
{
  "error": "invalid bearer token"
}
```

## 1. 控制台入口

### GET /

当控制面板启用时，返回内嵌的控制面板页面。

## 2. 规则管理

### GET /api/rules

获取规则列表。

查询参数：

- `family=ipv4`：仅返回 IPv4 规则
- `family=ipv6`：仅返回 IPv6 规则
- `family=all` 或不传：返回全部规则

错误响应：

```json
{
  "error": "family must be ipv4 or ipv6"
}
```

响应示例：

```json
[
  {
    "id": "ae261ad682fd7960",
    "name": "Tokyo relay",
    "family": "ipv4",
    "protocol": "all",
    "localPort": 2333,
    "inboundIp": "10.0.0.10",
    "targetIp": "163.223.125.6",
    "targetPort": 50028,
    "outboundIp": "10.0.0.20",
    "connLimit": 1000,
    "bandwidthKbps": 1024,
    "enabled": true,
    "createdAt": "2026-03-15T08:00:00Z",
    "updatedAt": "2026-03-15T08:00:00Z",
    "total": {
      "trafficBytes": 123456,
      "trafficPkts": 789
    },
    "tcp": {
      "trafficBytes": 120000,
      "trafficPkts": 700
    },
    "udp": {
      "trafficBytes": 3456,
      "trafficPkts": 89
    }
  }
]
```

### POST /api/rules

创建一条规则。

请求体：

```json
{
  "name": "Tokyo relay",
  "family": "ipv4",
  "protocol": "all",
  "localPort": 2333,
  "inboundIp": "10.0.0.10",
  "targetIp": "163.223.125.6",
  "targetPort": 50028,
  "outboundIp": "10.0.0.20",
  "connLimit": 1000,
  "bandwidthKbps": 1024
}
```

字段说明：

- `name`：可选，规则名称或备注，最长 200 个字符
- `family`：`ipv4` 或 `ipv6`
- `protocol`：`tcp`、`udp`、`all`
- `localPort`：本地监听端口，1-65535
- `inboundIp`：可选，限定入口命中的本地目标 IP；留空表示不限制入口地址
- `targetIp`：目标 IP
- `targetPort`：目标端口，1-65535
- `outboundIp`：可选，指定转发后使用的出口源 IP；留空时按现有 masquerade 配置处理
- `connLimit`：连接数限制，`0` 表示不限制
- `bandwidthKbps`：限速，单位 Kbps，也就是千比特每秒，`10240` 约等于 `10 Mbps`，`0` 表示不限制

限速实现说明：

- 后端会把 `Kbps` 转换成 iptables `hashlimit` 所需的字节速率
- 为避免 TCP 纯 ACK 小包被误伤导致吞吐显著低于配置值，TCP 限速规则会跳过长度小于 `128` 字节的确认包
- 该限速实现属于丢包式限速，不是队列整形；实际吞吐会受到 RTT、拥塞控制和应用协议影响，但应与配置值保持同一量级，而不再被 ACK 包异常压低

成功响应：

```json
{
  "message": "rule created"
}
```

### PUT /api/rules

更新已有规则。

请求体：

```json
{
  "id": "ae261ad682fd7960",
  "new": {
    "name": "Tokyo relay",
    "family": "ipv4",
    "protocol": "all",
    "localPort": 2333,
    "inboundIp": "10.0.0.10",
    "targetIp": "163.223.125.6",
    "targetPort": 50028,
    "outboundIp": "10.0.0.20",
    "connLimit": 1000,
    "bandwidthKbps": 2048
  }
}
```

成功响应：

```json
{
  "message": "rule updated"
}
```

### DELETE /api/rules

按规则 ID 删除规则。

请求体：

```json
{
  "id": "ae261ad682fd7960"
}
```

成功响应：

```json
{
  "message": "rule deleted"
}
```

## 4. 规则指标

### GET /api/rules/metrics

返回单条规则的累计指标与实时吞吐信息。

查询参数：

- `id=<rule-id>`：必填，返回单条规则指标

响应示例：

```json
{
  "id": "ae261ad682fd7960",
  "family": "ipv4",
  "protocol": "all",
  "localPort": 2333,
  "targetIp": "163.223.125.6",
  "targetPort": 50028,
  "sampleIntervalSeconds": 5,
  "cumulative": {
    "total": {
      "trafficBytes": 123456,
      "trafficPkts": 789
    },
    "tcp": {
      "trafficBytes": 120000,
      "trafficPkts": 700
    },
    "udp": {
      "trafficBytes": 3456,
      "trafficPkts": 89
    }
  },
  "realtime": {
    "total": {
      "bytesPerSec": 20480,
      "pktsPerSec": 32
    },
    "tcp": {
      "bytesPerSec": 20000,
      "pktsPerSec": 30
    },
    "udp": {
      "bytesPerSec": 480,
      "pktsPerSec": 2
    }
  },
  "lastUpdatedUnix": 1741996800
}
```

### GET /api/rules/diagnostics

按规则 ID 诊断从当前规则出口到目标地址的平均延迟。

查询参数：

- `id=<rule-id>`：必填，指定要诊断的规则

说明：

- 当规则协议为 `tcp` 或 `all` 时，使用 TCP 连接目标 `targetIp:targetPort` 的方式计算平均延迟
- 当规则协议为 `udp` 时，使用 ICMP ping 诊断目标 `targetIp` 的平均延迟
- 当规则未指定 `outboundIp` 时，后端会按系统默认路由解析实际出站 IP

响应示例：

```json
{
  "id": "ae261ad682fd7960",
  "family": "ipv4",
  "protocol": "all",
  "targetIp": "163.223.125.6",
  "targetPort": 50028,
  "configuredOutboundIp": "43.248.8.97",
  "effectiveOutboundIp": "43.248.8.97",
  "method": "tcp-connect",
  "sampleCount": 3,
  "successfulSamples": 3,
  "latencyMs": 28.41,
  "diagnosedAt": "2026-03-16T02:10:00Z"
}
```

## 4. 系统总览接口

### GET /api/system

返回系统总览，包含系统、开机时长、CPU、内存、磁盘、网卡累计统计、网卡实时速率和 NAT 视图数据。

说明：

- 原本拆开的系统基础信息、CPU、内存、磁盘、网络统计接口已经并入这个总览接口
- 网卡累计与实时信息在同一个响应里返回，控制台只依赖这个接口

主要字段：

- `version`：当前系统版本号
- `status`：转发能力、iptables 环境和 masquerade 配置
- `system`：主机、内核、架构、虚拟化信息
- `uptime`：开机时间和可读运行时长
- `cpu`：CPU 型号、逻辑核数、使用率
- `memory`：总内存、已用、可用、缓存等信息
- `disk`：磁盘分区数组
- `network.interfaces`：每张网卡的累计和实时信息
- `network.summary`：全部网卡的总发送、总接收、总上传速率、总下载速率
- `nat.ipv4`：IPv4 NAT 表文本
- `nat.ipv6`：IPv6 NAT 表文本

## 常见错误响应

```json
{
  "error": "id is required"
}
```

```json
{
  "error": "rule not found"
}
```

```json
{
  "error": "rule already exists"
}
```

```json
{
  "error": "family must be ipv4 or ipv6"
}
```