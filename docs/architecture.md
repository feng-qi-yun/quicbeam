# QuicBeam 架构设计文档

## 一、背景与实测动机（2026-11-22 ~ 11-24）

在同一条江苏电信家宽线路上，通过对比测试实锤了两类运营商干扰：

| 测试项 | 协议与端口 | 持续时长 | 实测上行 | 现象 |
|---|---|---|---|---|
| 中科大测速站（合肥电信） | **HTTPS `TCP 443`** | 3s | **82.26 Mbps** | 满速放行 |
| Cloudflare 测速（海外节点） | **HTTPS `TCP 443`** | 10s | **42.36 Mbps**（峰值 67.1 Mbps） | 10 秒持续不掉速 |
| Ookla（上海电信） | **非标 `TCP 8080`** | 9s | **1.88 ~ 1.94 Mbps** | 稳定压死在 ~2 Mbps |
| Tailscale / WireGuard | **UDP `41641` / `51935`** | 持续 | **1.75 Mbps → `udp=false`** | 限速 + 动态识别特征并黑洞端口 |

**核心结论**：
1. 宽带本身具备 **~80+ Mbps** 持续上行能力，并非物理故障。
2. 运营商同时存在 **非标端口上行限速（~2 Mbps）** 与 **WireGuard 特征端口动态黑洞**。
3. 突破口：**基于标准 `443` 端口 + 真 TLS 1.3 / QUIC (HTTP/3) 外壳**，避免 WireGuard 特征指纹，并验证/利用 443 白名单带宽。

---

## 二、四层架构设计

```text
┌──────────────────────────────────────────────────────────┐
│  L4 业务接入层：TCP/UDP 端口转发（Moonlight/SSH）或 TUN    │
├──────────────────────────────────────────────────────────┤
│  L3 抗 DPI 传输层：QUIC (UDP 443, ALPN h3) + RFC 9221     │
├──────────────────────────────────────────────────────────┤
│  L2 链路保活与跳端口：Connection Migration / Port Hopping │
├──────────────────────────────────────────────────────────┤
│  L1 寻址与穿透层：STUN 探测 + 极简信令交换 + IPv6 优先     │
└──────────────────────────────────────────────────────────┘
```

### L4：业务接入层（轻量级端口转发，不做 TUN 虚拟网卡）
- 项目刻意不引入 TUN 虚拟网卡与内核驱动，保持单文件免 Root 跨平台（Linux / Windows / Android Termux）极简形态，专注替代 Tailscale 在 Moonlight/Sunshine 与 SSH 中的作用。
- **TCP 映射**（走 QUIC Stream，可靠有序，支持出口目标白名单 `allowed_targets`）：
  - SSH (`22`)
  - Sunshine 控制信令 (`47984`, `47989`, `47990`, `48010`)
- **UDP 映射**（走 QUIC Unreliable Datagram RFC 9221，不可靠、零队头阻塞）：
  - Sunshine 视频/音频/输入流 (`47998` ~ `48010`)
- **协议封装格式（Datagram）**：
  - 常规包：`[1 byte channel_id][N bytes raw UDP payload]`，极简 1 字节多路复用头；
  - 超长包（如 Moonlight LAN 默认 1408B 超过路径 `MaxDatagramSize`）：自动切换 `0xFF` 逃逸头执行不可靠分片与无阻塞重组。

### L3：抗 DPI 传输层
- **首选传输**：`quic-go` + TLS 1.3 + ALPN `h3` + `EnableDatagrams: true`。
- **认证与防 MITM**：支持 `cert_sha256` 证书指纹钉扎（`quicbeam keygen` 一键生成自签证书、指纹与随机 PSK）+ 首条 Control Stream 常量时间 PSK 鉴权，非法探测连接直接拒绝关闭。

### L2：Port Hopping（连接迁移）
- 依托 QUIC 原生 Connection Migration（`AddPath` → `Probe` → `Switch`），在定时窗口到达时 Make-Before-Break 平滑迁移客户端源端口，保证串流不中断。

### L1：双端 NAT 打洞与极简加密信令
- 基于 RFC 7983 首字节复用（`DemuxPacketConn`），同一 UDP Socket 并发承接 STUN 探测、打洞包与 QUIC 握手：
  - 启动及运行期间通过纯 Go RFC 5389 STUN 采集公网 IPv4:Port 及原生全局 IPv6；
  - 通过 `SHA-256(PSK)` + AES-256-GCM 加密端点信息后经极简 HTTP/KV 信令（如 Cloudflare Workers KV）交换，并触发双向 UDP 并发打洞。

---

## 三、开发阶段规划

1. **Phase 0：`quicbeam probe`（已完成）** — 实测台式机 ↔ 笔记本 `UDP 443` QUIC Stream 93.4 Mbps、Datagram 60 Mbps 0.00% 丢包。
2. **Phase 1：MVP 对称直连隧道（已完成）** — `quicbeam server` / `client` 跑通 SSH + Moonlight 串流与 1408B 不可靠分片。
3. **Phase 2：双端 NAT 打洞 + 加密信令 + Port Hopping + 安全加固（已完成）** — STUN/IPv6 发现、AES-256-GCM 信令、同 Socket 双向打洞、Make-Before-Break 跳端口、`cert_sha256` 钉扎与 `allowed_targets` 白名单。
