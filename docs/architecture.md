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

### L4：业务接入层（MVP：端口转发）
- **TCP 映射**（走 QUIC Stream，可靠有序）：
  - SSH (`22`)
  - Sunshine 控制信令 (`47984`, `47989`, `48010`)
- **UDP 映射**（走 QUIC Unreliable Datagram RFC 9221，不可靠、零队头阻塞）：
  - Sunshine 视频/音频/输入流 (`47998` ~ `48010`)
- **协议封装格式（Datagram）**：
  - `[1 byte channel_id][N bytes raw UDP payload]`，极简 1 字节多路复用头，最小化 MTU 损耗。

### L3：抗 DPI 传输层
- **首选传输**：`quic-go` + TLS 1.3 + ALPN `h3` + `EnableDatagrams: true`。
- **认证机制**：双向 TLS（mTLS）或连接建立后的首条 Control Stream PSK 鉴权，非法探测连接直接伪装返回普通 HTTP/3 404 或静默关闭。
- **备选兜底**：若实测发现 `UDP 443` 同样遭遇限速，保留 `internal/transport` 接口抽象，可扩展支持 TLS-over-TCP 443（用于控制流/运维）或 FakeTCP。

### L2：Port Hopping（连接迁移）
- 依托 QUIC 原生 Connection Migration（通过 Connection ID 而非四元组标识会话），在检测到丢包飙升或定时窗口到达时平滑迁移客户端源端口（Make-Before-Break），保证串流不中断。

### L1：NAT 穿透与极简信令
- 双端均为 Cone NAT / 公网 IP，无需重型中控：
  - 启动时通过 STUN 采集公网 IPv4:Port 及原生 IPv6；
  - 通过极简信令接口（如 Cloudflare Workers KV）交换加密后的端点信息并并发打洞。

---

## 三、开发阶段规划

1. **Phase 0：`quicbeam probe`** — 实测台式机 ↔ 笔记本在 `UDP 443` QUIC Datagram 下的 10 秒持续上行吞吐，确认是否享受 443 白名单满速。
2. **Phase 1：MVP 直连隧道** — `quicbeam server` / `quicbeam client` 点对点连接，跑通 SSH + Moonlight 1080p60 串流。
3. **Phase 2：自动打洞 + Port Hopping** — 接入 STUN 与极简信令，支持动态 IP 自动重连与无感换端口。
4. **Phase 3：TUN 虚拟网卡（可选）** — 集成 `wintun` / `/dev/net/tun` 实现透明三层组网。
