# QuicBeam

> 面向远程游戏串流（Moonlight / Sunshine）与低延迟运维的 **抗 DPI / 抗 QoS P2P 隧道** —— 基于 **QUIC (HTTP/3, UDP 443) + RFC 9221 Unreliable Datagram**。

## 为什么做 QuicBeam？

在部分国内家宽环境下，传统的 WireGuard / Tailscale 方案面临双重封锁：
1. **协议指纹动态黑洞**：运营商省网 DPI 识别标准 WireGuard 握手包（固定 148/92 字节与明文头）后，无论怎么更换高位端口，都会将对应 UDP 端口逐个拉黑（`udp=false`），迫使连接回退至高延迟海外中继。
2. **非标端口上行限速（反 PCDN QoS）**：实测同一条家宽线路下，标准 **`443` 端口（HTTPS/TLS）** 上行可稳定跑满 **42~82 Mbps**，而非标端口（如 `8080`、高熵 UDP）被硬性压死在 **~1.9 Mbps**。

**QuicBeam** 的设计目标非常聚焦：
- **标准 `443` 端口 + 真 TLS 1.3 / QUIC (ALPN `h3`) 外壳**：天然融入主流 HTTP/3 视频流特征，绕开 WireGuard 指纹识别与非标端口上行限速。
- **双通道分离（零队头阻塞）**：
  - Moonlight 音视频 UDP 流 → **QUIC Unreliable Datagram (RFC 9221)**，不可靠、无重传阻塞、超低延迟。
  - SSH / Sunshine 控制信令 TCP 流 → **QUIC Stream**，可靠有序。
- **连接迁移 & 动态跳端口（Port Hopping）**：借助 QUIC 原生 Connection Migration，实现串流不断线的平滑换端口。
- **单文件跨平台**：Go 编写，一键交叉编译 Linux / Windows 单二进制文件，零驱动依赖（MVP 阶段无需管理员权限）。

---

## 项目结构

```text
quicbeam/
├── cmd/quicbeam/        # CLI 入口（server / client / probe）
├── internal/
│   ├── config/          # 配置加载与端口映射定义
│   ├── transport/       # QUIC (UDP 443) + RFC 9221 Datagram + TLS 1.3 传输层
│   ├── forward/         # TCP Stream 与 UDP Datagram 端口转发器（Moonlight/SSH）
│   └── signal/          # STUN 公网地址探测、极简信令交换与 Port Hopping
├── docs/
│   └── architecture.md  # 详细架构设计、DPI 威胁模型与实测背景
├── Makefile             # Linux / Windows 交叉编译快捷命令
├── AGENTS.md            # AI 编码代理开发指南与架构约束
├── LICENSE              # MIT License
└── go.mod
```

---

## 路线图（Roadmap）

- [ ] **Phase 0（链路验证）**：实现 `quicbeam probe`，实测江苏电信环境下 `UDP 443`（QUIC）是否与 `TCP 443` 一样享受满速上行；若 `UDP 443` 受限则评估 TLS-over-TCP 443 / FakeTCP 兜底。
- [ ] **Phase 1（MVP 直连隧道）**：基于 `quic-go` 实现 `server` / `client` 点对点连接，支持 TCP Stream（SSH）与 UDP Datagram（Sunshine `47998-48010`）转发。
- [ ] **Phase 2（自动穿透与跳端口）**：接入 STUN 探测、极简信令交换（如 Cloudflare Workers）与 QUIC Connection Migration Port Hopping。
- [ ] **Phase 3（可选 TUN 模式）**：集成 `wintun` / `/dev/net/tun` 实现全网段三层组网。

---

## 构建要求

- Go 1.24+

```bash
# 本地编译
make build

# 交叉编译 Windows 台式机端（amd64）
make build-windows
```

## License

[MIT](./LICENSE)
