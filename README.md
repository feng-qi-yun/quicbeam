# QuicBeam

> 面向远程游戏串流（Moonlight / Sunshine）与 SSH 运维的 **超轻量抗 DPI / 抗 QoS P2P 隧道** —— 基于 **QUIC (HTTP/3, UDP 443) + RFC 9221 Unreliable Datagram**，专注**双端 NAT 打洞**与**协议伪装**，无需虚拟网卡（TUN）或管理员驱动。

## 为什么做 QuicBeam？

在部分国内家宽环境下，传统的 WireGuard / Tailscale 方案面临双重封锁：
1. **协议指纹动态黑洞**：运营商省网 DPI 识别标准 WireGuard 握手包（固定 148/92 字节与明文头）后，无论怎么更换高位端口，都会将对应 UDP 端口逐个拉黑（`udp=false`），迫使连接回退至高延迟海外中继。
2. **非标端口上行限速（反 PCDN QoS）**：实测江苏电信家宽下，标准 **`443` 端口（TCP/UDP）** 持续上行可达 **80~93 Mbps**，而非标端口（如 `8080`、WireGuard UDP）被硬性压死在 **~1.9 Mbps**。

**QuicBeam** 的定位极其聚焦——**以最轻量的方式替代 Tailscale 在 Moonlight / Sunshine 与 SSH 中的作用**（刻意不引入虚拟网卡 TUN）：
- **标准 `443` 端口 + 真 TLS 1.3 / QUIC (ALPN `h3`) 外壳**：天然融入主流 HTTP/3 流量特征，支持 **TLS 证书 SHA-256 指纹钉扎（`cert_sha256`）** 与 **PSK 双向鉴权**。
- **双通道严格分离（零队头阻塞）**：
  - Moonlight 音视频/控制 UDP 流 → **QUIC Unreliable Datagram (RFC 9221)**，内置超长包（如 1408B LAN 视频帧）无阻塞不可靠分片重组。
  - SSH / Sunshine 控制信令 TCP 流 → **QUIC Stream**，可靠有序，支持出口目标白名单（默认仅放行本机回环）。
- **双端 Cone NAT 打洞 & 可选无感跳端口（Port Hopping）**：
  - 基于 RFC 7983 首字节复用，在**同一 UDP Socket** 上并发完成 STUN 探测、AES-256-GCM 密文信令交换、双向 UDP 打洞与 QUIC 握手；
  - 支持依托 QUIC 原生 Connection Migration（Make-Before-Break）的定时换源端口（默认关闭 `port_hop_interval_sec: 0`）。
- **单文件跨平台（Linux / Windows / macOS / Android Termux）**：纯 Go（`CGO_ENABLED=0`），零外部驱动，免 Root。

---

## 快速上手

### 1. 构建

要求 Go 1.24+：

```bash
make build              # Linux 本机 -> bin/quicbeam
make build-windows      # Windows amd64 -> bin/quicbeam.exe
make build-macos        # macOS Apple Silicon (arm64) -> bin/quicbeam-darwin-arm64
make build-macos-amd64  # macOS Intel (amd64) -> bin/quicbeam-darwin-amd64
make build-android      # Android (Termux) arm64 -> bin/quicbeam-android-arm64
make test               # 全量单元测试（含 -race 竞争检测）
```

### 2. 生成自签证书、指纹与随机 PSK

```bash
./bin/quicbeam keygen -out-dir ./certs -sni www.cloudflare.com
```

输出会直接给出服务端 `cert_file` / `key_file`，以及客户端可直接填入的 `cert_sha256` 指纹与 32 字节随机 `psk`（无需买域名，也不必开启 `insecure_skip_verify`）。

### 3. 链路吞吐探测与 STUN 诊断

```bash
# 查看当前机器公网 IPv4（STUN）与原生全局 IPv6
./bin/quicbeam stun

# 实测 UDP 443 持续 15 秒上行带宽（Stream 天花板 / RFC 9221 Datagram 60Mbps）
./bin/quicbeam probe -server -listen :443
./bin/quicbeam probe -remote <server_ip>:443 -proto stream -dir upload -duration 15s -insecure
./bin/quicbeam probe -remote <server_ip>:443 -proto datagram -dir upload -rate 60 -payload 1150 -duration 15s -insecure
```

### 4. 启动隧道（支持正向直连、反向拨号与双端打洞）

参考 [configs/moonlight.example.json](./configs/moonlight.example.json) 编写服务端与客户端配置（注意：`server` / `client` 传输角色与转发方向完全解耦，任意一端配置 `forwards` 即可监听本地端口并转发到对端）：

```bash
# 服务端（监听 UDP 443，可选开启 STUN + 加密信令发布与打洞）
./bin/quicbeam server -config server.json

# 客户端（拨号对端，支持 cert_sha256 钉扎、动态信令发现、NAT 打洞与可选 Port Hopping）
./bin/quicbeam client -config client.json
```

打开 **Moonlight**（Linux / Windows / Android）手动添加主机 **`127.0.0.1`**，即可经 `UDP 443` QUIC Datagram 串流。

> **关于 `port_hop_interval_sec` 的重要避坑说明**：默认值为 `0`（关闭），**在按四元组识别 TLS ClientHello 放行 443 白名单的国内家宽线路（如江苏电信）上请保持关闭**。实测 QUIC 原生 Connection Migration（`path.Switch()`）切换到新源端口后不再发送 QUIC Initial / TLS 1.3 ClientHello，仅发 1-RTT 短头密文，会导致新四元组被运营商 QoS 识别为未知 UDP 并锁死在 **~2 Mbps**（而保持完整 `h3` 握手的原四元组可稳跑 **86+ Mbps**）。
>
> 如需动态 IP 自动追踪与双端 NAT 打洞，可将 [deploy/cf-worker-signal.js](./deploy/cf-worker-signal.js) 部署到 Cloudflare Workers（绑定 KV 命名空间 `QUICBEAM_KV`），信令端仅存储由 `PSK` 派生的 AES-256-GCM 密文。

---

## 项目结构

```text
quicbeam/
├── cmd/quicbeam/            # CLI 入口（server / client / probe / stun / keygen）
├── internal/
│   ├── config/              # JSON 配置加载、默认值、校验与出口目标白名单
│   ├── transport/           # QUIC (UDP 443) + TLS 1.3 指纹钉扎 + Make-Before-Break 连接迁移
│   ├── forward/             # TCP Stream + RFC 9221 UDP Datagram 转发、不可靠分片与运行统计
│   ├── probe/               # UDP 443 Datagram / Stream 逐秒吞吐与丢包基准探测
│   └── signal/              # 纯 Go RFC 5389 STUN、AES-256-GCM 加密信令与 RFC 7983 同 Socket 打洞
├── configs/
│   └── moonlight.example.json
├── deploy/
│   └── cf-worker-signal.js  # Cloudflare Workers + KV 极简密文信令脚本
├── docs/
│   └── architecture.md      # 详细架构设计、DPI 威胁模型与实测数据
├── Makefile
├── AGENTS.md
└── go.mod
```

---

## 路线图（Roadmap）

- [x] **Phase 0（链路验证）**：实现 `quicbeam probe`，在江苏电信家宽实测 `UDP 443` QUIC Stream 15s 稳跑 **93.4 Mbps**、RFC 9221 Datagram 60 Mbps 15s **0.00% 丢包**（握手 ~12ms）。
- [x] **Phase 1（MVP 对称直连隧道）**：实现 `server` / `client` 点对点隧道，支持 TCP Stream（SSH / Sunshine 控制）与 RFC 9221 UDP Datagram（Moonlight 音视频/输入 + 超长包不可靠分片），已实机跑通 Moonlight 串流与 SSH。
- [x] **Phase 2（自动穿透、打洞与跳端口）**：实现纯 Go STUN + IPv6 探测、AES-256-GCM 加密信令、RFC 7983 同 Socket 双端 Cone NAT 打洞、QUIC Make-Before-Break Port Hopping、TLS `cert_sha256` 指纹钉扎、`keygen` 与出口目标白名单。

## License

[MIT](./LICENSE)
