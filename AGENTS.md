# AGENTS.md — QuicBeam 开发指南

本文件面向参与 `quicbeam` 开发的 AI Agent 与开发者，明确项目目标、不可妥协的协议约束及工程规范。

---

## 1. 项目定位

`quicbeam` 是一个轻量级、跨平台（Linux / Windows）的 **P2P 抗 DPI / 抗 QoS 隧道**，核心场景是**校园网笔记本 ↔ 家庭台式机的 Moonlight/Sunshine 远程串流与 SSH 运维**。

详细背景、运营商实测数据与四层架构见 [`docs/architecture.md`](./docs/architecture.md)。

---

## 2. 核心架构约束（红线）

1. **严禁将视频 UDP 流封装在可靠 TCP / QUIC Stream 中**：
   - Moonlight/Sunshine 自带 FEC 与丢帧恢复，对队头阻塞（Head-of-Line Blocking）极度敏感。
   - **所有 UDP 转发流量必须走 QUIC Unreliable Datagram（RFC 9221，`SendDatagram` / `ReceiveDatagram`）**；仅 TCP 转发流量（SSH、Sunshine HTTP/RTSP 控制流）走 QUIC Stream。
2. **默认伪装与端口策略**：
   - 必须使用标准 **TLS 1.3 + QUIC**（支持配置真实域名/自签证书与 `h3` ALPN），优先使用标准 **`443` 端口**（实测该线路仅 443 端口享受满速上行，非标端口会被压到 ~2 Mbps）。
   - 绝不自行发明对称/非对称加密原语；所有加密依赖标准 TLS 1.3 或 Noise Protocol 成熟库。
3. **MTU 与分片意识**：
   - QUIC Datagram 单包载荷上限受路径 MTU（通常 1200~1280 字节）限制；转发层需确保能承载 Moonlight 默认包大小，避免静默丢包，必要时在配置与日志中显式告警 `MaxDatagramSize`。
4. **Windows / Linux 跨平台兼容**：
   - 尽量保持纯 Go 实现（`CGO_ENABLED=0`），确保在 Linux 笔记本上执行 `GOOS=windows GOARCH=amd64 go build` 即可直接产出台式机可执行文件。
   - 任何涉及台式机远程部署的脚本必须注意 Windows PowerShell 5.1 编码（优先纯 ASCII 或 UTF-8 without BOM）与 SSH 会话退出时子进程生命周期问题。

---

## 3. 目录职责

- `cmd/quicbeam/`：仅放 CLI 参数解析与子命令组装（`server` / `client` / `probe`），不放核心业务逻辑。
- `internal/config/`：配置结构体定义、默认值与校验；禁止在仓库提交真实公网 IP、私钥、证书或 PSK。
- `internal/transport/`：QUIC Listener / Dialer、TLS 配置、Datagram 收发封装与连接迁移（Connection Migration）。
- `internal/forward/`：本地端口监听与远端目标转发（UDP Datagram 映射 + TCP Stream 映射）。
- `internal/signal/`：STUN 地址探测、极简信令客户端、NAT 打洞与 Port Hopping 调度。

---

## 4. 常用命令

```bash
go test ./...              # 运行全部单元测试
make build                 # 编译当前平台二进制到 bin/quicbeam
make build-windows         # 交叉编译 Windows amd64 到 bin/quicbeam.exe
```

## 5. 代码与提交规范

- 保持包边界清晰，`internal/` 下各包避免循环依赖（依赖方向：`cmd` → `forward` / `signal` → `transport` → `config`）。
- 敏感文件（`*.key`、`*.pem`、`config.local.*`）已在 `.gitignore` 中排除，提交前务必检查 `git status`。
- 关键网络路径（握手耗时、当前使用端口、Datagram MTU、切换/重连事件）必须有清晰的结构化日志，方便远程排障。

## 来自作者的提醒
1. commitmessage 要满足conventional规范
