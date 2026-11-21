# ClaudeIPGuard

轻量级 macOS 原生菜单栏工具（SwiftUI + AppKit），实时监控 **Claude AI 全维度网络封控指标**，支持桌面常驻悬浮窗、节点切换即时检测、高危系统通知预警以及本地 HTTP JSON 接口。

> 适用于 macOS 14+（Universal 通用版，原生支持 Apple Silicon 与 Intel 芯片，零第三方运行依赖）。

---

## 核心监控指标（9 大维度）

1. **Claude 实际出口地区**：直测 `claude.ai/cdn-cgi/trace`，校验是否处于 Anthropic 支持地区。
2. **DNS 泄露检测**：随机子域名直测 `edns.ip-api.com`，识别中国大陆运营商 DNS 泄露与跨区解析。
3. **IPv6 泄露检测**：独立探测 IPv6 出口，防止本地宽带双栈裸奔暴露真实地区。
4. **UDP / WebRTC（STUN）泄露检测**：发送原生 RFC 5389 UDP STUN 请求，排查因分流规则放行 STUN 导致的本地公网 IP 泄露。
5. **Anthropic 全站路由一致性**：对比 `claude.ai`、`api.anthropic.com` 与 `1.1.1.1` 出口 IP，防止网页端与 API 端跨国分叉。
6. **双引擎 IP 风险分与匿名标记**：交叉查询 `ipquery.io` + `proxycheck.io` + `ip-api.com`，提供 `0–100` 风险分、`VPN / Proxy / Tor / 机房` 标记及 rDNS 反向解析。
7. **出口 IP 稳定性监控**：监测未切节点情况下的动态 IP 自动漂移与异常跨国跳变。
8. **时区偏差提示**：自动比对 macOS 本机时区与出口 IP 归属时区。
9. **高危红线系统通知**：后台检测到泄露、不支持地区或高风险时自动推送 macOS 系统通知。

## 交互与联动特性

- **菜单栏常驻**：支持「简洁（地区 + 状态）」与「完整（地区 + IP）」两种显示样式，点击展开完整毛玻璃体检卡片。
- **可切换桌面悬浮窗**：点击右上角「📌」钉在桌面角落，自动记住位置，支持置顶开关。
- **零流量代理联动**：自动适配 Clash Verge Rev（Unix Socket）及常见 Clash / Mihomo 本地控制端口（`9097 / 9090 / 29090`），切换节点或 Wi-Fi 变动后 1 秒内自动重测；使用其他代理软件（如 Surge 等）时全部 9 项检测同样正常工作。
- **红/黄警报一键生成 AI 修复 Prompt**：一旦检测到风险或高危警报（如 DNS/IPv6/STUN 泄露、不支持地区、高风险机房节点、IP 漂移等），卡片自动弹出与警报等级对应的「✨ 复制 Prompt」按钮，按当前具体故障生成包含实时数据快照、Clash Verge 节点/配置排查方向与自动复测验收指令的专属 Prompt，直接粘贴给 AI 助手即可一键修复。
- **内置开机自启开关**：在右下角 ⚙️ 菜单一键开关「开机自动启动」。

---

## 安装方式

### 方式一：下载 `.dmg` 拖拽安装（推荐）

1. 前往本仓库右侧 **Releases** 页面下载最新 `ClaudeIPGuard-v*-macOS-Universal.dmg`。
2. 双击打开 `.dmg`，将 `ClaudeIPGuard.app` 拖入 **Applications（应用程序）**。
3. **首次打开若 macOS 提示“已损坏”或“无法验证开发者”**（开源应用未购买 Apple 付费公证的正常现象），打开终端执行一次以下命令即可放行：
   ```bash
   xattr -cr /Applications/ClaudeIPGuard.app && open /Applications/ClaudeIPGuard.app
   ```

### 方式二：一行命令自动安装（自动解除隔离）

在终端执行：

```bash
curl -fsSL https://raw.githubusercontent.com/Louis100-ruc/claude-ip-guard/main/install.sh | bash
```

### 方式三：本地从源码编译打包

```bash
git clone https://github.com/Louis100-ruc/claude-ip-guard.git
cd claude-ip-guard

# 编译并安装到 ~/Applications/ClaudeIPGuard.app
./build.sh

# 或打包通用版 .dmg 安装包（输出在 dist/ 目录）
./package-dmg.sh
```

---

## 本地 HTTP JSON 接口

应用启动后默认仅在 `127.0.0.1:17899` 监听本地接口（不对外网暴露），方便接入 Raycast、SwiftBar、脚本或状态栏工具：

| 接口 | 说明 |
| :--- | :--- |
| `GET http://127.0.0.1:17899/api/status` | 获取最新完整体检 JSON |
| `GET http://127.0.0.1:17899/api/refresh` | 立即触发一次新检测并返回 JSON |
| `GET http://127.0.0.1:17899/api/fix-prompt` | 获取针对当前状态生成的 AI 修复 Prompt（加 `?format=json` 返回 JSON） |
| `GET http://127.0.0.1:17899/health` | 健康检查 |

```bash
curl -s --noproxy 127.0.0.1 http://127.0.0.1:17899/api/status
```

## License

[MIT](./LICENSE)
