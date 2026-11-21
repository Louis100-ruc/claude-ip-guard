# ClaudeIPGuard

轻量级 **macOS / Windows 原生托盘实时监控工具**，全方位监控 **Claude AI 网络封控指标**，支持桌面常驻悬浮窗、节点切换即时检测、红/黄警报一键生成 AI 修复 Prompt、高危系统通知预警以及本地 HTTP JSON 接口。

> - **macOS 版**：原生 SwiftUI + AppKit，Universal 通用版（支持 Apple Silicon 与 Intel，macOS 14+），零依赖。
> - **Windows 版**：原生 C# WPF（基于 Windows 10/11 内置 `.NET Framework 4.8`），单文件 `.exe`（不到 200 KB），双击即用，零依赖。

---

## 核心监控指标（9 大维度）

1. **Claude 实际出口地区**：直测 `claude.ai/cdn-cgi/trace`，校验是否处于 Anthropic 支持地区。
2. **DNS 泄露检测**：随机子域名直测 `edns.ip-api.com`（含自动重试），识别中国大陆运营商 DNS 泄露与跨区解析；检测失败立即亮黄灯预警。
3. **IPv6 泄露检测**：独立探测 IPv6 出口，防止本地宽带双栈裸奔暴露真实地区。
4. **UDP / WebRTC（STUN）泄露检测**：发送原生 RFC 5389 UDP STUN 请求，排查因分流规则放行 STUN 导致的本地公网 IP 泄露。
5. **Anthropic 全站路由一致性**：对比 `claude.ai`、`api.anthropic.com` 与 `1.1.1.1` 出口 IP，防止网页端与 API 端跨国分叉。
6. **双引擎 IP 风险分与匿名标记**：交叉查询 `ipquery.io` + `proxycheck.io` + `ip-api.com`，提供 `0–100` 风险分、`VPN / Proxy / Tor / 机房` 标记及 rDNS 反向解析。
7. **出口 IP 稳定性监控**：监测未切节点情况下的动态 IP 自动漂移与异常跨国跳变。
8. **时区偏差提示**：自动比对本机时区与出口 IP 归属时区。
9. **高危红线系统通知**：后台检测到泄露、不支持地区或高风险时自动推送系统通知。

## 交互与联动特性

- **红/黄警报一键生成 AI 修复 Prompt**：出现风险或高危警报时，弹窗自动出现对应配色的「✨ 复制 Prompt」行动条，按当前具体故障生成专属诊断与修复提示词（含 Clash Verge 节点/配置排查指引与自动复测命令），粘贴给任意 AI 助手即可一键修复。
- **常驻菜单栏 / 系统托盘 + 桌面悬浮窗**：支持点击「📌」钉在桌面角落拖动放置，支持始终置顶开关。
- **零流量代理联动**：自动适配 Clash Verge Rev（macOS Unix Socket / Windows Named Pipe `verge-mihomo`）及常见 Clash / Mihomo 控制端口（`9097 / 9090 / 29090`），切换节点或网络变动后 1 秒内自动重测；使用其他代理软件时全部 9 项检测同样生效。
- **内置开机自启开关**：在右下角 ⚙️ 菜单一键开关「开机自动启动」。

---

## 安装方式

### Windows（Windows 10 / 11）

1. 前往本仓库右侧 **[Releases](https://github.com/Louis100-ruc/claude-ip-guard/releases)** 页面，下载最新 `ClaudeIPGuard-v*-Windows-x64.exe`。
2. 放到任意固定文件夹，**直接双击运行**（无需安装 Python / Node / .NET 运行时）。
   - 若首次打开弹出 Windows SmartScreen「已保护你的电脑」提示（开源软件未购买付费代码签名证书的正常现象），点击 **「更多信息」 → 「仍要运行」** 即可。
3. 运行后在任务栏右下角系统托盘即可看到红/黄/绿实时状态圆点；左键点击展开卡片，右键打开快捷菜单，点击面板右下角 ⚙️ 可一键开启「开机自动启动」。

#### 本地自行编译 Windows 版（需安装 .NET SDK）
```powershell
./windows/build-win.ps1
```

---

### macOS（macOS 14+，Apple Silicon & Intel 通用）

#### 方式一：一行命令自动安装（最省心，自动解除未公证拦截）

```bash
curl -fsSL https://raw.githubusercontent.com/Louis100-ruc/claude-ip-guard/main/install.sh | bash
```

#### 方式二：下载 `.dmg` 拖拽安装

1. 前往 **[Releases](https://github.com/Louis100-ruc/claude-ip-guard/releases)** 下载最新 `ClaudeIPGuard-v*-macOS-Universal.dmg`。
2. 双击打开并将 `ClaudeIPGuard.app` 拖入 **Applications（应用程序）**。
3. 若首次打开提示“已损坏”或“无法验证开发者”，在终端执行一次：
   ```bash
   xattr -cr /Applications/ClaudeIPGuard.app && open /Applications/ClaudeIPGuard.app
   ```

#### 方式三：本地从源码编译打包

```bash
git clone https://github.com/Louis100-ruc/claude-ip-guard.git
cd claude-ip-guard

# 编译并安装到 ~/Applications/ClaudeIPGuard.app
./build.sh

# 或打包通用版 .dmg 安装包（输出在 dist/ 目录）
./package-dmg.sh
```

---

## 本地 HTTP JSON 接口（macOS 与 Windows 通用）

应用启动后默认仅在 `127.0.0.1:17899` 监听本地接口（不对外网暴露），方便接入脚本、状态栏工具或 AI Agent 自动验收：

| 接口 | 说明 |
| :--- | :--- |
| `GET http://127.0.0.1:17899/api/status` | 获取最新完整体检 JSON |
| `GET http://127.0.0.1:17899/api/refresh` | 立即触发一次新检测并返回 JSON |
| `GET http://127.0.0.1:17899/api/fix-prompt` | 获取针对当前状态生成的 AI 修复 Prompt（加 `?format=json` 返回 JSON） |
| `GET http://127.0.0.1:17899/health` | 健康检查 |

```bash
# macOS / Linux
curl -s --noproxy 127.0.0.1 http://127.0.0.1:17899/api/status

# Windows PowerShell
curl.exe -s --noproxy 127.0.0.1 http://127.0.0.1:17899/api/status
```

## License

[MIT](./LICENSE)
