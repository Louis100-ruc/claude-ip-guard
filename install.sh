#!/usr/bin/env bash
set -euo pipefail

# ClaudeIPGuard one-line installer for macOS (Apple Silicon & Intel)
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Louis100-ruc/claude-ip-guard/main/install.sh | bash

REPO="${CLAUDE_IP_GUARD_REPO:-Louis100-ruc/claude-ip-guard}"
APP_NAME="ClaudeIPGuard"
INSTALL_APP="/Applications/${APP_NAME}.app"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo ">>> 正在安装 ${APP_NAME}..."

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "错误：ClaudeIPGuard 仅支持 macOS 14+。" >&2
  exit 1
fi

# Stop existing process if running
pkill -x "$APP_NAME" >/dev/null 2>&1 || true

# Try downloading latest DMG from GitHub Releases first
DMG_URL=""
if [[ "$REPO" != "OWNER/claude-ip-guard" ]]; then
  DMG_URL="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
    | grep -Eo '"browser_download_url":[[:space:]]*"[^"]*\.dmg"' \
    | head -n 1 \
    | sed -E 's/.*"([^"]+)"/\1/' || true)"
fi

if [[ -n "$DMG_URL" ]]; then
  echo ">>> 正在从 GitHub Releases 下载安装包..."
  curl -fL "$DMG_URL" -o "$TMP_DIR/${APP_NAME}.dmg"
  MOUNT_POINT="$TMP_DIR/mnt"
  mkdir -p "$MOUNT_POINT"
  hdiutil attach "$TMP_DIR/${APP_NAME}.dmg" -nobrowse -quiet -mountpoint "$MOUNT_POINT"
  rm -rf "$INSTALL_APP"
  cp -R "$MOUNT_POINT/${APP_NAME}.app" "$INSTALL_APP"
  hdiutil detach "$MOUNT_POINT" -quiet || true
else
  echo ">>> 未找到预编译 Release，尝试从源码本地编译安装..."
  if ! command -v swiftc >/dev/null 2>&1; then
    echo "错误：需要安装 Xcode Command Line Tools（运行 xcode-select --install）。" >&2
    exit 1
  fi
  if [[ -f "./build.sh" && -d "./Sources" ]]; then
    ./build.sh --native-only --no-install
    rm -rf "$INSTALL_APP"
    cp -R "./build/${APP_NAME}.app" "$INSTALL_APP"
  elif [[ "$REPO" != "OWNER/claude-ip-guard" ]]; then
    git clone --depth 1 "https://github.com/${REPO}.git" "$TMP_DIR/src"
    (cd "$TMP_DIR/src" && ./build.sh --native-only --no-install)
    rm -rf "$INSTALL_APP"
    cp -R "$TMP_DIR/src/build/${APP_NAME}.app" "$INSTALL_APP"
  else
    echo "请设置 CLAUDE_IP_GUARD_REPO=<你的GitHub用户名>/claude-ip-guard 或在项目目录内运行此脚本。" >&2
    exit 1
  fi
fi

# Remove macOS Gatekeeper quarantine attribute so it opens smoothly
xattr -cr "$INSTALL_APP" >/dev/null 2>&1 || true
codesign --force --deep --sign - "$INSTALL_APP" >/dev/null 2>&1 || true

echo ">>> 安装完成：${INSTALL_APP}"
echo ">>> 正在启动 ${APP_NAME}..."
open "$INSTALL_APP"
echo ">>> 已启动！抬头查看顶部菜单栏，可在右下角 ⚙️ 菜单开启「开机自动启动」。"
