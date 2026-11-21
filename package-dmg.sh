#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="ClaudeIPGuard"
VERSION="2.2.0"
BUILD_DIR="$PROJECT_DIR/build"
DIST_DIR="$PROJECT_DIR/dist"
STAGING_DIR="$BUILD_DIR/dmg-staging"
DMG_PATH="$DIST_DIR/${APP_NAME}-v${VERSION}-macOS-Universal.dmg"

"$PROJECT_DIR/build.sh" --no-install

rm -rf "$STAGING_DIR" "$DMG_PATH"
mkdir -p "$STAGING_DIR" "$DIST_DIR"

cp -R "$BUILD_DIR/${APP_NAME}.app" "$STAGING_DIR/"
ln -s /Applications "$STAGING_DIR/Applications"

cat > "$STAGING_DIR/首次打开提示说明.txt" << 'EOF'
ClaudeIPGuard 安装说明（macOS 14+，支持 Apple Silicon 与 Intel 芯片）
===================================================================

1. 将 ClaudeIPGuard.app 拖入右侧的 Applications（应用程序）文件夹。
2. 首次打开若 macOS 提示“无法验证开发者”或“已损坏”（开源软件未购买 Apple 付费公证的正常现象）：
   - 方法 A（推荐，一行命令解除隔离）：打开「终端」，粘贴执行：
       xattr -cr /Applications/ClaudeIPGuard.app && open /Applications/ClaudeIPGuard.app
   - 方法 B：打开「系统设置 → 隐私与安全性」，拉到底部点击「仍要打开」。
3. 启动后抬头看 Mac 顶部菜单栏即可看到实时状态；点击右下角 ⚙️ 菜单可一键开启「开机自动启动」。
EOF

echo "Creating DMG at $DMG_PATH..."
hdiutil create \
  -volname "$APP_NAME $VERSION" \
  -srcfolder "$STAGING_DIR" \
  -ov \
  -format UDZO \
  "$DMG_PATH" >/dev/null

rm -rf "$STAGING_DIR"
echo "DMG ready: $DMG_PATH"
ls -lh "$DMG_PATH"
