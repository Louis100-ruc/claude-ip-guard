#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="ClaudeIPGuard"
VERSION="2.1.1"
BUILD_DIR="$PROJECT_DIR/build"
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"
INSTALL_DIR="$HOME/Applications"
INSTALL_APP="$INSTALL_DIR/$APP_NAME.app"

INSTALL_FLAG=1
UNIVERSAL_FLAG=1
for arg in "$@"; do
  case "$arg" in
    --no-install) INSTALL_FLAG=0 ;;
    --native-only) UNIVERSAL_FLAG=0 ;;
  esac
done

rm -rf "$APP_BUNDLE" "$BUILD_DIR/icon.iconset" "$BUILD_DIR/icon_1024.png"
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"

# Generate AppIcon.icns
if command -v swift >/dev/null 2>&1 && command -v iconutil >/dev/null 2>&1 && command -v sips >/dev/null 2>&1; then
  swift "$PROJECT_DIR/scripts/make-icon.swift" "$BUILD_DIR/icon_1024.png"
  ICONSET="$BUILD_DIR/icon.iconset"
  mkdir -p "$ICONSET"
  for sz in 16 32 128 256 512; do
    sips -z "$sz" "$sz" "$BUILD_DIR/icon_1024.png" --out "$ICONSET/icon_${sz}x${sz}.png" >/dev/null
    sz2=$((sz * 2))
    sips -z "$sz2" "$sz2" "$BUILD_DIR/icon_1024.png" --out "$ICONSET/icon_${sz}x${sz}@2x.png" >/dev/null
  done
  iconutil -c icns "$ICONSET" -o "$APP_BUNDLE/Contents/Resources/AppIcon.icns"
  rm -rf "$ICONSET" "$BUILD_DIR/icon_1024.png"
fi

cat > "$APP_BUNDLE/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>zh_CN</string>
    <key>CFBundleExecutable</key>
    <string>${APP_NAME}</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>com.claudeipguard.app</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>${APP_NAME}</string>
    <key>CFBundleDisplayName</key>
    <string>${APP_NAME}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleVersion</key>
    <string>21</string>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
</dict>
</plist>
EOF

SOURCES=(
  "$PROJECT_DIR/Sources/Models.swift"
  "$PROJECT_DIR/Sources/ClashSocketClient.swift"
  "$PROJECT_DIR/Sources/IPChecker.swift"
  "$PROJECT_DIR/Sources/LocalHTTPServer.swift"
  "$PROJECT_DIR/Sources/MonitorStore.swift"
  "$PROJECT_DIR/Sources/StatusCardView.swift"
  "$PROJECT_DIR/Sources/AppDelegate.swift"
  "$PROJECT_DIR/Sources/main.swift"
)

COMMON_FLAGS=(
  -O
  -swift-version 5
  -framework AppKit
  -framework SwiftUI
  -framework Network
  -framework Combine
)

if [[ "$UNIVERSAL_FLAG" -eq 1 ]]; then
  echo "Compiling $APP_NAME (Universal: arm64 + x86_64)..."
  swiftc "${COMMON_FLAGS[@]}" -target arm64-apple-macosx14.0 "${SOURCES[@]}" -o "$BUILD_DIR/${APP_NAME}_arm64"
  swiftc "${COMMON_FLAGS[@]}" -target x86_64-apple-macosx14.0 "${SOURCES[@]}" -o "$BUILD_DIR/${APP_NAME}_x86_64"
  lipo -create "$BUILD_DIR/${APP_NAME}_arm64" "$BUILD_DIR/${APP_NAME}_x86_64" -output "$APP_BUNDLE/Contents/MacOS/$APP_NAME"
  rm -f "$BUILD_DIR/${APP_NAME}_arm64" "$BUILD_DIR/${APP_NAME}_x86_64"
else
  ARCH="$(uname -m)"
  echo "Compiling $APP_NAME ($ARCH)..."
  swiftc "${COMMON_FLAGS[@]}" -target "${ARCH}-apple-macosx14.0" "${SOURCES[@]}" -o "$APP_BUNDLE/Contents/MacOS/$APP_NAME"
fi

codesign --force --deep --sign - "$APP_BUNDLE" >/dev/null 2>&1 || true

if [[ "$INSTALL_FLAG" -eq 1 ]]; then
  mkdir -p "$INSTALL_DIR"
  rm -rf "$INSTALL_APP"
  cp -R "$APP_BUNDLE" "$INSTALL_APP"
  echo "Built and installed to: $INSTALL_APP"
else
  echo "Built app bundle at: $APP_BUNDLE"
fi
