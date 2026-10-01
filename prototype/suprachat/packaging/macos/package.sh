#!/usr/bin/env bash
set -euo pipefail

SOURCE="${1:?publish directory required}"
DEST="${2:?destination package directory required}"
APP="$DEST/SupraChat.app"
MACOS="$APP/Contents/MacOS"

rm -rf "$DEST"
mkdir -p "$MACOS"
cp -R "$SOURCE"/. "$MACOS"/
chmod +x "$MACOS/SupraChat" "$MACOS/SupraChat.Automation" "$MACOS/runtime/codex/codex"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleDisplayName</key><string>SupraChat</string>
  <key>CFBundleExecutable</key><string>SupraChat</string>
  <key>CFBundleIdentifier</key><string>com.sempersupra.suprachat</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>SupraChat</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>CFBundleURLTypes</key>
  <array><dict><key>CFBundleURLName</key><string>SupraChat</string><key>CFBundleURLSchemes</key><array><string>suprachat</string></array></dict></array>
  <key>CFBundleDocumentTypes</key>
  <array><dict>
    <key>CFBundleTypeName</key><string>SupraChat Attachments</string>
    <key>CFBundleTypeRole</key><string>Editor</string>
    <key>LSHandlerRank</key><string>Alternate</string>
    <key>CFBundleTypeExtensions</key>
    <array>
      <string>png</string><string>jpg</string><string>jpeg</string><string>webp</string><string>gif</string>
      <string>pdf</string><string>txt</string><string>md</string><string>json</string><string>csv</string><string>tsv</string>
      <string>html</string><string>htm</string><string>xml</string><string>rtf</string><string>odt</string>
      <string>doc</string><string>docx</string><string>ppt</string><string>pptx</string><string>xls</string><string>xlsx</string>
    </array>
  </dict></array>
</dict>
</plist>
PLIST

codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict "$APP"
plutil -lint "$APP/Contents/Info.plist"
