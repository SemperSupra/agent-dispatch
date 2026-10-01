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

# Playwright creates a hidden .links housekeeping directory in its browser registry.
# It is not required to launch the pinned browser, but codesign --deep interprets it
# as an invalid nested bundle/subcomponent when it lives inside Contents/MacOS.
if [[ -d "$MACOS/runtime/browser/.links" ]]; then
  rm -rf "$MACOS/runtime/browser/.links"
fi

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

# Sign inside-out. Avoid --deep on the outer app: Microsoft.Playwright ships
# housekeeping/runtime directories (for example .playwright) that are not bundles
# and must not be reinterpreted as nested bundles by codesign.
while IFS= read -r -d '' file_path; do
  if file -b "$file_path" | grep -q 'Mach-O'; then
    codesign --force --sign - "$file_path"
    codesign --verify --strict "$file_path"
  fi
done < <(find "$APP/Contents/MacOS" -type f -print0)

# Browser distributions may contain real nested .app bundles; sign those as
# bundles after their Mach-O members and before sealing SupraChat.app.
while IFS= read -r nested_app; do
  [[ "$nested_app" == "$APP" ]] && continue
  codesign --force --sign - "$nested_app"
  codesign --verify --strict "$nested_app"
done < <(find "$APP/Contents/MacOS/runtime/browser" -type d -name '*.app' -print 2>/dev/null | awk '{ print length, $0 }' | sort -rn | cut -d' ' -f2-)

codesign --force --sign - "$APP"
codesign --verify --strict "$APP"
plutil -lint "$APP/Contents/Info.plist"
