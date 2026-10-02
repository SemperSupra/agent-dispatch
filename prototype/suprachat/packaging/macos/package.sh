#!/usr/bin/env bash
set -euo pipefail

SOURCE="${1:?publish directory required}"
DEST="${2:?destination package directory required}"
APP="$DEST/SupraChat.app"
MACOS="$APP/Contents/MacOS"
RESOURCES="$APP/Contents/Resources"

rm -rf "$DEST"
mkdir -p "$MACOS" "$RESOURCES"

# A valid macOS bundle keeps non-code payload out of Contents/MacOS.
# Materialize the self-contained publish under Resources, then move the two
# top-level executables into MacOS and retain the existing AppContext-relative
# runtime paths with portable relative symlinks.
cp -R "$SOURCE"/. "$RESOURCES"/

for executable in SupraChat SupraChat.Automation; do
  if [[ ! -f "$RESOURCES/$executable" ]]; then
    echo "Required packaged executable missing: $RESOURCES/$executable" >&2
    exit 1
  fi
  mv "$RESOURCES/$executable" "$MACOS/$executable"
done

for relative in .playwright runtime oracles docs build-info.json; do
  if [[ -e "$RESOURCES/$relative" ]]; then
    ln -s "../Resources/$relative" "$MACOS/$relative"
  fi
done

chmod +x "$MACOS/SupraChat" "$MACOS/SupraChat.Automation" "$RESOURCES/runtime/codex/codex"

# Package lifecycle helpers before the outer app is sealed. The installer must
# never add/remove files inside a signed app bundle after this point.
cat > "$RESOURCES/uninstall.sh" <<'UNINSTALL'
#!/usr/bin/env bash
set -euo pipefail
rm -f "${HOME}/.local/bin/suprachat-cli" "${HOME}/.local/bin/suprachat" "${HOME}/.local/bin/suprachat-gui"
rm -rf "${HOME}/Applications/SupraChat.app"
UNINSTALL
# Keep lifecycle scripts as sealed resource data, not executable nested code.
# Invoke them explicitly with /bin/bash after installation.
chmod 0644 "$RESOURCES/uninstall.sh"

# Playwright creates a hidden .links housekeeping directory in its browser
# registry. It is not required at runtime and should not enter the resource seal.
if [[ -d "$RESOURCES/runtime/browser/.links" ]]; then
  rm -rf "$RESOURCES/runtime/browser/.links"
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

# Sign packaged leaf code first. The main bundle executable is intentionally
# excluded here: signing CFBundleExecutable can cause codesign to seal the
# enclosing app before nested code/resources are ready.
while IFS= read -r -d '' file_path; do
  if file -b "$file_path" | grep -q 'Mach-O'; then
    codesign --force --sign - "$file_path"
  fi
done < <(find "$RESOURCES" -type f -print0)

# SupraChat.Automation is an auxiliary executable, not CFBundleExecutable.
codesign --force --sign - "$MACOS/SupraChat.Automation"

# Browser distributions contain real nested .app bundles. Seal them after
# their Mach-O members and before sealing SupraChat.app.
while IFS= read -r nested_app; do
  [[ "$nested_app" == "$APP" ]] && continue
  codesign --force --sign - "$nested_app"
  codesign --verify --strict "$nested_app"
done < <(find "$RESOURCES/runtime/browser" -type d -name '*.app' -print 2>/dev/null | awk '{ print length, $0 }' | sort -rn | cut -d' ' -f2-)

# Seal the outer app last; this signs the declared CFBundleExecutable and seals
# Resources in one authoritative signature.
codesign --force --sign - "$APP"
codesign --verify --strict "$APP"
plutil -lint "$APP/Contents/Info.plist"

# Bundle-shape invariants: regular non-code payload must not drift back into
# Contents/MacOS. Symlinks are intentional compatibility shims for existing
# AppContext-relative runtime paths.
for entry in "$MACOS"/* "$MACOS"/.[!.]*; do
  [[ -e "$entry" || -L "$entry" ]] || continue
  if [[ -L "$entry" ]]; then
    continue
  fi
  base="$(basename "$entry")"
  if [[ "$base" != "SupraChat" && "$base" != "SupraChat.Automation" ]]; then
    echo "Unexpected regular payload under Contents/MacOS: $entry" >&2
    exit 1
  fi
done
