#!/usr/bin/env bash
set -euo pipefail
SOURCE="$(cd "$(dirname "$0")" && pwd)"
DEST="${HOME}/.local/opt/suprachat"
BIN="${HOME}/.local/bin"
APPS="${HOME}/.local/share/applications"
DESKTOP="$APPS/suprachat.desktop"
mkdir -p "$DEST" "$BIN" "$APPS"
rm -rf "$DEST"
mkdir -p "$DEST"
cp -R "$SOURCE"/. "$DEST"/
rm -f "$DEST/install.sh"
chmod +x "$DEST/SupraChat" "$DEST/SupraChat.Automation" "$DEST/runtime/codex/codex"
ln -sfn "$DEST/SupraChat.Automation" "$BIN/suprachat-cli"
ln -sfn "$DEST/SupraChat.Automation" "$BIN/suprachat"
ln -sfn "$DEST/SupraChat" "$BIN/suprachat-gui"
cat > "$DESKTOP" <<EOF
[Desktop Entry]
Type=Application
Name=SupraChat
Comment=ChatGPT parity client and agent runtime
Exec=${DEST}/SupraChat %U
Terminal=false
Categories=Network;Utility;
MimeType=x-scheme-handler/suprachat;application/pdf;text/plain;text/markdown;application/json;text/csv;image/png;image/jpeg;image/webp;image/gif;
StartupNotify=true
EOF
if command -v xdg-mime >/dev/null 2>&1; then xdg-mime default suprachat.desktop x-scheme-handler/suprachat || true; fi
if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database "$APPS" >/dev/null 2>&1 || true; fi
cat > "$DEST/uninstall.sh" <<'UNINSTALL'
#!/usr/bin/env bash
set -euo pipefail
rm -f "${HOME}/.local/bin/suprachat-cli" "${HOME}/.local/bin/suprachat" "${HOME}/.local/bin/suprachat-gui"
rm -f "${HOME}/.local/share/applications/suprachat.desktop"
rm -rf "${HOME}/.local/opt/suprachat"
UNINSTALL
chmod +x "$DEST/uninstall.sh"
echo "Installed SupraChat to $DEST"
echo "Desktop entry: $DESKTOP"
echo "Automation/agent CLI: $BIN/suprachat-cli"
echo "GUI launcher: $BIN/suprachat-gui"
echo "Ensure $BIN is on PATH for shell use."
