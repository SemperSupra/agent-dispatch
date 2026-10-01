#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
SOURCE="$ROOT/SupraChat.app"
DEST="${HOME}/Applications/SupraChat.app"
BIN="${HOME}/.local/bin"
if [[ ! -d "$SOURCE" ]]; then echo "SupraChat.app is missing beside install.sh" >&2; exit 2; fi
mkdir -p "${HOME}/Applications" "$BIN"
rm -rf "$DEST"
cp -R "$SOURCE" "$DEST"
ln -sfn "$DEST/Contents/MacOS/SupraChat.Automation" "$BIN/suprachat-cli"
ln -sfn "$DEST/Contents/MacOS/SupraChat.Automation" "$BIN/suprachat"
ln -sfn "$DEST/Contents/MacOS/SupraChat" "$BIN/suprachat-gui"
cat > "$DEST/Contents/Resources-uninstall.sh" <<'UNINSTALL'
#!/usr/bin/env bash
set -euo pipefail
rm -f "${HOME}/.local/bin/suprachat-cli" "${HOME}/.local/bin/suprachat" "${HOME}/.local/bin/suprachat-gui"
rm -rf "${HOME}/Applications/SupraChat.app"
UNINSTALL
chmod +x "$DEST/Contents/Resources-uninstall.sh"
echo "Installed SupraChat.app to $DEST"
echo "Automation/agent CLI: $BIN/suprachat-cli"
echo "GUI launcher: $BIN/suprachat-gui"
echo "Ensure $BIN is on PATH for shell use."
