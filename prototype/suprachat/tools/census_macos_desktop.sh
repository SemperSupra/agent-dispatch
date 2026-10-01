#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${GITHUB_WORKSPACE:-$PWD}"
OUT="$ROOT_DIR/out/desktop-oracle/macos"
WORK="${RUNNER_TEMP:-/tmp}/suprachat-macos-census-$$"
mkdir -p "$OUT" "$WORK"
trap 'rm -rf "$WORK"' EXIT

urls=(
  "https://persistent.oaistatic.com/codex-app-prod/ChatGPT.dmg"
  "https://persistent.oaistatic.com/codex-app-prod/ChatGPT-latest-x64.dmg"
  "https://persistent.oaistatic.com/classic/public/ChatGPT_Classic.dmg"
)

index=0
for url in "${urls[@]}"; do
  index=$((index+1))
  dmg="$WORK/app-$index.dmg"
  curl --proto '=https' --tlsv1.2 -fL --retry 3 "$url" -o "$dmg"
  dmg_sha="$(shasum -a 256 "$dmg" | awk '{print $1}')"
  dmg_size="$(stat -f %z "$dmg")"

  attach="$WORK/attach-$index.txt"
  hdiutil attach -nobrowse -readonly "$dmg" | tee "$attach"
  volume="$(awk -F '\t' '$3 ~ /^\/Volumes\// {print $3}' "$attach" | tail -n1)"
  if [ -z "$volume" ]; then
    echo "Unable to locate mounted volume for $url" >&2
    exit 20
  fi
  source_app="$(find "$volume" -maxdepth 2 -type d -name '*.app' -print -quit)"
  if [ -z "$source_app" ]; then
    hdiutil detach "$volume" || true
    echo "No app bundle found in $url" >&2
    exit 21
  fi

  app="$WORK/App-$index.app"
  ditto "$source_app" "$app"
  hdiutil detach "$volume"

  plist="$app/Contents/Info.plist"
  bundle_id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$plist")"
  version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$plist")"
  build="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$plist")"
  label="$(printf '%s-%s-%s' "$bundle_id" "$version" "$index" | tr '/ :' '---')"
  census="$OUT/$label"
  mkdir -p "$census"

  codesign -dv --verbose=4 "$app" > "$census/codesign.txt" 2>&1 || true
  spctl -a -vv "$app" > "$census/spctl.txt" 2>&1 || true
  codesign -d --entitlements :- "$app" > "$census/entitlements.plist" 2>/dev/null || true
  if [ -f "$census/entitlements.plist" ]; then
    python3 - "$census/entitlements.plist" > "$census/entitlement-keys.json" <<'PY'
import json,plistlib,sys
try:
    with open(sys.argv[1],"rb") as f:
        x=plistlib.load(f)
    print(json.dumps({"keys":sorted(map(str,x.keys()))},indent=2,sort_keys=True))
except Exception as e:
    print(json.dumps({"parse_error":type(e).__name__},indent=2))
PY
    rm -f "$census/entitlements.plist"
  fi

  app_asar="$(find "$app" -type f -name app.asar -print -quit || true)"
  app_asar_sha=""
  if [ -n "$app_asar" ]; then
    app_asar_sha="$(shasum -a 256 "$app_asar" | awk '{print $1}')"
    npx --yes @electron/asar@4.3.1 extract "$app_asar" "$app/Contents/Resources/__app_asar_extracted"
  fi

  python3 "$ROOT_DIR/prototype/suprachat/tools/characterize_desktop_bundle.py" \
    "$app" "$census" --label "$label" --platform macos

  bundled_codex="$(find "$app/Contents/Resources" -type f -name codex -print -quit || true)"
  bundled_arch=""
  bundled_version=""
  bundled_sha=""
  bundled_size=""
  semver=""
  standalone_asset=""
  standalone_sha=""
  standalone_size=""
  standalone_version=""
  compare_status="BUNDLED_CODEX_NOT_FOUND"

  if [ -n "$bundled_codex" ]; then
    chmod +x "$bundled_codex" || true
    bundled_arch="$(file -b "$bundled_codex" || true)"
    bundled_version="$("$bundled_codex" --version 2>&1 | head -n1 || true)"
    if ! printf '%s' "$bundled_version" | grep -Eq 'codex(-cli)?[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+' && printf '%s' "$bundled_arch" | grep -q 'x86_64'; then
      bundled_version="$(arch -x86_64 "$bundled_codex" --version 2>&1 | head -n1 || true)"
    fi
    if ! printf '%s' "$bundled_version" | grep -Eq 'codex(-cli)?[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+'; then
      bundled_version="$(strings "$bundled_codex" | grep -E 'codex(-cli)?[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
    fi
    bundled_sha="$(shasum -a 256 "$bundled_codex" | awk '{print $1}')"
    bundled_size="$(stat -f %z "$bundled_codex")"
    semver="$(printf '%s' "$bundled_version" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
    compare_status="NO_MATCHING_PUBLIC_RELEASE"

    if printf '%s' "$bundled_arch" | grep -q arm64; then
      standalone_asset="codex-aarch64-apple-darwin.tar.gz"
    elif printf '%s' "$bundled_arch" | grep -q x86_64; then
      standalone_asset="codex-x86_64-apple-darwin.tar.gz"
    fi

    if [ -n "$semver" ] && [ -n "$standalone_asset" ]; then
      archive="$WORK/standalone-$index-$semver.tar.gz"
      standalone_dir="$WORK/standalone-$index-$semver"
      mkdir -p "$standalone_dir"
      if curl --proto '=https' --tlsv1.2 -fL --retry 2 \
        "https://github.com/openai/codex/releases/download/rust-v$semver/$standalone_asset" \
        -o "$archive"; then
        tar -xzf "$archive" -C "$standalone_dir"
        standalone_bin="$(find "$standalone_dir" -type f -name 'codex*' -perm -u+x -print | sort | head -n1 || true)"
        if [ -n "$standalone_bin" ]; then
          standalone_sha="$(shasum -a 256 "$standalone_bin" | awk '{print $1}')"
          standalone_size="$(stat -f %z "$standalone_bin")"
          standalone_version="$("$standalone_bin" --version 2>&1 | head -n1 || true)"
          if [ "$standalone_sha" = "$bundled_sha" ]; then
            compare_status="EXACT_BINARY_MATCH"
          else
            compare_status="DIFFERENT_BINARY"
            bundled_unsigned="$WORK/bundled-unsigned-$index"
            standalone_unsigned="$WORK/standalone-unsigned-$index"
            cp "$bundled_codex" "$bundled_unsigned"
            cp "$standalone_bin" "$standalone_unsigned"
            bundled_codesign="$(codesign -dv --verbose=4 "$bundled_codex" 2>&1 || true)"
            standalone_codesign="$(codesign -dv --verbose=4 "$standalone_bin" 2>&1 || true)"
            codesign --remove-signature "$bundled_unsigned" >/dev/null 2>&1 || true
            codesign --remove-signature "$standalone_unsigned" >/dev/null 2>&1 || true
            bundled_unsigned_sha="$(shasum -a 256 "$bundled_unsigned" | awk '{print $1}')"
            standalone_unsigned_sha="$(shasum -a 256 "$standalone_unsigned" | awk '{print $1}')"
            bundled_unsigned_size="$(stat -f %z "$bundled_unsigned")"
            standalone_unsigned_size="$(stat -f %z "$standalone_unsigned")"
            if [ "$bundled_unsigned_sha" = "$standalone_unsigned_sha" ]; then
              compare_status="SIGNATURE_ONLY_DIFFERENCE"
            else
              compare_status="DIFFERENT_UNSIGNED_PAYLOAD"
            fi
          fi
        fi
      fi
    fi
  fi

  export CENSUS="$census" SOURCE_URL="$url" BUNDLE_ID="$bundle_id" APP_VERSION="$version" APP_BUILD="$build"
  export DMG_SHA="$dmg_sha" DMG_SIZE="$dmg_size" APP_ASAR_SHA="$app_asar_sha"
  export BUNDLED_PATH="$bundled_codex" BUNDLED_ARCH="$bundled_arch" BUNDLED_VERSION="$bundled_version"
  export BUNDLED_SHA="$bundled_sha" BUNDLED_SIZE="$bundled_size" SEMVER="$semver"
  export STANDALONE_ASSET="$standalone_asset" STANDALONE_VERSION="$standalone_version"
  export STANDALONE_SHA="$standalone_sha" STANDALONE_SIZE="$standalone_size" COMPARE_STATUS="$compare_status"
  export BUNDLED_UNSIGNED_SHA="${bundled_unsigned_sha:-}" STANDALONE_UNSIGNED_SHA="${standalone_unsigned_sha:-}"
  export BUNDLED_UNSIGNED_SIZE="${bundled_unsigned_size:-}" STANDALONE_UNSIGNED_SIZE="${standalone_unsigned_size:-}"
  export BUNDLED_CODESIGN="${bundled_codesign:-}" STANDALONE_CODESIGN="${standalone_codesign:-}"
  python3 - <<'PY'
import json,os,pathlib
out=pathlib.Path(os.environ["CENSUS"])
def opt(name):
    v=os.environ.get(name,"")
    return v or None
doc={
  "schema":"suprachat-bundled-vs-standalone-codex/v1",
  "application":{
    "source_url":os.environ["SOURCE_URL"],
    "bundle_id":os.environ["BUNDLE_ID"],
    "version":os.environ["APP_VERSION"],
    "build":os.environ["APP_BUILD"],
    "dmg_sha256":os.environ["DMG_SHA"],
    "dmg_size_bytes":int(os.environ["DMG_SIZE"]),
    "app_asar_sha256":opt("APP_ASAR_SHA"),
  },
  "bundled":{
    "path":opt("BUNDLED_PATH"),
    "architecture":opt("BUNDLED_ARCH"),
    "version_output":opt("BUNDLED_VERSION"),
    "sha256":opt("BUNDLED_SHA"),
    "size_bytes":int(os.environ["BUNDLED_SIZE"]) if opt("BUNDLED_SIZE") else None,
  },
  "parsed_version":opt("SEMVER"),
  "standalone":{
    "asset":opt("STANDALONE_ASSET"),
    "version_output":opt("STANDALONE_VERSION"),
    "sha256":opt("STANDALONE_SHA"),
    "size_bytes":int(os.environ["STANDALONE_SIZE"]) if opt("STANDALONE_SIZE") else None,
  },
  "unsigned_comparison":{
    "bundled_sha256":opt("BUNDLED_UNSIGNED_SHA"),
    "standalone_sha256":opt("STANDALONE_UNSIGNED_SHA"),
    "bundled_size_bytes":int(os.environ["BUNDLED_UNSIGNED_SIZE"]) if opt("BUNDLED_UNSIGNED_SIZE") else None,
    "standalone_size_bytes":int(os.environ["STANDALONE_UNSIGNED_SIZE"]) if opt("STANDALONE_UNSIGNED_SIZE") else None,
  },
  "code_signing":{
    "bundled_summary":opt("BUNDLED_CODESIGN"),
    "standalone_summary":opt("STANDALONE_CODESIGN"),
  },
  "status":os.environ["COMPARE_STATUS"],
}
(out/"codex-comparison.json").write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n")
PY

  rm -rf "$app" "$dmg"
done

python3 - "$OUT" <<'PY'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1])
rows=[]
for p in sorted(root.glob("*/codex-comparison.json")):
    rows.append(json.loads(p.read_text()))
(root/"codex-comparison-all.json").write_text(json.dumps(rows,indent=2,sort_keys=True)+"\n")
PY

if find "$OUT" -type f \( -name '*.dmg' -o -name 'app.asar' -o -name '*.app' \) | grep -q .; then
  echo "Proprietary application bytes escaped into output tree" >&2
  exit 30
fi
