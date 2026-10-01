#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${GITHUB_WORKSPACE:-$PWD}"
OUT="$ROOT_DIR/out/desktop-oracle/linux"
WORK="${RUNNER_TEMP:-/tmp}/suprachat-linux-census-$$"
mkdir -p "$OUT" "$WORK"
trap 'rm -rf "$WORK"' EXIT

sudo apt-get update -qq
sudo apt-get install -y -qq rpm cpio file binutils >/dev/null

urls=(
  "https://persistent.oaistatic.com/codex-app-prod/linux/deb/latest/chatgpt_amd64.deb"
  "https://persistent.oaistatic.com/codex-app-prod/linux/deb/latest/chatgpt_arm64.deb"
  "https://persistent.oaistatic.com/codex-app-prod/linux/rpm/latest/chatgpt.x86_64.rpm"
  "https://persistent.oaistatic.com/codex-app-prod/linux/rpm/latest/chatgpt.aarch64.rpm"
)

printf '{"schema":"suprachat-desktop-source-set/v1","urls":[' > "$OUT/source-set.json"
first=1
for url in "${urls[@]}"; do
  if [ $first -eq 0 ]; then printf ',' >> "$OUT/source-set.json"; fi
  first=0
  python3 - "$url" >> "$OUT/source-set.json" <<'PY'
import json,sys
print(json.dumps(sys.argv[1]),end="")
PY
done
printf ']}\n' >> "$OUT/source-set.json"

asar_reference_hash=""
for url in "${urls[@]}"; do
  base="$(basename "${url%%\?*}")"
  pkg="$WORK/$base"
  curl --proto '=https' --tlsv1.2 -fL --retry 3 "$url" -o "$pkg"
  pkg_sha="$(sha256sum "$pkg" | awk '{print $1}')"
  pkg_size="$(stat -c %s "$pkg")"
  root="$WORK/root-${base//[^A-Za-z0-9_.-]/_}"
  mkdir -p "$root"

  kind=""
  arch=""
  version=""
  package_name=""
  case "$pkg" in
    *.deb)
      kind="deb"
      arch="$(dpkg-deb -f "$pkg" Architecture)"
      version="$(dpkg-deb -f "$pkg" Version)"
      package_name="$(dpkg-deb -f "$pkg" Package)"
      dpkg-deb -x "$pkg" "$root"
      ;;
    *.rpm)
      kind="rpm"
      arch="$(rpm -qp --qf '%{ARCH}' "$pkg")"
      version="$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$pkg")"
      package_name="$(rpm -qp --qf '%{NAME}' "$pkg")"
      (cd "$root" && rpm2cpio "$pkg" | cpio -idmu --quiet)
      ;;
    *)
      echo "Unknown package type: $pkg" >&2
      exit 20
      ;;
  esac

  label="$kind-$arch"
  census="$OUT/$label"
  mkdir -p "$census"

  app_asar="$(find "$root" -type f -name app.asar -print -quit || true)"
  app_asar_sha=""
  if [ -n "$app_asar" ]; then
    app_asar_sha="$(sha256sum "$app_asar" | awk '{print $1}')"
    if [ -z "$asar_reference_hash" ]; then
      asar_reference_hash="$app_asar_sha"
      npx --yes @electron/asar@4.3.1 extract "$app_asar" "$root/__app_asar_extracted"
    fi
  fi

  python3 "$ROOT_DIR/prototype/suprachat/tools/characterize_desktop_bundle.py" \
    "$root" "$census" --label "$label" --platform linux

  bundled_codex="$(find "$root" -type f -name codex -path '*/resources/*' -print -quit || true)"
  bundled_version=""
  bundled_sha=""
  bundled_size=""
  bundled_file=""
  semver=""
  standalone_asset=""
  standalone_sha=""
  standalone_size=""
  standalone_version=""
  compare_status="BUNDLED_CODEX_NOT_FOUND"

  if [ -n "$bundled_codex" ]; then
    chmod +x "$bundled_codex" || true
    bundled_file="$(file -b "$bundled_codex" || true)"
    bundled_version="$("$bundled_codex" --version 2>&1 | head -n1 || true)"
    if [ -z "$bundled_version" ]; then
      bundled_version="$(strings "$bundled_codex" | grep -E 'codex(-cli)?[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
    fi
    bundled_sha="$(sha256sum "$bundled_codex" | awk '{print $1}')"
    bundled_size="$(stat -c %s "$bundled_codex")"
    semver="$(printf '%s' "$bundled_version" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
    compare_status="NO_MATCHING_PUBLIC_RELEASE"

    case "$arch" in
      amd64|x86_64) standalone_asset="codex-x86_64-unknown-linux-musl.tar.gz" ;;
      arm64|aarch64) standalone_asset="codex-aarch64-unknown-linux-musl.tar.gz" ;;
    esac

    if [ -n "$semver" ] && [ -n "$standalone_asset" ]; then
      standalone_archive="$WORK/standalone-$label-$semver.tar.gz"
      standalone_dir="$WORK/standalone-$label-$semver"
      mkdir -p "$standalone_dir"
      if curl --proto '=https' --tlsv1.2 -fL --retry 2 \
        "https://github.com/openai/codex/releases/download/rust-v$semver/$standalone_asset" \
        -o "$standalone_archive"; then
        tar -xzf "$standalone_archive" -C "$standalone_dir"
        standalone_bin="$(find "$standalone_dir" -type f -name 'codex*' -perm -u+x -print | sort | head -n1 || true)"
        if [ -n "$standalone_bin" ]; then
          standalone_sha="$(sha256sum "$standalone_bin" | awk '{print $1}')"
          standalone_size="$(stat -c %s "$standalone_bin")"
          standalone_version="$("$standalone_bin" --version 2>&1 | head -n1 || true)"
          if [ "$standalone_sha" = "$bundled_sha" ]; then
            compare_status="EXACT_BINARY_MATCH"
          else
            compare_status="DIFFERENT_BINARY"
          fi
        fi
      fi
    fi
  fi

  export CENSUS="$census" SOURCE_URL="$url" PACKAGE_NAME="$package_name" PACKAGE_VERSION="$version"
  export PACKAGE_ARCH="$arch" PACKAGE_KIND="$kind" PACKAGE_SHA="$pkg_sha" PACKAGE_SIZE="$pkg_size"
  export APP_ASAR_SHA="$app_asar_sha" BUNDLED_PATH="$bundled_codex" BUNDLED_FILE="$bundled_file"
  export BUNDLED_VERSION="$bundled_version" BUNDLED_SHA="$bundled_sha" BUNDLED_SIZE="$bundled_size"
  export SEMVER="$semver" STANDALONE_ASSET="$standalone_asset" STANDALONE_VERSION="$standalone_version"
  export STANDALONE_SHA="$standalone_sha" STANDALONE_SIZE="$standalone_size" COMPARE_STATUS="$compare_status"
  python3 - <<'PY'
import json,os,pathlib
out=pathlib.Path(os.environ["CENSUS"])
def opt(name):
    v=os.environ.get(name,"")
    return v or None
doc={
  "schema":"suprachat-bundled-vs-standalone-codex/v1",
  "package":{
    "source_url":os.environ["SOURCE_URL"],
    "name":os.environ["PACKAGE_NAME"],
    "version":os.environ["PACKAGE_VERSION"],
    "architecture":os.environ["PACKAGE_ARCH"],
    "kind":os.environ["PACKAGE_KIND"],
    "sha256":os.environ["PACKAGE_SHA"],
    "size_bytes":int(os.environ["PACKAGE_SIZE"]),
    "app_asar_sha256":opt("APP_ASAR_SHA"),
  },
  "bundled":{
    "path":opt("BUNDLED_PATH"),
    "file_type":opt("BUNDLED_FILE"),
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
  "status":os.environ["COMPARE_STATUS"],
}
(out/"codex-comparison.json").write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n")
PY

  rm -rf "$root" "$pkg"
done

python3 - "$OUT" <<'PY'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1])
rows=[]
for p in sorted(root.glob("*/codex-comparison.json")):
    rows.append(json.loads(p.read_text()))
(root/"codex-comparison-all.json").write_text(json.dumps(rows,indent=2,sort_keys=True)+"\n")
PY

if find "$OUT" -type f \( -name '*.deb' -o -name '*.rpm' -o -name 'app.asar' \) | grep -q .; then
  echo "Proprietary package bytes escaped into output tree" >&2
  exit 30
fi
