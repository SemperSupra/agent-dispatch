#!/bin/sh
set -eu
out="$1"
{
  printf 'UNAME_S=%s\n' "$(uname -s 2>/dev/null || true)"
  printf 'UNAME_R=%s\n' "$(uname -r 2>/dev/null || true)"
  printf 'UNAME_M=%s\n' "$(uname -m 2>/dev/null || true)"
  printf 'UID=%s\n' "$(id -u 2>/dev/null || true)"
  printf 'GID=%s\n' "$(id -g 2>/dev/null || true)"
  printf 'SHELL_PATH=%s\n' "$(command -v sh 2>/dev/null || true)"
  for cmd in sh bash ksh zsh cc gcc clang make cmake python3 python perl ruby go rustc cargo pkg pkg_add pkgin pkgman svcadm service rcctl sysctl; do
    if command -v "$cmd" >/dev/null 2>&1; then printf 'CMD_%s=1\n' "$cmd"; else printf 'CMD_%s=0\n' "$cmd"; fi
  done
  cpu=""
  if command -v getconf >/dev/null 2>&1; then cpu="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"; fi
  if [ -z "$cpu" ] && command -v sysctl >/dev/null 2>&1; then cpu="$(sysctl -n hw.ncpu 2>/dev/null || true)"; fi
  printf 'CPU_ONLINE=%s\n' "$cpu"
  mem=""
  if command -v sysctl >/dev/null 2>&1; then
    for key in hw.physmem hw.physmem64 hw.realmem; do
      mem="$(sysctl -n "$key" 2>/dev/null || true)"
      [ -n "$mem" ] && break
    done
  fi
  printf 'MEM_BYTES=%s\n' "$mem"
  df -Pk / 2>/dev/null | awk 'NR==2 {printf "ROOT_FS=%s\nROOT_TOTAL_KIB=%s\nROOT_FREE_KIB=%s\n",$1,$2,$4}' || true
  tmp="/tmp/runner-guest-census-$$"
  mkdir -p "$tmp"
  trap 'rm -rf "$tmp"' 0
  printf nonce >"$tmp/CaseProbe"
  if [ -e "$tmp/caseprobe" ]; then printf 'FS_CASE_INSENSITIVE=1\n'; else printf 'FS_CASE_INSENSITIVE=0\n'; fi
  if ln -s "$tmp/CaseProbe" "$tmp/symlink" 2>/dev/null && [ "$(cat "$tmp/symlink" 2>/dev/null || true)" = nonce ]; then printf 'FS_SYMLINK=1\n'; else printf 'FS_SYMLINK=0\n'; fi
  if ln "$tmp/CaseProbe" "$tmp/hardlink" 2>/dev/null && [ "$(cat "$tmp/hardlink" 2>/dev/null || true)" = nonce ]; then printf 'FS_HARDLINK=1\n'; else printf 'FS_HARDLINK=0\n'; fi
} >"$out"
