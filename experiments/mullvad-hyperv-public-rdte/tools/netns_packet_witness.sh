#!/usr/bin/env bash
# PUBLIC-ONLY synthetic Linux-kernel forwarding witness.
# Creates only run-owned network namespaces + veth pairs; does not change the
# runner's default/physical NIC, host routes, host DNS, or host nftables tables.
# No Mullvad API, secrets, operational packets, or external network destinations.
set -Eeuo pipefail
export LC_ALL=C

: "${GITHUB_RUN_ID:?fixed hosted GitHub runner required}"
: "${GITHUB_RUN_ATTEMPT:?run attempt identity required}"
[[ "$GITHUB_RUN_ID" =~ ^[0-9]+$ && "$GITHUB_RUN_ATTEMPT" =~ ^[0-9]+$ ]] ||
  { echo "invalid run identity"; exit 2; }
[[ -n "${RUNNER_TEMP:-}" && "${RUNNER_ENVIRONMENT:-}" == "github-hosted" ]] ||
  { echo "refuse non-GitHub-hosted runner"; exit 2; }

work="${GITHUB_WORKSPACE:?}/experiments/mullvad-hyperv-public-rdte"
witness="$work/tools/netns_udp_witness.py"
[[ -f "$witness" ]] || exit 2
for command in ip nft python3 sudo; do
  command -v "$command" >/dev/null || { echo "required public host tool unavailable: $command"; exit 2; }
done
sudo -n true >/dev/null

# All names are unique to the verified native run and attempt, and prechecked.
tag="${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
lan_ns="rdte-lan-${tag}"
gw_ns="rdte-gw-${tag}"
wan_ns="rdte-wan-${tag}"
suffix="${GITHUB_RUN_ID: -6}${GITHUB_RUN_ATTEMPT: -2}"
a="r${suffix}a"; b="r${suffix}b"; c="r${suffix}c"; d="r${suffix}d"
[[ "${#a}" -le 15 ]] || exit 2
for ns in "$lan_ns" "$gw_ns" "$wan_ns"; do
  if sudo -n ip netns list | grep -Fq "$ns "; then
    echo "run namespace name is already owned: collision"; exit 2
  fi
done
for nic in "$a" "$b" "$c" "$d"; do
  if ip link show dev "$nic" >/dev/null 2>&1; then
    echo "pre-existing veth identity collision"; exit 2
  fi
done

created_lan=false; created_gw=false; created_wan=false
server_pid=""
cleanup() {
  work_rc=$?
  cleanup_rc=0
  trap - EXIT INT TERM
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  [[ -n "${server_log:-}" ]] && rm -f -- "$server_log"
  # Only processes in *this run's* namespace are terminated, if any.
  if [[ "$created_wan" == true ]]; then
    while read -r pid; do
      [[ "$pid" =~ ^[0-9]+$ ]] && sudo -n kill "$pid" >/dev/null 2>&1 || true
    done < <(sudo -n ip netns pids "$wan_ns" 2>/dev/null || true)
  fi
  for pair in "$lan_ns:$created_lan" "$gw_ns:$created_gw" "$wan_ns:$created_wan"; do
    ns="${pair%%:*}"; created="${pair##*:}"
    if [[ "$created" == true ]]; then
      sudo -n ip netns delete "$ns" >/dev/null 2>&1 || cleanup_rc=1
    fi
  done
  for nic in "$a" "$b" "$c" "$d"; do
    # Only remove a veth if it was created in this run; after namespace teardown
    # no veth should remain in the host namespace. Never touch pre-existing NICs.
    if ip link show dev "$nic" >/dev/null 2>&1; then
      echo "unexpected residual test NIC $nic"; cleanup_rc=1
    fi
  done
  for ns in "$lan_ns" "$gw_ns" "$wan_ns"; do
    if sudo -n ip netns list | grep -Fq "$ns "; then
      echo "run-owned namespace cleanup failed"; cleanup_rc=1
    fi
  done
  [[ "$cleanup_rc" -eq 0 ]] && echo "CLEANUP=PASS" || echo "CLEANUP=FAIL"
  [[ "$work_rc" -eq 0 && "$cleanup_rc" -ne 0 ]] && work_rc=1
  exit "$work_rc"
}
trap cleanup EXIT INT TERM

sudo -n ip netns add "$lan_ns"; created_lan=true
sudo -n ip netns add "$gw_ns"; created_gw=true
sudo -n ip netns add "$wan_ns"; created_wan=true

sudo -n ip link add "$a" type veth peer name "$b"
sudo -n ip link set "$a" netns "$lan_ns"
sudo -n ip link set "$b" netns "$gw_ns"
sudo -n ip link add "$c" type veth peer name "$d"
sudo -n ip link set "$c" netns "$gw_ns"
sudo -n ip link set "$d" netns "$wan_ns"

sudo -n ip -n "$lan_ns" link set "$a" name lan0
sudo -n ip -n "$gw_ns" link set "$b" name gwlan
sudo -n ip -n "$gw_ns" link set "$c" name gwwan
sudo -n ip -n "$wan_ns" link set "$d" name wan0

for ns in "$lan_ns" "$gw_ns" "$wan_ns"; do sudo -n ip -n "$ns" link set lo up; done
sudo -n ip -n "$lan_ns" addr add 192.0.2.2/24 dev lan0
sudo -n ip -n "$gw_ns" addr add 192.0.2.1/24 dev gwlan
sudo -n ip -n "$gw_ns" addr add 198.51.100.1/24 dev gwwan
sudo -n ip -n "$wan_ns" addr add 198.51.100.2/24 dev wan0
sudo -n ip -n "$lan_ns" -6 addr add 2001:db8:1::2/64 dev lan0
sudo -n ip -n "$gw_ns" -6 addr add 2001:db8:1::1/64 dev gwlan
sudo -n ip -n "$gw_ns" -6 addr add 2001:db8:2::1/64 dev gwwan
sudo -n ip -n "$wan_ns" -6 addr add 2001:db8:2::2/64 dev wan0
for spec in "$lan_ns:lan0" "$gw_ns:gwlan" "$gw_ns:gwwan" "$wan_ns:wan0"; do
  sudo -n ip -n "${spec%%:*}" link set "${spec##*:}" up
done
sudo -n ip netns exec "$gw_ns" sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns exec "$gw_ns" sysctl -qw net.ipv6.conf.all.forwarding=1
sudo -n ip -n "$lan_ns" route add default via 192.0.2.1
sudo -n ip -n "$lan_ns" -6 route add default via 2001:db8:1::1

# IPv6 address can initially be tentative. Wait for DAD before binding server.
dad_ready=false
for cycle in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if ! sudo -n ip -n "$wan_ns" -6 addr show dev wan0 | grep -q tentative; then
    dad_ready=true
    break
  fi
  sleep 0.15
done
[[ "$dad_ready" == true ]] || { echo "WAN IPv6 DAD not ready"; exit 1; }

server_log="$RUNNER_TEMP/rdte-witness-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}.log"
# Logs are limited to errors from the public synthetic witness, no real traffic.
: > "$server_log"
sudo -n ip netns exec "$wan_ns" python3 -B "$witness" server >"$server_log" 2>&1 &
server_pid=$!
sleep 0.35
if ! kill -0 "$server_pid" >/dev/null 2>&1; then
  echo "synthetic observer exited before baseline"
  head -n 10 "$server_log"
  exit 1
fi

probe() { sudo -n ip netns exec "$lan_ns" python3 -B "$witness" probe --family "$1" --port "$2"; }
expect_accepted() {
  if ! probe "$1" "$2"; then
    echo "native positive witness missing: family=$1 class=$3"; return 1
  fi
}
expect_blocked() {
  if probe "$1" "$2"; then
    echo "actual plaintext escape detected: family=$1 class=$3"; return 1
  else
    rc=$?
    if [[ "$rc" -ne 4 ]]; then
      echo "unverifiable negative (not expected receive timeout): family=$1 class=$3 code=$rc"; return 1
    fi
  fi
}

# Before a guard exists, independently show real packets can cross both families.
baseline4=false
baseline6=false
for n in 1 2 3 4 5 6 7 8 9 10; do
  probe 4 42001 && baseline4=true || true
  probe 6 42001 && baseline6=true || true
  [[ "$baseline4" == true && "$baseline6" == true ]] && break
  sleep 0.15
done
if [[ "$baseline4" != true || "$baseline6" != true ]]; then
  echo "positive control failed: ipv4=${baseline4} ipv6=${baseline6}"
  if [[ -s "$server_log" ]]; then head -n 10 "$server_log"; fi
  sudo -n ip -n "$lan_ns" route get 198.51.100.2 2>/dev/null || true
  sudo -n ip -n "$lan_ns" -6 route get 2001:db8:2::2 2>/dev/null || true
  exit 1
fi
echo "POSITIVE_CONTROL_IPV4=PASS"
echo "POSITIVE_CONTROL_IPV6=PASS"

# Real nf_tables inet forward hook. Default drop is installed in the isolated
# gateway namespace, never in the runner's host network namespace.
sudo -n ip netns exec "$gw_ns" nft -f - <<'NFT'
table inet rdte_gate {
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
}
NFT
for f in 4 6; do
  expect_blocked "$f" 42001 "user-data"
  expect_blocked "$f" 42002 "first-hop"
done
echo "NATIVE_NFT_DEFAULT_DROP_DUALSTACK=PASS"

# Deliberately allow only one synthetic UDP service, with both directions and
# exact src/dst/interface/protocol/port. No WireGuard tunnel is involved.
sudo -n ip netns exec "$gw_ns" nft -f - <<'NFT'
add rule inet rdte_gate forward iifname "gwlan" oifname "gwwan" ip saddr 192.0.2.2 ip daddr 198.51.100.2 udp dport 42002 accept
add rule inet rdte_gate forward iifname "gwwan" oifname "gwlan" ip saddr 198.51.100.2 ip daddr 192.0.2.2 udp sport 42002 accept
add rule inet rdte_gate forward iifname "gwlan" oifname "gwwan" ip6 saddr 2001:db8:1::2 ip6 daddr 2001:db8:2::2 udp dport 42002 accept
add rule inet rdte_gate forward iifname "gwwan" oifname "gwlan" ip6 saddr 2001:db8:2::2 ip6 daddr 2001:db8:1::2 udp sport 42002 accept
NFT
for f in 4 6; do
  expect_accepted "$f" 42002 "scope-allowed"
  expect_blocked "$f" 42001 "still-denied"
done
echo "NATIVE_NFT_SCOPED_ALLOW_DUALSTACK=PASS"

# Simulate revocation by emptying this test's only forwarding chain.
sudo -n ip netns exec "$gw_ns" nft flush chain inet rdte_gate forward
for f in 4 6; do
  expect_blocked "$f" 42001 "revoked-user"
  expect_blocked "$f" 42002 "revoked-first-hop"
done
echo "NATIVE_NFT_REVOKE_DUALSTACK=PASS"
echo "EVIDENCE_CLASS=PUBLIC_ISOLATED_LINUX_KERNEL_PACKET_WITNESS"
echo "PRIVILEGED_SCOPE=RUN_OWNED_NETNS_ONLY"
echo "MULLVAD_SERVICE=NOT_CALLED"
echo "WIREGUARD_TUNNEL=NOT_RUN"
echo "NESTED_HYPERV_GUEST=NOT_RUN"
echo "PRIVATE_PRODUCT=NOT_QUALIFIED"
