#!/usr/bin/env bash
# R63 read-only recovery SSH source/CLI negative oracle. No real SSH, auth,
# device/firmware operations, credentials, host listener, or production claim.
set -Eeuo pipefail
export LC_ALL=C TZ=UTC
s=tools/wyse-buildroot/overlay/etc/init.d/S50dropbear
cli=tools/wyse-buildroot/overlay/usr/libexec/wyse-ssh-readonly
test -s "$s" && test -s "$cli"
sh -n "$s" "$cli"
grep -Fq -- "dropbear -s -g -j -k -c '/bin/sh /usr/libexec/wyse-ssh-readonly' -p 22 -r" "$s"
grep -Fq 'WYSE_SSH=HOLD_UNENROLLED_NO_HOST_KEY' "$s"
grep -Fq 'WYSE_SSH=HOLD_NO_RESTRICTED_COMMAND' "$s"
grep -Fq 'WYSE_SSH=KEY_ONLY_RESTRICTED_START' "$s"
! grep -Fq 'dropbear -R' "$s"
echo R63_SOURCE_FORCED_COMMAND_AND_NO_FORWARDING=PASS
# Only fixed strings are permitted. Never eval or execute an operator command.
test "$(env -u SSH_ORIGINAL_COMMAND /bin/sh "$cli")" = "$(printf 'WYSE_RECOVERY_COMMANDS=help,status\nWYSE_RECOVERY_SSH_SCOPE=READ_ONLY')"
test "$(SSH_ORIGINAL_COMMAND=help /bin/sh "$cli")" = "$(printf 'WYSE_RECOVERY_COMMANDS=help,status\nWYSE_RECOVERY_SSH_SCOPE=READ_ONLY')"
test "$(SSH_ORIGINAL_COMMAND=status /bin/sh "$cli")" = "$(printf 'WYSE_RECOVERY_SSH_SCOPE=READ_ONLY\nWYSE_RECOVERD_INTEGRATION=NOT_QUALIFIED\nWYSE_PRODUCTION_PAIRING=NOT_QUALIFIED')"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
denied=0
deny() {
  local request=$1 output status
  set +e
  output=$(SSH_ORIGINAL_COMMAND="$request" /bin/sh "$cli" 2>&1)
  status=$?
  set -e
  test "$status" -eq 64 || { echo "R63_UNSAFE_COMMAND_NOT_DENIED=RED" >&2; exit 63; }
  test "$output" = "WYSE_RECOVERY_SSH=DENIED_UNSUPPORTED_COMMAND" || exit 62
  denied=$((denied + 1))
}
deny 'id'
deny 'sh'
deny 'sudo reboot'
deny 'status; id'
deny 'status || true'
deny 'status --json'
deny 'cat /etc/shadow'
deny 'touch /tmp/unwanted'
deny '$(touch /tmp/unwanted)'
deny "status; touch $scratch/should-not-exist"
# Empty remote command is permitted ONLY for static help.
test ! -e "$scratch/should-not-exist"
test "$denied" -eq 10
echo R63_FORCED_CLI_ALLOWLIST_AND_INJECTION_NEGATIVES=PASS
echo R63_ACTUAL_GUEST_SSH_AUTH_SHELL_AND_FORWARDING=NOT_TESTED
echo R63_GO_RECOVERD_SIGNING_ENROLLMENT_AND_PHYSICAL=NOT_TESTED
