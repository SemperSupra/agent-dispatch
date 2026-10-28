#!/usr/bin/env bash
# Public native contrast. Negative signed C right shift is implementation-defined.
# This is not JNI/ART, decompiler, or general semantic recovery proof.
set -euo pipefail
: "${COMPILER:?}" "${OPT_LEVEL:?}"
case "$COMPILER:$OPT_LEVEL" in gcc:O0|gcc:O2|clang:O0|clang:O2) ;; *) exit 2;; esac
command -v "$COMPILER" >/dev/null
command -v python3 >/dev/null
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cat > "$work/signedness.c" <<'C'
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
__attribute__((noinline, used)) static int32_t signed_shift(int32_t n) {
    return n >> 1;
}
__attribute__((noinline, used)) static uint32_t unsigned_shift(uint32_t n) {
    return n >> 1;
}
int main(void) {
    static const int32_t samples[] = {0, 1, INT32_MAX, INT32_MIN, -1, -2};
    for (unsigned i = 0; i < sizeof(samples) / sizeof(samples[0]); ++i) {
        int32_t n = samples[i];
        printf("%08" PRIx32 "|%08" PRIx32 "|%08" PRIx32 "\n",
               (uint32_t)n, (uint32_t)signed_shift(n), unsigned_shift((uint32_t)n));
    }
    return 0;
}
C
"$COMPILER" "-$OPT_LEVEL" -std=c11 -Wall -Wextra -Werror -fno-pie -no-pie "$work/signedness.c" -o "$work/contrast"
python3 - "$work/signedness.c" "$work/contrast" "$COMPILER" "$OPT_LEVEL" <<'PY'
import hashlib, json, pathlib, subprocess, sys
source, exe = (pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
compiler, optimization = sys.argv[3:]
assert source.stat().st_size < 4096 and exe.stat().st_size < 1048576
version = subprocess.run([compiler, '--version'], text=True, capture_output=True,
                         check=True, timeout=5).stdout.splitlines()[0][:200]
p = subprocess.run([str(exe)], text=True, capture_output=True, check=True, timeout=5)
assert not p.stderr and len(p.stdout) < 1024
xs = [0, 1, 0x7fffffff, 0x80000000, 0xffffffff, 0xfffffffe]
lines = p.stdout.splitlines()
assert len(lines) == len(xs), 'missing/duplicate native samples'
divergences = []
for index, (expected, line) in enumerate(zip(xs, lines)):
    fields = line.split('|')
    assert len(fields) == 3 and all(len(x) == 8 and all(ch in '0123456789abcdef' for ch in x) for x in fields)
    before, signed, unsigned = [int(x, 16) for x in fields]
    assert before == expected and unsigned == (before >> 1), 'unsigned logical shift oracle mismatch'
    if before <= 0x7fffffff:
        assert signed == unsigned, 'signed nonnegative shift mismatch'
    elif signed != unsigned:
        divergences.append(index)
# GCC/Clang on this Ubuntu runner give arithmetic signed negative shifts.
# C defines this as implementation-defined, not a general portable oracle.
assert divergences == [3, 4, 5], 'negative signedness contrast not observed for scoped compiler'
print(json.dumps({
    'kind': 'PUBLIC_FIXED_C_SIGNEDNESS_CONTRAST_V1',
    'result': 'PASS_SCOPED_COMPILER_CONTRAST_NOT_GENERAL_JNI_SEMANTICS',
    'compiler': compiler, 'optimization': optimization,
    'compiler_version': version,
    'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
    'binary_sha256': hashlib.sha256(exe.read_bytes()).hexdigest(),
    'unsigned_reference_checks': len(xs),
    'nonnegative_signed_reference_checks': 3,
    'negative_signedness_divergences': len(divergences),
    'signed_negative_shift_portability': 'IMPLEMENTATION_DEFINED',
    'shift_by_32_or_more': 'NOT_EXECUTED_UNDEFINED_C_BEHAVIOR',
    'android_jni_art_executed': False,
    'semantic_ir_promoted': False
}, sort_keys=True))
PY
