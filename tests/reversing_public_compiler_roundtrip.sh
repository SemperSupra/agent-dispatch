#!/usr/bin/env bash
# Public source-known compiler/strip behavioral control. No private code or model grading.
set -euo pipefail
: "${COMPILER:?}" "${OPT_LEVEL:?}"
case "$COMPILER:$OPT_LEVEL" in gcc:O0|gcc:O2|clang:O0|clang:O2) ;; *)
    echo 'unsupported fixed compilation profile' >&2; exit 2;; esac
command -v "$COMPILER" >/dev/null
for tool in strip objdump nm python3; do command -v "$tool" >/dev/null; done
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cat > "$work/fixture.c" <<'C'
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
__attribute__((noinline, used)) static uint32_t recover_target(uint32_t x) {
    uint32_t v = x ^ UINT32_C(0x9e3779b9);
    for (uint32_t i = 0; i < UINT32_C(5); ++i) {
        if ((v & UINT32_C(1)) == 0)
            v = (v >> 1) ^ UINT32_C(0xa5a5a5a5);
        else
            v = (v >> 1) ^ UINT32_C(0x3c6ef372);
    }
    uint32_t result = (v + (x * UINT32_C(33))) ^ UINT32_C(0x12345678);
#ifdef INJECT_FAULT
    result ^= UINT32_C(1);
#endif
    return result;
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    errno = 0;
    char *end = NULL;
    unsigned long long n = strtoull(argv[1], &end, 0);
    if (errno != 0 || end == argv[1] || *end != '\0' || n > UINT32_MAX) return 3;
    printf("%08" PRIx32 "\n", recover_target((uint32_t)n));
    return 0;
}
C
"$COMPILER" "-$OPT_LEVEL" -std=c11 -Wall -Wextra -Werror -fno-pie -no-pie -fno-unwind-tables -fno-asynchronous-unwind-tables "$work/fixture.c" -o "$work/original"
cp "$work/original" "$work/stripped"
strip --strip-all "$work/stripped"
"$COMPILER" "-$OPT_LEVEL" -std=c11 -Wall -Wextra -Werror -fno-pie -no-pie -fno-unwind-tables -fno-asynchronous-unwind-tables -DINJECT_FAULT=1 "$work/fixture.c" -o "$work/mutant"
strip --strip-all "$work/mutant"
python3 - "$work/original" "$work/stripped" "$work/mutant" "$COMPILER" "$OPT_LEVEL" <<'PY'
import hashlib, json, pathlib, re, struct, subprocess, sys
unstripped, stripped, mutant = map(pathlib.Path, sys.argv[1:4])
compiler, opt = sys.argv[4:6]
for path in (unstripped, stripped, mutant):
    b = path.read_bytes()
    assert len(b) < (1 << 20), 'oversized fixture'
    assert b[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<HH', b, 16) == (2, 62), 'not fixed ELF64 x86_64 executable'
assert hashlib.sha256(unstripped.read_bytes()).hexdigest() != hashlib.sha256(stripped.read_bytes()).hexdigest(), 'strip changed no bytes'
original_symbols = subprocess.run(['nm', str(unstripped)], check=True, capture_output=True, text=True).stdout
assert 'recover_target' in original_symbols, 'original symbol missing'
post = subprocess.run(['nm', str(stripped)], capture_output=True, text=True)
assert 'recover_target' not in post.stdout, 'stripped output kept target symbol'
disasm = subprocess.run(['objdump', '-d', '-j', '.text', str(stripped)], check=True, capture_output=True, text=True).stdout
assert len(re.findall(r'^\s*[0-9a-f]+:\s+[0-9a-f]{2}', disasm, flags=re.M)) >= 10, 'no decoded .text instructions'
mask = 0xffffffff
def reference(n):
    v = n ^ 0x9e3779b9
    for _ in range(5):
        v = ((v >> 1) ^ (0x3c6ef372 if (v & 1) else 0xa5a5a5a5)) & mask
    return f'{((v + n * 33) & mask) ^ 0x12345678:08x}\n'
values = (0, 1, 2, 3, 7, 255, 0x7fffffff, 0x80000000, 0xffffffff)
for n in values:
    expected = reference(n)
    for path in (unstripped, stripped):
        out = subprocess.run([str(path), str(n)], check=True, capture_output=True, text=True, timeout=3)
        assert out.stdout == expected and not out.stderr, f'oracle mismatch compiler={compiler} opt={opt} n={n}'
    bad = subprocess.run([str(mutant), str(n)], check=True, capture_output=True, text=True, timeout=3)
    assert bad.stdout != expected, 'negative mutant evaded independent oracle'
for inp in ('4294967296', '-1', 'not-a-number', ''):
    bad = subprocess.run([str(stripped), inp], capture_output=True, text=True, timeout=3)
    assert bad.returncode != 0 and bad.stdout == '', 'invalid command input accepted'
receipt = {'kind':'PUBLIC_SOURCE_KNOWN_UNSIGNED_ORACLE_V1', 'compiler':compiler, 'optimization':opt,
           'input_count':len(values),'behavior_checks':len(values)*2,
           'mutant_rejections':len(values),'argument_rejections':4,
           'original_sha256':hashlib.sha256(unstripped.read_bytes()).hexdigest(),
           'stripped_sha256':hashlib.sha256(stripped.read_bytes()).hexdigest(),
           'mutant_sha256':hashlib.sha256(mutant.read_bytes()).hexdigest(),
           'result':'PASS_NOT_A_REVERSE_ENGINEERING_OR_MODEL_QUALIFICATION'}
print(json.dumps(receipt, sort_keys=True))
PY
