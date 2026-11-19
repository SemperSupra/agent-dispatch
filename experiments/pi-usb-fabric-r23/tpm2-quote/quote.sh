#!/usr/bin/env bash
set -Eeuo pipefail
root="$(mktemp -d /tmp/r23-quote-XXXXXXXX)"
pid=""
cleanup(){
 if [[ -n "$pid" ]];then kill "$pid" 2>/dev/null || :;wait "$pid" 2>/dev/null || :;fi
 rm -rf "$root"
 echo R23_C_SWTMP_DISPOSABLE_STATE_DESTROYED=PASS
}
trap cleanup EXIT
chmod 0700 "$root"
mkdir -m 0700 "$root/state"
swtpm socket --tpm2 --tpmstate "dir=$root/state" \
 --server "type=tcp,port=2321,bindaddr=127.0.0.1" \
 --ctrl "type=tcp,port=2322,bindaddr=127.0.0.1" \
 --flags not-need-init >"$root/swtpm.log" 2>&1 &
pid=$!
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
cd "$root"
ready=no
for i in $(seq 1 80);do
 if ! kill -0 "$pid" 2>/dev/null;then cat swtpm.log;exit 11;fi
 if tpm2_getrandom -Q 16 -o random.bin >/dev/null 2>&1;then ready=yes;break;fi
 sleep 0.1
done
if [[ "$ready" != yes ]] || [[ "$(wc -c < random.bin)" != 16 ]];then
 echo R23_C_REAL_TPM2_GETRANDOM=RED;exit 12
fi
echo R23_C_REAL_SWTMP_TPM2_GETRANDOM=PASS
tpm2_pcrread -Q -o pcr-origin.bin sha256:0,1,2
test -s pcr-origin.bin
echo R23_C_REAL_SWTMP_PCR_READ=PASS
tpm2_createek -Q -c ek.ctx -G rsa -u ekpub.pem -f pem
tpm2_createak -Q -C ek.ctx -c ak.ctx -G rsa -s rsassa -g sha256 -u akpub.pem -f pem -n ak.name
test -s akpub.pem
nonce="$(python3 -c 'import secrets;print(secrets.token_hex(16))')"
tpm2_quote -Q -c ak.ctx -l sha256:0,1,2 -q "$nonce" \
 -m quote.msg -s quote.sig -o quote.pcrs -g sha256
for filename in quote.msg quote.sig quote.pcrs;do test -s "$filename";done
tpm2_checkquote -Q -u akpub.pem -m quote.msg -s quote.sig -f quote.pcrs -g sha256 -q "$nonce"
echo R23_C_REAL_SWTMP_NONCE_PCR_QUOTE_VERIFIED=PASS
wrong_nonce="$(python3 -c 'import secrets;print(secrets.token_hex(16))')"
test "$wrong_nonce" != "$nonce"
if tpm2_checkquote -Q -u akpub.pem -m quote.msg -s quote.sig -f quote.pcrs -g sha256 -q "$wrong_nonce" >wrong-nonce.log 2>&1;then
 echo R23_C_WRONG_QUOTE_CHALLENGE=RED;exit 13
fi
echo R23_C_WRONG_QUOTE_CHALLENGE_DENIED=PASS
cp quote.pcrs altered-pcrs
python3 - <<'PY'
from pathlib import Path
p=Path("altered-pcrs")
b=bytearray(p.read_bytes())
if not b:raise RuntimeError("empty PCR list")
b[-1]^=0x80
p.write_bytes(bytes(b))
PY
if tpm2_checkquote -Q -u akpub.pem -m quote.msg -s quote.sig -f altered-pcrs -g sha256 -q "$nonce" >wrong-pcr.log 2>&1;then
 echo R23_C_ALTERED_PCRS=RED;exit 14
fi
echo R23_C_ALTERED_PCRS_DENIED=PASS
test -s quote.sig
echo R23_C_TPM2_QUOTE_IN_GUEST=NOT_TESTED
echo R23_C_HARDWARE_INDEPENDENT_IDENTITY=NOT_TESTED
echo R23_C_TPM2_NATIVE_ED25519_KEY_RESIDENCY=NOT_TESTED
