#!/bin/sh
# Real Linux PID1 inside disposable QEMU VM, attached to upstream swtpm TPM2.
# QEMU host controls TPM emulator; this is NOT hardware or identity attestation.
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
set -eu
mkdir -p /proc /sys /dev /tmp
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
echo R24_C_REAL_LINUX_GUEST_PID1=PASS
for mod in tpm tpm_tis tpm_tis_core tpm_crb; do
 /sbin/modprobe "$mod" 2>/dev/null || true
done
n=0
while [ ! -c /dev/tpm0 ] && [ "$n" -lt 25 ];do
 sleep 1
 n=$((n+1))
done
if [ ! -c /dev/tpm0 ];then
 echo R24_C_GUEST_TPM_TIS_CHARACTER_DEVICE=RED
 ls -l /dev/tpm* /sys/class/tpm 2>/dev/null || true
 poweroff -f || true
 exit 22
fi
echo R24_C_GUEST_TPM_TIS_CHARACTER_DEVICE=PASS
export TPM2TOOLS_TCTI="device:/dev/tpm0"
cd /tmp
if ! tpm2_getrandom -Q 16 -o random.bin;then
 echo R24_C_REAL_GUEST_TPM_GETRANDOM=RED
 poweroff -f || true
 exit 23
fi
test "$(wc -c < random.bin)" -eq 16
echo R24_C_REAL_GUEST_TPM_GETRANDOM=PASS
tpm2_pcrread -Q --pcrs_format serialized -o before.pcr sha256:0,1,2
test -s before.pcr
echo R24_C_REAL_GUEST_TPM_PCR_READ=PASS
tpm2_createek -Q -c 0x81010001 -G rsa -u ekpub.pem -f pem
tpm2_createak -Q -C 0x81010001 -c ak.ctx -G rsa -s rsassa -g sha256 -u akpub.pem -f pem -n ak.name
tpm2_flushcontext -t
nonce="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
test "${#nonce}" -eq 32
tpm2_quote -Q -c ak.ctx -l sha256:0,1,2 -q "$nonce" -m quote.msg -s quote.sig -o quote.pcrs -g sha256
tpm2_checkquote -Q -u akpub.pem -m quote.msg -s quote.sig -f quote.pcrs -g sha256 -q "$nonce"
echo R24_C_REAL_GUEST_TPM_NONCE_QUOTE_VERIFIED=PASS
wrong="00000000000000000000000000000000"
if [ "$nonce" = "$wrong" ];then wrong="ffffffffffffffffffffffffffffffff";fi
if tpm2_checkquote -Q -u akpub.pem -m quote.msg -s quote.sig -f quote.pcrs -g sha256 -q "$wrong" >/tmp/wrong-nonce.log 2>&1;then
 echo R24_C_GUEST_TPM_WRONG_NONCE=RED;poweroff -f || true;exit 25
fi
echo R24_C_GUEST_TPM_WRONG_NONCE_DENIED=PASS
printf 'R24-C-ACTUAL-GUEST-PCR-EVENT\n' > pcr-event.bin
tpm2_pcrevent 0 pcr-event.bin >/dev/null
tpm2_pcrread -Q --pcrs_format serialized -o changed.pcr sha256:0,1,2
if cmp -s quote.pcrs changed.pcr;then
 echo R24_C_GUEST_PCR_EVENT_NO_CHANGE=RED;poweroff -f || true;exit 26
fi
if tpm2_checkquote -Q -u akpub.pem -m quote.msg -s quote.sig -f changed.pcr -g sha256 -q "$nonce" >/tmp/wrong-pcr.log 2>&1;then
 echo R24_C_GUEST_CHANGED_PCR_STILL_ADMITTED=RED;poweroff -f || true;exit 27
fi
echo R24_C_REAL_GUEST_CHANGED_PCR_QUOTE_DENIED=PASS
echo R24_C_REAL_QEMU_GUEST_SWTMP_TPM2_COMMANDS=PASS
echo R24_C_SOFTWARE_TPM_HOST_CONTROLS_IDENTITY=NOT_TESTED
poweroff -f || true
sleep 3
exit 0
