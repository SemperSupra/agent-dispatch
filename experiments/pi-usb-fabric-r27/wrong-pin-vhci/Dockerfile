# syntax=docker/dockerfile:1.7
# Isolated disposable TEST-only host-key substitution, never alter guest seed.
ARG PARENT
FROM ${PARENT}
USER root
RUN python3 - <<'PY'
from pathlib import Path
p=Path("/guest/r27-approved-public.hex")
v=p.read_text().strip()
if len(v)!=64 or any(c not in "0123456789abcdef" for c in v):
    raise SystemExit("invalid original approved TEST public key")
wrong=("0" if v[0]!="0" else "1")+v[1:]
if wrong==v:raise SystemExit("wrong host pin not modified")
p.write_text(wrong+"\n")
p.chmod(0o644)
print("R27_E_WRONG_HOST_PIN_DERIVED_WITHOUT_GUEST_INITRD_CHANGE=PASS")
PY
COPY experiments/pi-usb-fabric-r27/wrong-pin-vhci/deny.sh /guest/r27-e-deny.sh
USER 65532:65532
ENTRYPOINT ["/bin/sh","/guest/r27-e-deny.sh"]
