#!/usr/bin/env python3
"""Actual QEMU synthetic USB guest, independently preboot WRONG host pin.

Negative acceptance: the running guest may produce legitimate, correctly
Ed25519-signed evdev events, but its public key differs from the pre-enrolled
host pin. Existing sole R26 actuator must refuse the receipt, preserve HELD,
and deny the next lease. No production trust or hardware secrets.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

spec=importlib.util.spec_from_file_location(
    "r26_positive_oracle","/guest/r26-l9c-scoped-release-detach-oracle.py")
test=importlib.util.module_from_spec(spec)
spec.loader.exec_module(test)

def run():
    preapproved=Path("/guest/r26-preapproved-pub.hex").read_text().strip()
    if len(preapproved)!=64:raise RuntimeError("wrong preapproved test public key")
    # A different 32-byte public value is independently enrolled before
    # QEMU exists. Never mutate the guest image or disclose its private seed.
    wrong=("0" if preapproved[0]!="0" else "1")+preapproved[1:]
    if wrong==preapproved:raise RuntimeError("failed wrong signer negative")
    with tempfile.TemporaryDirectory(prefix="r26-wrong-pin-",dir="/tmp") as d:
        root=Path(d)
        approved=root/"preenrolled-wrong.pub"
        approved.write_text(wrong+"\n")
        os.chmod(approved,0o600)
        print("R26_B_WRONG_HOST_PIN_ESTABLISHED_BEFORE_QEMU_BOOT=PASS",flush=True)
        nonce=os.urandom(32).hex()
        media=root/"synthetic.img"
        marker=b"R26-B-NEGATIVE-DISPOSABLE"
        media.write_bytes(marker+bytes(2097152-len(marker)))
        original=hashlib.sha256(media.read_bytes()).hexdigest()
        journal=root/"held.json"
        pcap=root/"usb.pcap"
        qmp=str(root/"qmp.sock")
        receipt=str(root/"receipt.sock")
        api=str(root/"api.sock")
        qemu=actuator=first=second=None
        try:
            qemu=subprocess.Popen([
                "qemu-system-x86_64","-machine","q35","-accel","tcg",
                "-cpu","qemu64","-m","1024M","-smp","1","-S",
                "-nodefaults","-display","none","-monitor","none",
                "-serial","stdio","-net","none","-no-reboot",
                "-kernel","/guest/kernel","-initrd","/guest/initrd.gz",
                "-append","console=ttyS0 rdinit=/init loglevel=7 panic=-1 r26_scoped=1 r22_challenge="+nonce,
                "-device","qemu-xhci,id=xhci0",
                "-device","virtio-serial-pci,id=vs0",
                "-chardev","socket,id=receipt,path="+receipt+",server=on,wait=off",
                "-device","virtserialport,chardev=receipt,name=org.r26.receipts",
                "-qmp","unix:"+qmp+",server=on,wait=off",
            ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            qlogs=test.Lines(qemu)
            env=dict(os.environ,R24_APPROVED_GUEST_KEY_PATH=str(approved),R24_GUEST_NONCE=nonce)
            actuator=subprocess.Popen([
                "/guest/r26-actuator","--qmp",qmp,"--socket",api,
                "--media",str(media),"--capture",str(pcap),
                "--journal",str(journal),"--receipt",receipt,"--scoped-receipts",
            ],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=env)
            alogs=test.Lines(actuator)
            alogs.wait("R26_L_SOLE_QMP_ACTUATOR_LISTENING=PASS",20)
            first=subprocess.Popen(["/guest/r26-frontend","--socket",api],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,text=True,bufsize=1)
            test.ready(first,'"state":"frontend-ready"')
            lease=test.request(first,{"op":"reserve","actor":"approved-agent"})
            test.expect(lease,True,"R26_B_NEGATIVE_INITIAL_LEASE")
            base={"actor":"approved-agent","epoch":lease["epoch"],"generation":lease["generation"]}
            test.expect(test.request(first,dict(base,op="attach")),True,
                "R26_B_NEGATIVE_REAL_QMP_USB_DEVICE_ATTACHED")
            test.expect(test.request(first,dict(base,op="start")),True,
                "R26_B_NEGATIVE_REAL_GUEST_BOOTED")
            qlogs.wait("R24_B_GUEST_PUBLIC_KEY=",40)
            with qlogs.cv:
                vals=[v for v in qlogs.lines if "R24_B_GUEST_PUBLIC_KEY=" in v]
            if len(vals)!=1:raise RuntimeError("ambiguous real guest key")
            published=vals[0].split("R24_B_GUEST_PUBLIC_KEY=",1)[1].strip()
            if published!=preapproved or published==wrong:
                raise RuntimeError("preboot wrong-pin test did not select original real guest")
            qlogs.wait("R26_L8_REAL_GUEST_VIRTIO_EVDEV_OBSERVER_READY=PASS")
            alogs.wait("R26_L9C_HOST_PER_LEASE_SCOPE_BOUND=PASS")
            test.expect(test.request(first,dict(base,op="input",command="key-a-down")),True,
                "R26_B_NEGATIVE_GUEST_INPUT_DOWN_DELIVERED")
            alogs.wait("R24_B_WIRE_KEY_NOT_HOST_PINNED_REJECTED=PASS",35)
            st=json.loads(journal.read_text())
            if not st.get("held") or st.get("sequence")!=1:
                raise RuntimeError("wrong-key DOWN unexpectedly cleared HELD")
            print("R26_B_WRONG_ED25519_SIGNER_ACTUAL_GUEST_RECEIPT_DENIED=PASS",flush=True)
            first.kill();first.wait(timeout=5);first=None
            alogs.wait("R26_L_ACK_ONLY_RELEASE_QUARANTINED_PENDING_GUEST_PROOF=PASS",35)
            st=json.loads(journal.read_text())
            if not st.get("held") or st.get("sequence")!=1:
                raise RuntimeError("wrong-key ACK or guest UP cleared durable HELD")
            second=subprocess.Popen(["/guest/r26-frontend","--socket",api],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                text=True,bufsize=1)
            test.ready(second,'"state":"frontend-ready"')
            denied=test.request(second,{"op":"reserve","actor":"approved-agent"})
            test.expect(denied,False,"R26_B_WRONG_KEY_SECOND_LEASE_DENIED")
            if hashlib.sha256(media.read_bytes()).hexdigest()!=original:
                raise RuntimeError("synthetic media changed during wrong-key denial")
            print("R26_B_WRONG_HOST_PIN_HELD_AND_NO_READMISSION=PASS",flush=True)
            print("R26_B_WRONG_PIN_USES_REAL_QMP_NOT_USBIP=PASS",flush=True)
        finally:
            for p in (second,first,actuator,qemu):test.stop(p)
            print("R26_B_WRONG_KEY_ALL_DISPOSABLE_PROCESSES_STOPPED=PASS",flush=True)

if __name__=="__main__":
    run()
