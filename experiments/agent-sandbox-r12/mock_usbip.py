#!/usr/bin/env python3
"""R12: public synthetic USB/IP v1.1.1 protocol interoperability, no real USB.
A standard upstream usbip CLI discovers a mock USB HID via OP_REQ_DEVLIST.
OP_REQ_IMPORT is deliberately denied; no USB URBs or vHCI attach.
All components run in one no-network disposable OCI cell (loopback only).
"""
import socket
import struct
import subprocess
import threading
import time

VERSION=0x0111
REQ_LIST=0x8005
REP_LIST=0x0005
REQ_IMPORT=0x8003
REP_IMPORT=0x0003
PORT=3240
busid=b"1-1"
events=[]
stop=threading.Event()
ready=threading.Event()

def fixed(text,size):
 if len(text)>=size:raise ValueError("oversized string")
 return text+b"\0"*(size-len(text))

def recv_exact(conn,n):
 out=b""
 while len(out)<n:
  part=conn.recv(n-len(out))
  if not part:raise RuntimeError("short protocol request")
  out+=part
 return out

def device_record():
 # Structure defined by the Linux kernel's USB/IP protocol reference.
 path=fixed(b"/sys/devices/virtual/usbip/r12-synthetic",256)
 name=fixed(busid,32)
 fields=struct.pack("!IIIHHHBBBBBB",
   1,2,3,0x1209,0x0001,0x0100,3,1,1,1,1,1)
 iface=bytes([3,1,1,0])
 record=path+name+fields+iface
 if len(record)!=316:raise RuntimeError("invalid synthetic descriptor length")
 return record

def serve():
 srv=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
 srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 srv.bind(("127.0.0.1",PORT))
 srv.listen(3)
 srv.settimeout(.2)
 ready.set()
 try:
  while not stop.is_set():
   try:conn,_=srv.accept()
   except socket.timeout:continue
   with conn:
    conn.settimeout(4)
    version,opcode,status=struct.unpack("!HHI",recv_exact(conn,8))
    if version!=VERSION or status!=0:
     events.append("bad_header")
     continue
    if opcode==REQ_LIST:
     conn.sendall(struct.pack("!HHII",VERSION,REP_LIST,0,1)+device_record())
     events.append("list")
    elif opcode==REQ_IMPORT:
     requested=recv_exact(conn,32).split(b"\0",1)[0]
     conn.sendall(struct.pack("!HHI",VERSION,REP_IMPORT,1))
     events.append("import_denied_"+requested.decode("ascii","replace"))
    else:
     events.append("unknown_rejected")
 finally:srv.close()

def main():
 worker=threading.Thread(target=serve,daemon=True)
 worker.start()
 if not ready.wait(3):raise RuntimeError("mock USB/IP loopback listener missing")
 try:
  result=subprocess.run(["usbip","list","--remote=127.0.0.1"],
     stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=12)
  if result.returncode!=0 or "1-1" not in result.stdout:
   print("R12_REAL_USBIP_CLI_DEVICE_LIST=RED",result.returncode,
         result.stdout[-800:],result.stderr[-800:])
   raise SystemExit(10)
  print("R12_REAL_OPEN_SOURCE_USBIP_CLIENT_LIST=PASS")
  with socket.create_connection(("127.0.0.1",PORT),timeout=2) as s:
   s.sendall(struct.pack("!HHI",VERSION,REQ_IMPORT,0)+fixed(busid,32))
   reply=recv_exact(s,8)
   v,code,status=struct.unpack("!HHI",reply)
   if (v,code,status)!=(VERSION,REP_IMPORT,1):
    raise RuntimeError("import unexpectedly authorized: "+str((v,code,status)))
  print("R12_SYNTHETIC_DEVICE_IMPORT_FAIL_CLOSED=PASS")
  for _ in range(30):
   if "list" in events and "import_denied_1-1" in events:break
   time.sleep(.02)
  if events.count("list")!=1 or events.count("import_denied_1-1")!=1:
   raise RuntimeError("missing independent mock protocol receipts "+str(events))
  print("R12_PROTOCOL_DEVICE_LIST_AND_DENY_OBSERVED=PASS")
  print("R12_REAL_USB_HUB_DRIVER_FORWARDING=NOT_TESTED")
  print("R12_GUEST_KERNEL_VHCI_ATTACH=NOT_TESTED")
  print("R12_USBIP_BUILTIN_AUTHENTICATION_ENCRYPTION=ABSENT")
 finally:
  stop.set()
  worker.join(timeout=2)
if __name__=="__main__":main()
