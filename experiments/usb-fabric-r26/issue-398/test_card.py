#!/usr/bin/env python3
"""R26-N5c: a PCSC card reader/write path with a generated in-memory card.

A vpcd PCSC reader connects to a fake, test-only ISO7816 card on loopback.
Not a USB CCID transport, not a CAC clone, and no real credentials involved.
"""
import os
import socket
import struct
import subprocess
import threading
import time

TEST_AID=bytes.fromhex("F000000001")
ARTIFICIAL_ATR=bytes.fromhex("3B00")  # minimal, synthetic T=0
TEST_BYTES=b"R26-SYNTHETIC-ONLY"
class Card:
 def __init__(self):
  self.memory=bytearray(256)
  self.selected=False
  self.requests=0
 def exchange(self,apdu):
  self.requests+=1
  if len(apdu)<4:return b"\x67\x00"
  cla,ins,p1,p2=apdu[:4]
  if cla!=0:return b"\x6e\x00"
  if ins==0xa4:
   self.selected=(len(apdu)>=5 and apdu[4]==len(TEST_AID) and
                  apdu[5:5+len(TEST_AID)]==TEST_AID)
   return b"\x90\x00" if self.selected else b"\x6a\x82"
  if not self.selected:return b"\x69\x82"
  if ins==0x20:return b"\x69\x82"  # no card PIN path
  offset=p1*256+p2
  if ins==0xd6:
   if len(apdu)<5 or len(apdu)!=5+apdu[4]:return b"\x67\x00"
   count=apdu[4]
   if count==0 or offset+count>len(self.memory):return b"\x6b\x00"
   self.memory[offset:offset+count]=apdu[5:]
   return b"\x90\x00"
  if ins==0xb0:
   if len(apdu)!=5:return b"\x67\x00"
   count=apdu[4]
   if count==0 or offset+count>len(self.memory):return b"\x6b\x00"
   return bytes(self.memory[offset:offset+count])+b"\x90\x00"
  return b"\x6d\x00"
def read_exact(sock,n):
 data=bytearray()
 while len(data)<n:
  piece=sock.recv(n-len(data))
  if not piece:raise ConnectionError("card reader disconnected")
  data.extend(piece)
 return bytes(data)
def serve(card,stop,signals):
 sock=None
 try:
  for _ in range(200):
   if stop.is_set():return
   try:
    sock=socket.create_connection(("127.0.0.1",35963),timeout=2)
    break
   except OSError:
    time.sleep(.1)
  if not sock:raise RuntimeError("vpcd listener never appeared")
  sock.settimeout(5)
  signals.append("connected")
  while not stop.is_set():
   try:
    n=struct.unpack(">H",read_exact(sock,2))[0]
    if n>512:raise RuntimeError("unexpected vpcd card command size")
    req=read_exact(sock,n)
    if n==1 and req in (b"\x00",b"\x01",b"\x02"):
     # Powered off/reset returns no frame by vpicc protocol.
     if req!=b"\x01":card.selected=False
     continue
    if n==1 and req==b"\x04":
     ans=ARTIFICIAL_ATR
    else:
     ans=card.exchange(req)
    sock.sendall(struct.pack(">H",len(ans))+ans)
   except socket.timeout:continue
   except (ConnectionError,OSError):break
 except Exception as e:signals.append(type(e).__name__+": "+str(e)[:150])
 finally:
  if sock:sock.close()

def card_roundtrip():
 from smartcard.System import readers
 from smartcard.Exceptions import CardConnectionException,NoCardException
 found=[]
 for _ in range(60):
  found=readers()
  if found:break
  time.sleep(.2)
 if not found:raise RuntimeError("PCSC virtual reader unavailable")
 print("R26_N5C_REAL_PCSC_VIRTUAL_READER_FOUND=PASS",flush=True)
 c=None
 for _ in range(40):
  try:
   c=found[0].createConnection()
   c.connect()
   break
  except (CardConnectionException,NoCardException):
   time.sleep(.2)
 if c is None:raise RuntimeError("PCSC card did not connect")
 print("R26_N5C_REAL_PCSC_TEST_CARD_CONNECTED=PASS",flush=True)
 atr=c.getATR()
 if not atr:raise RuntimeError("test card ATR absent")
 print("R26_N5C_REAL_PCSC_ATR_PRESENT=PASS",flush=True)
 def transmit(message):
  data,sw1,sw2=c.transmit(list(message))
  return bytes(data),(sw1<<8)|sw2
 _,sw=transmit(b"\x00\xa4\x04\x00\x05"+bytes.fromhex("F000000002"))
 if sw!=0x6a82:raise RuntimeError("wrong AID was not denied")
 print("R26_N5C_PCSC_WRONG_APPLET_AID_DENIED=PASS",flush=True)
 _,sw=transmit(b"\x00\xa4\x04\x00\x05"+TEST_AID)
 if sw!=0x9000:raise RuntimeError("synthetic applet not selected")
 print("R26_N5C_REAL_PCSC_TEST_APPLET_SELECT=PASS",flush=True)
 _,sw=transmit(b"\x00\x20\x00\x00\x00")
 if sw!=0x6982:raise RuntimeError("PIN VERIFY path was not denied")
 print("R26_N5C_PCSC_PIN_VERIFY_DENIED=PASS",flush=True)
 _,sw=transmit(b"\x00\xd6\x00\x00"+bytes([len(TEST_BYTES)])+TEST_BYTES)
 if sw!=0x9000:raise RuntimeError("test-only UPDATE BINARY failed")
 print("R26_N5C_REAL_PCSC_TEST_CARD_UPDATE_BINARY=PASS",flush=True)
 data,sw=transmit(b"\x00\xb0\x00\x00"+bytes([len(TEST_BYTES)]))
 if sw!=0x9000 or data!=TEST_BYTES:raise RuntimeError("test-only READ BINARY differed from write")
 print("R26_N5C_REAL_PCSC_TEST_CARD_READ_AFTER_WRITE=PASS",flush=True)
 c.disconnect()
 c=found[0].createConnection();c.connect()
 _,sw=transmit(b"\x00\xa4\x04\x00\x05"+TEST_AID)
 if sw!=0x9000:raise RuntimeError("test card not selectable after reconnect")
 data,sw=transmit(b"\x00\xb0\x00\x00"+bytes([len(TEST_BYTES)]))
 if sw!=0x9000 or data!=TEST_BYTES:
  raise RuntimeError("test card read failed after PCSC reconnect")
 print("R26_N5C_PCSC_RECONNECT_TEST_CARD_DATA_PERSISTED=PASS",flush=True)
 c.disconnect()
 print("R26_N5C_REAL_CAC_AND_USB_CCID_TRANSPORT=NOT_TESTED",flush=True)

def main():
 stop=threading.Event()
 stderr=subprocess.DEVNULL
 pcsc=subprocess.Popen(["pcscd","--foreground","--disable-polkit"],stdout=stderr,stderr=stderr)
 card=Card();signals=[]
 thread=threading.Thread(target=serve,args=(card,stop,signals),daemon=True)
 thread.start()
 try:
  card_roundtrip()
  if not signals or signals[0]!="connected":
   raise RuntimeError("virtual reader/card transport never connected")
  if card.requests<7:raise RuntimeError("missing required APDU exchanges")
  print("R26_N5C_REAL_PCSC_WRITABLE_TEST_APPLET_END_TO_END=PASS",flush=True)
 finally:
  stop.set()
  pcsc.terminate()
  try:pcsc.wait(timeout=3)
  except subprocess.TimeoutExpired:pcsc.kill();pcsc.wait()
  thread.join(timeout=3)
if __name__=="__main__":
 main()
