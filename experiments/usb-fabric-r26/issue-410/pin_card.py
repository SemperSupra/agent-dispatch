#!/usr/bin/env python3
"""R26-P1b actual PCSC reader, disposable software *test card* with test PIN.

This is NOT an issued CAC and NOT a USB CCID backend. Never log APDU data,
the test PIN, private key, card identity, or raw certificate. A real product
must use OS-approved protected real-PIN entry, not this automated test prompt.
"""
import hmac,os,subprocess,threading,time
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from base_card import Card,serve,TEST_AID
from smartcard.System import readers
from smartcard.Exceptions import CardConnectionException,NoCardException
from smartcard.pcsc.PCSCExceptions import EstablishContextException

# Deliberately fictional lab-only test PIN, NEVER a personal credential.
TEST_ONLY_PIN=b"246813"
TEST_ONLY_FILE=b"R26-PIN-AUTHORIZED-WRITE"
def status(sw):return sw.to_bytes(2,"big")

class AuthTestCard(Card):
 def __init__(self):
  self._selected=False
  self.verified=False
  super().__init__()
  self.retries=3
  self.blocked=False
  self.key=ec.generate_private_key(ec.SECP256R1())
 @property
 def selected(self):return self._selected
 @selected.setter
 def selected(self,value):
  if not value:self.verified=False
  self._selected=bool(value)
 def exchange(self,apdu):
  self.requests+=1
  if len(apdu)<4:return status(0x6700)
  cla,ins,p1,p2=apdu[:4]
  if cla!=0:return status(0x6e00)
  if ins==0xa4:
   self.verified=False
   # Parent implementation counts APDUs; no raw data logging.
   return super().exchange(apdu)
  if not self.selected:return status(0x6982)
  if ins==0x20:  # ISO 7816 VERIFY on test-only card
   if self.blocked:return status(0x6983)
   if len(apdu)<5 or len(apdu)!=5+apdu[4]:return status(0x6700)
   attempted=bytearray(apdu[5:])
   try:
    good=hmac.compare_digest(attempted,TEST_ONLY_PIN)
   finally:
    for i in range(len(attempted)):attempted[i]=0
   if not good:
    self.retries-=1
    self.verified=False
    if self.retries==0:
     self.blocked=True
     return status(0x6983)
    return status(0x63c0|self.retries)
   self.retries=3
   self.verified=True
   return status(0x9000)
  if ins==0xca and p1==1 and p2==1: # read test public P-256 point
   point=self.key.public_key().public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint)
   return point+status(0x9000)
  if ins==0x2a and p1==0x9e and p2==0x9a: # test-only signature
   if not self.verified:return status(0x6982)
   if len(apdu)!=37 or apdu[4]!=32:return status(0x6700)
   return self.key.sign(apdu[5:],ec.ECDSA(hashes.SHA256()))+status(0x9000)
  if ins==0xd6: # guest test applet writes PIN-gated
   if not self.verified:return status(0x6982)
   return super().exchange(apdu)
  if ins==0xfe: # test-only explicit logout
   self.verified=False
   return status(0x9000)
  return super().exchange(apdu)

def get_connection():
 found=[]
 for _ in range(80):
  try:
   found=readers()
  except EstablishContextException:
   time.sleep(.2)
   continue
  if found:break
  time.sleep(.2)
 if not found:raise RuntimeError("real PCSC virtual reader missing")
 print("R26_P1B_REAL_PCSC_READER_DISCOVERED=PASS",flush=True)
 c=None
 for _ in range(50):
  try:
   c=found[0].createConnection()
   c.connect()
   break
  except (CardConnectionException,NoCardException):
   time.sleep(.2)
 if c is None:raise RuntimeError("test card did not connect")
 if not c.getATR():raise RuntimeError("test-only ATR not returned")
 print("R26_P1B_REAL_PCSC_CARD_CONNECTED_ATR=PASS",flush=True)
 return c

def tx(c,frame):
 # pyscard performs real PCSC transmit through vpcd/vpicc socket transport;
 # never print raw frame/response.
 data,sw1,sw2=c.transmit(list(frame))
 return bytes(data),(sw1<<8)|sw2
def expect(c,frame,wanted,label):
 _,sw=tx(c,frame)
 if sw!=wanted:raise RuntimeError(f"{label}: status {sw:04x} expected {wanted:04x}")
 print(label+"=PASS",flush=True)

def run_workflow():
 c=get_connection()
 wrong_aid=b"\x00\xa4\x04\x00\x05"+bytes.fromhex("F000000002")
 select=b"\x00\xa4\x04\x00\x05"+TEST_AID
 expect(c,wrong_aid,0x6a82,"R26_P1B_WRONG_APPLET_DENIED")
 expect(c,select,0x9000,"R26_P1B_TEST_APPLET_SELECTED")
 challenge=os.urandom(32)
 sign=b"\x00\x2a\x9e\x9a\x20"+challenge
 expect(c,sign,0x6982,"R26_P1B_SIGNING_WITHOUT_PIN_DENIED")
 write=b"\x00\xd6\x00\x00"+bytes([len(TEST_ONLY_FILE)])+TEST_ONLY_FILE
 expect(c,write,0x6982,"R26_P1B_WRITING_WITHOUT_PIN_DENIED")
 wrong=b"\x00\x20\x00\x00\x06"+b"999999"
 expect(c,wrong,0x63c2,"R26_P1B_WRONG_PIN_RETRY_DECREMENTED")
 # A test prompt stands in for the protected OS PIN dialog; no echo to logs.
 def test_only_prompt():
  return bytearray(TEST_ONLY_PIN)
 entered=test_only_prompt()
 try:
  expect(c,b"\x00\x20\x00\x00"+bytes([len(entered)])+entered,
         0x9000,"R26_P1B_TEST_PIN_SUBMITTED_OVER_PCSC")
 finally:
  for i in range(len(entered)):entered[i]=0
 point,sw=tx(c,b"\x00\xca\x01\x01")
 if sw!=0x9000:raise RuntimeError("synthetic card public key unavailable")
 public=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),point)
 signature,sw=tx(c,sign)
 if sw!=0x9000 or not signature:raise RuntimeError("card-mediated test signature failed")
 public.verify(signature,challenge,ec.ECDSA(hashes.SHA256()))
 print("R26_P1B_PCSC_PIN_GATED_P256_CHALLENGE_SIGNATURE_VERIFIED=PASS",flush=True)
 tampered=bytearray(challenge);tampered[0]^=1
 try:public.verify(signature,tampered,ec.ECDSA(hashes.SHA256()))
 except InvalidSignature:
  print("R26_P1B_TAMPERED_CHALLENGE_REJECTED=PASS",flush=True)
 else:raise RuntimeError("tampered challenge accepted")
 expect(c,write,0x9000,"R26_P1B_PIN_GATED_TEST_APPLET_UPDATE")
 data,sw=tx(c,b"\x00\xb0\x00\x00"+bytes([len(TEST_ONLY_FILE)]))
 if sw!=0x9000 or data!=TEST_ONLY_FILE:raise RuntimeError("test file readback wrong")
 print("R26_P1B_REAL_PCSC_TEST_WRITE_READBACK=PASS",flush=True)
 expect(c,b"\x00\xfe\x00\x00",0x9000,"R26_P1B_TEST_SESSION_LOGOUT")
 expect(c,sign,0x6982,"R26_P1B_SIGN_AFTER_LOGOUT_DENIED")
 # Deliberately exhaust a second set of wrong test PIN attempts.
 expect(c,wrong,0x63c2,"R26_P1B_PIN_RETRY_AFTER_LOGOUT")
 expect(c,wrong,0x63c1,"R26_P1B_PIN_RETRY_FINAL_WARNING")
 expect(c,wrong,0x6983,"R26_P1B_TEST_PIN_LOCKOUT")
 expect(c,b"\x00\x20\x00\x00\x06"+TEST_ONLY_PIN,0x6983,
        "R26_P1B_LOCKOUT_CORRECT_PIN_STILL_DENIED")
 c.disconnect()
 print("R26_P1B_FULL_SYNTHETIC_PCSC_PIN_SIGN_AND_WRITE_WORKFLOW=PASS",flush=True)
 print("R26_P1B_ACTUAL_USB_CCID_VIRTUAL_CAC_HARDWARE_PIN=NOT_TESTED",flush=True)

def main():
 pcsc=subprocess.Popen(["pcscd","--foreground","--disable-polkit"],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 card=AuthTestCard()
 stop=threading.Event(); signals=[]
 thread=threading.Thread(target=serve,args=(card,stop,signals),daemon=True)
 thread.start()
 try:
  run_workflow()
  if not signals or signals[0]!="connected" or card.requests<14:
   raise RuntimeError("PCSC virtual card transport lacked required exchanges")
 finally:
  stop.set()
  pcsc.terminate()
  try:pcsc.wait(timeout=4)
  except subprocess.TimeoutExpired:pcsc.kill();pcsc.wait()
  thread.join(timeout=4)
if __name__=="__main__":main()
