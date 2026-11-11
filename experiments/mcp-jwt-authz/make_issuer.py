#!/usr/bin/env python3
"""Disposable P-256 issuer + JWT tokens for public-safe authz tests. No real identities."""
import base64,json,subprocess,time,pathlib,hashlib
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def derint(buf,pos):
 if buf[pos]!=2: raise ValueError("bad DER integer")
 size=buf[pos+1]; pos+=2
 if size&128:
  nb=size&127;size=int.from_bytes(buf[pos:pos+nb],"big");pos+=nb
 return int.from_bytes(buf[pos:pos+size],"big"),pos+size
def sign(payload):
 h={"alg":"ES256","typ":"JWT","kid":"synthetic-key"}
 material=b64(json.dumps(h,separators=(",",":")).encode())+"."+b64(json.dumps(payload,separators=(",",":")).encode())
 sig=subprocess.check_output(["openssl","dgst","-sha256","-sign","private.pem"],input=material.encode())
 if sig[0]!=0x30:raise ValueError("wrong DER sig")
 pos=2
 if sig[1]&128:pos=2+(sig[1]&127)
 r,pos=derint(sig,pos);s,pos=derint(sig,pos)
 return material+"."+b64(r.to_bytes(32,"big")+s.to_bytes(32,"big"))
def main():
 subprocess.run(["openssl","ecparam","-genkey","-name","prime256v1","-noout","-out","private.pem"],check=True)
 der=subprocess.check_output(["openssl","pkey","-in","private.pem","-pubout","-outform","DER"],stderr=subprocess.DEVNULL)
 point=der[-65:]
 if point[0]!=4:raise ValueError("unexpected public key")
 jwk={"keys":[{"kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":"synthetic-key","x":b64(point[1:33]),"y":b64(point[33:])}]}
 pathlib.Path("jwks.json").write_text(json.dumps(jwk))
 now=int(time.time())
 for principal in ["alpha","beta","revoked"]:
  token=sign({"iss":"m1-synthetic-issuer","aud":"m1-synthetic-client","sub":principal,"iat":now,"exp":now+600})
  pathlib.Path("token-"+principal+".txt").write_text(token)
 pathlib.Path("issuer-evidence.json").write_text(json.dumps({"issuer":"m1-synthetic-issuer","aud":"m1-synthetic-client",
  "tokenSubjects":["alpha","beta","revoked"],"publicJWKHash":hashlib.sha256(pathlib.Path("jwks.json").read_bytes()).hexdigest(),
  "note":"ephemeral generated public-safe issuer; never upload private.pem or token files"},indent=2))
if __name__=="__main__":main()
