package armgate

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/tls"
 "crypto/x509"
 "crypto/x509/pkix"
 "math/big"
 "net"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "testing"
 "time"

 modeplan "github.com/SemperSupra/agent-dispatch/tools/wyse-modeplan/modeplan"
 planpermit "github.com/SemperSupra/agent-dispatch/tools/wyse-planpermit"
)

// Uses two separately established ephemeral TLS trust domains: the operator
// TLS state from the policy fixture, and a real HTTPS mutual-TLS network
// hop for the remote nonce witness. Its server ledger is IN-MEMORY ONLY.
func testR22RemoteWitness(t *testing.T)(planpermit.ExternalNonceAuthority,*sync.Map,func()){
 t.Helper()
 _,cakey,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 caT:=&x509.Certificate{SerialNumber:big.NewInt(300),Subject:pkix.Name{CommonName:"synthetic remote witness CA"},
  NotBefore:time.Now().Add(-time.Minute),NotAfter:time.Now().Add(time.Hour),
  BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
 caDER,err:=x509.CreateCertificate(rand.Reader,caT,caT,cakey.Public(),cakey)
 if err!=nil{t.Fatal(err)}
 ca,err:=x509.ParseCertificate(caDER);if err!=nil{t.Fatal(err)}
 roots:=x509.NewCertPool();roots.AddCert(ca)
 issue:=func(serial int64,server bool)tls.Certificate{
  _,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
  usage:=x509.ExtKeyUsageClientAuth
  if server{usage=x509.ExtKeyUsageServerAuth}
  leaf:=&x509.Certificate{SerialNumber:big.NewInt(serial),
   NotBefore:time.Now().Add(-time.Minute),NotAfter:time.Now().Add(time.Hour),
   KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{usage}}
  if server{leaf.IPAddresses=[]net.IP{net.ParseIP("127.0.0.1")}}
  der,err:=x509.CreateCertificate(rand.Reader,leaf,ca,priv.Public(),cakey);if err!=nil{t.Fatal(err)}
  return tls.Certificate{Certificate:[][]byte{der,caDER},PrivateKey:priv}
 }
 serverCert,clientCert:=issue(301,true),issue(302,false)
 consumed:=&sync.Map{}
 server:=httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  key:=strings.TrimPrefix(r.URL.Path,"/v1/nonce-reservations/")
  if r.Method!=http.MethodPost||r.TLS==nil||r.TLS.Version!=tls.VersionTLS13||
   len(r.TLS.VerifiedChains)==0||len(key)!=64{
   w.WriteHeader(http.StatusForbidden);return
  }
  if _,loaded:=consumed.LoadOrStore(key,true);loaded{
   w.WriteHeader(http.StatusConflict);return
  }
  w.WriteHeader(http.StatusCreated)
 }))
 server.TLS=&tls.Config{MinVersion:tls.VersionTLS13,Certificates:[]tls.Certificate{serverCert},
  ClientAuth:tls.RequireAndVerifyClientCert,ClientCAs:roots}
 server.StartTLS()
 witness,err:=planpermit.NewRemoteHTTPSNonceWitness(server.URL,
  &tls.Config{MinVersion:tls.VersionTLS13,RootCAs:roots,Certificates:[]tls.Certificate{clientCert}})
 if err!=nil{server.Close();t.Fatal(err)}
 return witness,consumed,server.Close
}
func TestR22SignedPolicyAndRemoteTLSWitnessRejectRestoredLocalReplay(t *testing.T){
 n,p,peer,audience,bundle,roots,epoch,now,_:=signedBundleFixture(t)
 _,_,permit,verifier,_:=prepared(t)
 remote,consumed,closeServer:=testR22RemoteWitness(t)
 defer closeServer()
 base:=t.TempDir()
 root:=filepath.Join(base,"ledger")
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 local,err:=planpermit.NewLinuxNonceStore(root);if err!=nil{t.Fatal(err)}
 dual,err:=planpermit.NewAnchoredNonceStore(local,remote);if err!=nil{t.Fatal(err)}
 next,err:=AuthorizeSignedGrantArm(context.Background(),n,p,permit,verifier,dual,now,
  peer,audience,bundle,roots,epoch)
 if err!=nil||next.Stage!=modeplan.Armed{t.Fatalf("verified signed-policy + mTLS authority denied: %v",err)}
 if !n.GARMHold{t.Fatal("synthetic pure arm bypassed GARM hold")}
 if err:=local.Close();err!=nil{t.Fatal(err)}
 if err:=os.Rename(root,root+"-spent");err!=nil{t.Fatal(err)}
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 restored,err:=planpermit.NewLinuxNonceStore(root);if err!=nil{t.Fatal(err)}
 defer restored.Close()
 dual,err=planpermit.NewAnchoredNonceStore(restored,remote);if err!=nil{t.Fatal(err)}
 if _,err=AuthorizeSignedGrantArm(context.Background(),n,p,permit,verifier,dual,now,
  peer,audience,bundle,roots,epoch);err==nil{
  t.Fatal("old signed permit rearmed after restored local ledger despite remote consumed mark")
 }
 files,err:=os.ReadDir(root)
 if err!=nil||len(files)!=0{t.Fatalf("rejected replay changed restored local ledger: %v %v",files,err)}
 count:=0
 consumed.Range(func(_,_ any)bool{count++;return true})
 if count!=1{t.Fatalf("expected exactly one remote consumed key, got %d",count)}
}
