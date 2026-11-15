package planpermit

import(
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
 "strings"
 "sync"
 "sync/atomic"
 "testing"
 "time"
)

func mockTLSWitness(t *testing.T,handler http.Handler)(string,*tls.Config,func()){
 t.Helper()
 _,caPriv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 caTemplate:=&x509.Certificate{
  SerialNumber:big.NewInt(10),Subject:pkix.Name{CommonName:"test independent witness CA"},
  NotBefore:time.Now().Add(-time.Minute),NotAfter:time.Now().Add(time.Hour),
  IsCA:true,BasicConstraintsValid:true,KeyUsage:x509.KeyUsageCertSign,
 }
 caDER,err:=x509.CreateCertificate(rand.Reader,caTemplate,caTemplate,caPriv.Public(),caPriv);if err!=nil{t.Fatal(err)}
 ca,err:=x509.ParseCertificate(caDER);if err!=nil{t.Fatal(err)}
 roots:=x509.NewCertPool();roots.AddCert(ca)
 newLeaf:=func(serial int64,server bool)tls.Certificate{
  t.Helper()
  _,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
  usage:=x509.ExtKeyUsageClientAuth
  if server{usage=x509.ExtKeyUsageServerAuth}
  c:=&x509.Certificate{SerialNumber:big.NewInt(serial),
   Subject:pkix.Name{CommonName:"synthetic witness peer"},
   NotBefore:time.Now().Add(-time.Minute),NotAfter:time.Now().Add(time.Hour),
   KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{usage},
  }
  if server{c.IPAddresses=[]net.IP{net.ParseIP("127.0.0.1")}}
  der,err:=x509.CreateCertificate(rand.Reader,c,ca,priv.Public(),caPriv);if err!=nil{t.Fatal(err)}
  return tls.Certificate{Certificate:[][]byte{der,caDER},PrivateKey:priv}
 }
 serverCert,clientCert:=newLeaf(11,true),newLeaf(12,false)
 s:=httptest.NewUnstartedServer(handler)
 s.TLS=&tls.Config{MinVersion:tls.VersionTLS13,
  Certificates:[]tls.Certificate{serverCert},
  ClientCAs:roots,ClientAuth:tls.RequireAndVerifyClientCert}
 s.StartTLS()
 clientConfig:=&tls.Config{MinVersion:tls.VersionTLS13,
  RootCAs:roots,Certificates:[]tls.Certificate{clientCert}}
 return s.URL,clientConfig,s.Close
}
func TestR22HTTPSWitnessMutualTLS13AtMostOne(t *testing.T){
 var mutex sync.Mutex
 seen:=map[string]bool{}
 endpoint,cfg,closeServer:=mockTLSWitness(t,http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.TLS==nil||r.TLS.Version!=tls.VersionTLS13||len(r.TLS.VerifiedChains)==0||
    r.Method!=http.MethodPost||!strings.HasPrefix(r.URL.Path,"/v1/nonce-reservations/"){
   w.WriteHeader(http.StatusForbidden);return
  }
  key:=strings.TrimPrefix(r.URL.Path,"/v1/nonce-reservations/")
  if !validHex256(key){w.WriteHeader(http.StatusBadRequest);return}
  mutex.Lock();defer mutex.Unlock()
  if seen[key]{w.WriteHeader(http.StatusConflict);return}
  seen[key]=true
  w.WriteHeader(http.StatusCreated)
 }))
 defer closeServer()
 witness,err:=NewRemoteHTTPSNonceWitness(endpoint,cfg);if err!=nil{t.Fatal(err)}
 key:=strings.Repeat("a",64)
 var successes atomic.Int32
 var wg sync.WaitGroup
 for i:=0;i<24;i++{wg.Add(1);go func(){defer wg.Done()
  if witness.ReserveOutsideRollbackDomain(context.Background(),key)==nil{successes.Add(1)}
 }()}
 wg.Wait()
 if successes.Load()!=1{t.Fatalf("accepted %d remote duplicate reservations",successes.Load())}
 if err:=witness.ReserveOutsideRollbackDomain(context.Background(),key);err==nil{t.Fatal("duplicate reused")}
}
func TestR22HTTPSWitnessFailClosedResponsesAndRedirect(t *testing.T){
 var code atomic.Int32;code.Store(http.StatusServiceUnavailable)
 var observed atomic.Int32
 endpoint,cfg,closeServer:=mockTLSWitness(t,http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  observed.Add(1)
  if code.Load()==http.StatusTemporaryRedirect{
   w.Header().Set("Location","https://example.com/v1/nonce-reservations/forged")
  }
  w.WriteHeader(int(code.Load()))
 }))
 defer closeServer()
 witness,err:=NewRemoteHTTPSNonceWitness(endpoint,cfg);if err!=nil{t.Fatal(err)}
 key:=strings.Repeat("b",64)
 for _,status:=range []int32{http.StatusServiceUnavailable,http.StatusTemporaryRedirect,http.StatusOK,http.StatusAccepted,http.StatusConflict}{
  code.Store(status)
  if err:=witness.ReserveOutsideRollbackDomain(context.Background(),key);err==nil{t.Fatalf("HTTP %d accepted",status)}
 }
 if observed.Load()!=5{t.Fatalf("redirect or silent retry occurred, requests=%d",observed.Load())}
 code.Store(http.StatusCreated)
 if err:=witness.ReserveOutsideRollbackDomain(context.Background(),key);err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if err:=witness.ReserveOutsideRollbackDomain(ctx,key);err==nil{t.Fatal("cancelled request accepted")}
}
func TestR22HTTPSWitnessRejectsBadClientSecurityContext(t *testing.T){
 endpoint,cfg,closeServer:=mockTLSWitness(t,http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(http.StatusCreated)}))
 defer closeServer()
 for _,url:=range []string{"http://127.0.0.1:3000",endpoint+"/arbitrary",endpoint+"?target=other","https://user:pass@localhost"}{
  if _,err:=NewRemoteHTTPSNonceWitness(url,cfg);err==nil{t.Fatalf("malformed or insecure URL accepted %q",url)}
 }
 for _,mutate:=range []func(*tls.Config){
  func(c *tls.Config){c.RootCAs=nil},
  func(c *tls.Config){c.InsecureSkipVerify=true},
  func(c *tls.Config){c.MinVersion=tls.VersionTLS12},
  func(c *tls.Config){c.Certificates=nil},
 }{
  clone:=cfg.Clone();mutate(clone)
  if _,err:=NewRemoteHTTPSNonceWitness(endpoint,clone);err==nil{t.Fatal("invalid transport trust admitted")}
 }
 witness,err:=NewRemoteHTTPSNonceWitness(endpoint,cfg);if err!=nil{t.Fatal(err)}
 for _,bad:=range []string{"",strings.Repeat("a",63),strings.Repeat("B",64),"../../etc"}{
  if err:=witness.ReserveOutsideRollbackDomain(context.Background(),bad);err==nil{t.Fatal("malformed nonce key accepted")}
 }
}
