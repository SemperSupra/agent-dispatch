package authz

import (
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/tls"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/pem"
 "math/big"
 "net/http"
 "net/http/httptest"
 "testing"
 "time"
 "sync"
)

func serial(t *testing.T)*big.Int {t.Helper();n,err:=rand.Int(rand.Reader,new(big.Int).Lsh(big.NewInt(1),120));if err!=nil{t.Fatal(err)};return n}
func key(t *testing.T)*ecdsa.PrivateKey{t.Helper();k,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)};return k}
func cert(t *testing.T,ca *x509.Certificate,caKey *ecdsa.PrivateKey,role string,server bool)(tls.Certificate,*x509.Certificate){
 t.Helper()
 k:=key(t)
 tmpl:=&x509.Certificate{SerialNumber:serial(t),Subject:pkix.Name{CommonName:role},NotBefore:time.Now().Add(-time.Minute),NotAfter:time.Now().Add(time.Hour),BasicConstraintsValid:true}
 if server{tmpl.DNSNames=[]string{"localhost"};tmpl.IPAddresses=nil;tmpl.ExtKeyUsage=[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}else{tmpl.ExtKeyUsage=[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
 tmpl.KeyUsage=x509.KeyUsageDigitalSignature
 if ca==nil{ca=tmpl;ca.IsCA=true;ca.KeyUsage=x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature;ca.BasicConstraintsValid=true;caKey=k}
 der,err:=x509.CreateCertificate(rand.Reader,tmpl,ca,&k.PublicKey,caKey);if err!=nil{t.Fatal(err)}
 parsed,err:=x509.ParseCertificate(der);if err!=nil{t.Fatal(err)}
 pemKey,err:=x509.MarshalECPrivateKey(k);if err!=nil{t.Fatal(err)}
 chain,err:=tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),pem.EncodeToMemory(&pem.Block{Type:"EC PRIVATE KEY",Bytes:pemKey}));if err!=nil{t.Fatal(err)}
 return chain,parsed
}
func TestActualTLSAudienceScopesAndRefusal(t *testing.T) {
 rootKey:=key(t)
 rootTmpl:=&x509.Certificate{SerialNumber:serial(t),Subject:pkix.Name{CommonName:"synthetic-ca"},NotBefore:time.Now().Add(-time.Minute),NotAfter:time.Now().Add(2*time.Hour),IsCA:true,BasicConstraintsValid:true,KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature}
 der,err:=x509.CreateCertificate(rand.Reader,rootTmpl,rootTmpl,&rootKey.PublicKey,rootKey);if err!=nil{t.Fatal(err)}
 root,err:=x509.ParseCertificate(der);if err!=nil{t.Fatal(err)}
 pool:=x509.NewCertPool();pool.AddCert(root)
 serverIdentity,_:=cert(t,root,rootKey,"localhost",true)
 roles:=[]struct{role Audience; grants []Capability}{
  {Human,[]Capability{InventoryRead,EnrollmentWitness,KeyRotationApprove}},
  {Automation,[]Capability{InventoryRead,EnrollmentPropose,RecoveryPlan}},
  {Agent,[]Capability{InventoryRead,RecoveryPlan,EvidenceAppend}},
 }
 clients:=map[Audience]tls.Certificate{}
 grants:=map[[32]byte]Grant{}
 for _,row:=range roles {
  client,c:=cert(t,root,rootKey,string(row.role),false)
  clients[row.role]=client
  fp,_:=Fingerprint(c)
  allow:=map[Capability]bool{}
  for _,cap:=range row.grants{allow[cap]=true}
  grants[fp]=Grant{Role:row.role,Capabilities:allow}
 }
 auth,err:=New(grants);if err!=nil{t.Fatal(err)}
 server:=httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  cap:=Capability(r.URL.Query().Get("cap"))
  p,err:=auth.Check(r,cap)
  if err!=nil{w.WriteHeader(http.StatusForbidden);return}
  w.WriteHeader(http.StatusOK)
  _,_=w.Write([]byte(p.Audience))
 }))
 server.TLS=&tls.Config{Certificates:[]tls.Certificate{serverIdentity},ClientAuth:tls.RequireAndVerifyClientCert,ClientCAs:pool,MinVersion:tls.VersionTLS13}
 server.StartTLS();defer server.Close()
 clientFor:=func(certs []tls.Certificate)*http.Client{
  return &http.Client{Timeout:3*time.Second,Transport:&http.Transport{TLSClientConfig:&tls.Config{RootCAs:pool,Certificates:certs,MinVersion:tls.VersionTLS13}}}
 }
 check:=func(c *http.Client,cap Capability,claim string,want int){
  t.Helper()
  req,_:=http.NewRequest("GET",server.URL+"/?cap="+string(cap),nil)
  req.Header.Set("X-Actor",claim)
  req.Header.Set("X-Forwarded-Client-Cert","FORGED")
  resp,err:=c.Do(req)
  if want==-1 {if err==nil{resp.Body.Close();t.Fatal("missing TLS certificate was admitted")};return}
  if err!=nil{t.Fatal(err)}
  resp.Body.Close()
  if resp.StatusCode!=want{t.Fatalf("cap %s spoof=%s expected=%d got=%d",cap,claim,want,resp.StatusCode)}
 }
 for _,row:=range roles{
  c:=clientFor([]tls.Certificate{clients[row.role]})
  check(c,InventoryRead,"superuser",200)
  for _,allowed:=range row.grants{check(c,allowed,"human",200)}
 }
 check(clientFor([]tls.Certificate{clients[Agent]}),EnrollmentWitness,"human",403)
 check(clientFor([]tls.Certificate{clients[Human]}),RecoveryPlan,"agent",403)
 check(clientFor([]tls.Certificate{clients[Automation]}),EvidenceAppend,"agent",403)
 check(clientFor([]tls.Certificate{clients[Human]}),Capability("firmware.flash"),"human",403)
 check(clientFor(nil),InventoryRead,"human",-1)
 unknown,_:=cert(t,root,rootKey,"unknown",false)
 check(clientFor([]tls.Certificate{unknown}),InventoryRead,"human",403)
 foreignKey:=key(t)
 foreignDer,_:=x509.CreateCertificate(rand.Reader,rootTmpl,rootTmpl,&foreignKey.PublicKey,foreignKey)
 foreignRoot,_:=x509.ParseCertificate(foreignDer)
 unknownClient,_:=cert(t,foreignRoot,foreignKey,"other-ca",false)
 check(clientFor([]tls.Certificate{unknownClient}),InventoryRead,"human",-1)
 // A concurrent request claiming human cannot escalate the agent certificate.
 var wg sync.WaitGroup
 for i:=0;i<12;i++{wg.Add(1);go func(){defer wg.Done();check(clientFor([]tls.Certificate{clients[Agent]}),EnrollmentWitness,"human",403)}()}
 wg.Wait()
}
func TestPolicyFailClosedAndImmutableCopy(t *testing.T){
 if _,err:=New(nil);err==nil{t.Fatal("accepted empty policy")}
 if _,err:=New(map[[32]byte]Grant{{}:{Role:Audience("root"),Capabilities:map[Capability]bool{InventoryRead:true}}});err==nil{t.Fatal("accepted unknown role")}
 if _,err:=New(map[[32]byte]Grant{{}:{Role:Human,Capabilities:map[Capability]bool{"firmware.flash":true}}});err==nil{t.Fatal("accepted unlisted physical capability")}
 if _,err:=New(map[[32]byte]Grant{{}:{Role:Human,Capabilities:map[Capability]bool{InventoryRead:false}}});err==nil{t.Fatal("accepted false grant")}
 a,err:=New(map[[32]byte]Grant{{}:{Role:Agent,Capabilities:map[Capability]bool{InventoryRead:true}}})
 if err!=nil{t.Fatal(err)}
 if _,err:=a.Check(httptest.NewRequest("GET","/",nil),InventoryRead);err==nil{t.Fatal("accepted no mTLS")}
}
