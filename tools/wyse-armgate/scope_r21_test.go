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
 "testing"
 "time"

 modeplan "github.com/SemperSupra/agent-dispatch/tools/wyse-modeplan/modeplan"
)

// Produce a real, ephemeral CA-validated mutual TLS 1.3 handshake over an
// in-memory socket, not a manually forged ConnectionState.
func ephemeralVerifiedClient(t *testing.T)tls.ConnectionState{
 t.Helper()
 _,caKey,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 caTemplate:=&x509.Certificate{
  SerialNumber:big.NewInt(100),Subject:pkix.Name{CommonName:"synthetic test CA"},
  NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),
  IsCA:true,BasicConstraintsValid:true,MaxPathLen:1,
  KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageCRLSign,
 }
 caDER,err:=x509.CreateCertificate(rand.Reader,caTemplate,caTemplate,caKey.Public(),caKey)
 if err!=nil{t.Fatal(err)}
 ca,err:=x509.ParseCertificate(caDER);if err!=nil{t.Fatal(err)}
 roots:=x509.NewCertPool();roots.AddCert(ca)

 makeLeaf:=func(id int64,server bool)tls.Certificate{
  t.Helper()
  _,key,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
  purpose:=x509.ExtKeyUsageClientAuth
  if server {purpose=x509.ExtKeyUsageServerAuth}
  leaf:=&x509.Certificate{
   SerialNumber:big.NewInt(id),Subject:pkix.Name{CommonName:"synthetic-local-tls"},
   NotBefore:time.Now().Add(-time.Minute),NotAfter:time.Now().Add(time.Hour),
   KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{purpose},
  }
  if server{leaf.DNSNames=[]string{"localhost"}}
  der,err:=x509.CreateCertificate(rand.Reader,leaf,ca,key.Public(),caKey)
  if err!=nil{t.Fatal(err)}
  signer,err:=x509.ParseCertificate(der);if err!=nil{t.Fatal(err)}
  return tls.Certificate{Certificate:[][]byte{der,caDER},PrivateKey:key,Leaf:signer,}
 }
 // Leaf PEM isn't necessary for constructing tls.Certificate, which requires
 // DER chain and private key; every key exists only within this test.
 serverCert:=makeLeaf(101,true);clientCert:=makeLeaf(102,false)
 srv,cli:=net.Pipe()
 t.Cleanup(func(){srv.Close();cli.Close()})
 server:=tls.Server(srv,&tls.Config{
  MinVersion:tls.VersionTLS13,Certificates:[]tls.Certificate{serverCert},
  ClientAuth:tls.RequireAndVerifyClientCert,ClientCAs:roots,
 })
 client:=tls.Client(cli,&tls.Config{MinVersion:tls.VersionTLS13,ServerName:"localhost",
  RootCAs:roots,Certificates:[]tls.Certificate{clientCert}})
 result:=make(chan error,1)
 go func(){result<-server.Handshake()}()
 if err:=client.Handshake();err!=nil{t.Fatal(err)}
 if err:=<-result;err!=nil{t.Fatal(err)}
 state:=server.ConnectionState()
 if state.Version!=tls.VersionTLS13||len(state.VerifiedChains)==0 {t.Fatal("mutual TLS verification absent")}
 return state
}

func scopedFixture(t *testing.T)(modeplan.Node,modeplan.Plan,tls.ConnectionState,
 IssuerCapability,Audience,time.Time){
 t.Helper()
 n,p,_,_,now:=prepared(t)
 state:=ephemeralVerifiedClient(t)
 spki,err:=verifiedSPKI(state);if err!=nil{t.Fatal(err)}
 grant:=IssuerCapability{
  IssuerKeyID:"test-issuer-01",ClientSPKISHA256:spki,
  Audience:Human,Action:"HOST_INSTALL",DeviceID:n.ID,
  TargetProfile:p.TargetProfile,ApprovedChangeID:p.ApprovedChangeID,
  PlanIntentSHA256:p.IntentSHA256,
  NotBeforeUnix:now.Add(-time.Minute).Unix(),ExpiresUnix:now.Add(time.Minute).Unix(),
 }
 return n,p,state,grant,Human,now
}
func TestR21MutualTLS13ScopedPermitForAllThreeAudiences(t *testing.T){
 n,p,state,base,_,now:=scopedFixture(t)
 _,_,token,verifier,_:=prepared(t)
 // Reuse plan-specific token from same deterministic fixture, but this
 // fixture creates its own ephemeral issuer key. Only its paired verifier
 // is used with that token.
 for _,audience:=range []Audience{Human,Automation,Agent}{
  t.Run(string(audience),func(t *testing.T){
   g:=base;g.Audience=audience
   result,err:=AuthorizeTLSScopedArm(context.Background(),n,p,token,verifier,&oneUse{},now,state,audience,g)
   if err!=nil||result.Stage!=modeplan.Armed {t.Fatalf("scoped arm denied: %v",err)}
  })
 }
}
func TestR21ScopedPermitRejectsPrincipalAndIssuerEscalationBeforeNonce(t *testing.T){
 n,p,state,base,audience,now:=scopedFixture(t)
 _,_,token,verifier,_:=prepared(t)
 cases:=[]struct{
  name string
  mutate func(*IssuerCapability,*tls.ConnectionState,*Audience)
 }{
  {"wrong-client-key",func(g *IssuerCapability,_ *tls.ConnectionState,_ *Audience){g.ClientSPKISHA256="falsified"}},
  {"unapproved-issuer",func(g *IssuerCapability,_ *tls.ConnectionState,_ *Audience){g.IssuerKeyID="another-issuer"}},
  {"guest-only-capability",func(g *IssuerCapability,_ *tls.ConnectionState,_ *Audience){g.Action="GUEST_INSTALL"}},
  {"different-device",func(g *IssuerCapability,_ *tls.ConnectionState,_ *Audience){g.DeviceID="other-device"}},
  {"different-plan",func(g *IssuerCapability,_ *tls.ConnectionState,_ *Audience){g.PlanIntentSHA256="replaced"}},
  {"other-change",func(g *IssuerCapability,_ *tls.ConnectionState,_ *Audience){g.ApprovedChangeID="other-change"}},
  {"other-profile",func(g *IssuerCapability,_ *tls.ConnectionState,_ *Audience){g.TargetProfile=modeplan.DisposableBareMetal}},
  {"role-upgrade",func(_ *IssuerCapability,_ *tls.ConnectionState,a *Audience){*a=Agent}},
  {"grant-expired",func(g *IssuerCapability,_ *tls.ConnectionState,_ *Audience){g.ExpiresUnix=now.Unix()}},
  {"grant-not-yet-valid",func(g *IssuerCapability,_ *tls.ConnectionState,_ *Audience){g.NotBeforeUnix=now.Add(time.Minute).Unix()}},
  {"handshake-not-complete",func(_ *IssuerCapability,s *tls.ConnectionState,_ *Audience){s.HandshakeComplete=false}},
  {"tls12-denied",func(_ *IssuerCapability,s *tls.ConnectionState,_ *Audience){s.Version=tls.VersionTLS12}},
  {"no-verified-chain",func(_ *IssuerCapability,s *tls.ConnectionState,_ *Audience){s.VerifiedChains=nil}},
  {"missing-peer",func(_ *IssuerCapability,s *tls.ConnectionState,_ *Audience){s.PeerCertificates=nil}},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   g,s,a:=base,state,audience
   tc.mutate(&g,&s,&a)
   ledger:=&oneUse{}
   if _,err:=AuthorizeTLSScopedArm(context.Background(),n,p,token,verifier,ledger,now,s,a,g);err==nil{
    t.Fatal("unscoped or unauthenticated approval accepted")
   }
   if len(ledger.used)!=0 {t.Fatalf("nonce spent on unauthorized caller: %v",ledger.used)}
  })
 }
}
