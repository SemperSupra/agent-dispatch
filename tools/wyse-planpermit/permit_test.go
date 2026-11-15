package planpermit

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "strings"
 "sync"
 "sync/atomic"
 "testing"
 "time"
)

type memoryOnce struct{ mu sync.Mutex;used map[string]bool;broken bool }
func (s *memoryOnce)ConsumeOnce(ctx context.Context,key string)error{
 if err:=ctx.Err();err!=nil{return err}
 s.mu.Lock();defer s.mu.Unlock()
 if s.broken{return errors.New("injected durable store unavailable")}
 if s.used==nil{s.used=map[string]bool{}}
 if s.used[key]{return errors.New("replay")}
 s.used[key]=true;return nil
}
func sample(t *testing.T)(Permit,Target,*Verifier,time.Time,ed25519.PrivateKey){
 t.Helper()
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 target:=Target{DeviceID:"synthetic-opaque-01",Revision:8,SSDByID:"synthetic-sata-ssd-by-id-01",
  EMMCByID:"synthetic-emmc-by-id-01",ArtifactSHA256:strings.Repeat("a",64),PlanIntentSHA256:strings.Repeat("b",64)}
 now:=time.Unix(1_800_000_000,0)
 p:=Permit{Schema:Schema,KeyID:"synthetic-test-issuer",Claims:Claims{Target:target,Action:"HOST_INSTALL",
  Nonce:"synthetic-once-abc12345678",IssuedAtUnix:now.Add(-time.Second).Unix(),ExpiresAtUnix:now.Add(60*time.Second).Unix()}}
 p,err=Sign(priv,p);if err!=nil{t.Fatal(err)}
 v,err:=NewVerifier(map[string]ed25519.PublicKey{p.KeyID:pub});if err!=nil{t.Fatal(err)}
 return p,target,v,now,priv
}
func TestSignedExactBindingAndSingleUse(t *testing.T){
 p,target,v,now,_:=sample(t);store:=&memoryOnce{}
 if err:=v.VerifyOnce(context.Background(),p,target,"HOST_INSTALL",now,store);err!=nil{t.Fatal(err)}
 if err:=v.VerifyOnce(context.Background(),p,target,"HOST_INSTALL",now,store);err==nil{t.Fatal("replay admitted")}
}
func TestTargetAndSignatureTamperingDenied(t *testing.T){
 p,target,v,now,_:=sample(t)
 tests:=[]struct{name string;change func(*Permit)}{
  {"device",func(x *Permit){x.Claims.Target.DeviceID="synthetic-other"}},
  {"revision",func(x *Permit){x.Claims.Target.Revision++}},
  {"ssd",func(x *Permit){x.Claims.Target.SSDByID=x.Claims.Target.EMMCByID}},
  {"emmc",func(x *Permit){x.Claims.Target.EMMCByID="synthetic-other-emmc"}},
  {"artifact",func(x *Permit){x.Claims.Target.ArtifactSHA256=strings.Repeat("c",64)}},
  {"intent",func(x *Permit){x.Claims.Target.PlanIntentSHA256=strings.Repeat("d",64)}},
  {"action",func(x *Permit){x.Claims.Action="GUEST_INSTALL"}},
  {"nonce",func(x *Permit){x.Claims.Nonce="synthetic-once-different5678"}},
  {"key",func(x *Permit){x.KeyID="unknown-key"}},
  {"sig",func(x *Permit){x.Signature=append([]byte(nil),x.Signature...);x.Signature[0]^=1}},
  {"issued-at",func(x *Permit){x.Claims.IssuedAtUnix--}},
  {"expires",func(x *Permit){x.Claims.ExpiresAtUnix++}},
 }
 for _,z:=range tests {t.Run(z.name,func(t *testing.T){copy:=p;z.change(&copy)
  if err:=v.VerifyOnce(context.Background(),copy,target,"HOST_INSTALL",now,&memoryOnce{});err==nil{t.Fatal("tampered permit accepted")}
 })}
}
func TestExpiredFutureAndOverlongPermitsDenied(t *testing.T){
 p,target,v,now,priv:=sample(t)
 for _,z:=range []struct{name string;issued,expires int64}{
  {"expired",now.Add(-4*time.Minute).Unix(),now.Unix()},
  {"not-yet-valid",now.Add(time.Second).Unix(),now.Add(2*time.Second).Unix()},
  {"too-long",now.Add(-time.Second).Unix(),now.Add(6*time.Minute).Unix()},
 }{
  t.Run(z.name,func(t *testing.T){copy:=p;copy.Claims.IssuedAtUnix=z.issued;copy.Claims.ExpiresAtUnix=z.expires
   signed,err:=Sign(priv,copy)
   if z.name=="too-long"{if err==nil{t.Fatal("overlong permit signed")};return}
   if err!=nil{t.Fatal(err)}
   if err:=v.VerifyOnce(context.Background(),signed,target,"HOST_INSTALL",now,&memoryOnce{});err==nil{t.Fatal("time-invalid permit accepted")}
  })
 }
}
func TestUntrustedIssuerStoreAndMissingContextDenied(t *testing.T){
 p,target,v,now,_:=sample(t)
 if err:=v.VerifyOnce(context.Background(),p,target,"HOST_INSTALL",now,nil);err==nil{t.Fatal("no store accepted")}
 if err:=v.VerifyOnce(context.Background(),p,target,"HOST_INSTALL",now,&memoryOnce{broken:true});err==nil{t.Fatal("failed store accepted")}
 empty,err:=NewVerifier(nil);if err==nil||empty!=nil{t.Fatal("untrusted issuer allowed")}
 pub2,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 revoked,err:=NewVerifier(map[string]ed25519.PublicKey{"different-key":pub2});if err!=nil{t.Fatal(err)}
 if err:=revoked.VerifyOnce(context.Background(),p,target,"HOST_INSTALL",now,&memoryOnce{});err==nil{t.Fatal("revoked issuer accepted")}
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if err:=v.VerifyOnce(ctx,p,target,"HOST_INSTALL",now,&memoryOnce{});!errors.Is(err,context.Canceled){t.Fatalf("cancel ignored %v",err)}
}
func TestConcurrentReplayAtMostOne(t *testing.T){
 p,target,v,now,_:=sample(t)
 s:=&memoryOnce{}
 var wins atomic.Int32
 var wg sync.WaitGroup
 for i:=0;i<32;i++{wg.Add(1);go func(){defer wg.Done()
  if err:=v.VerifyOnce(context.Background(),p,target,"HOST_INSTALL",now,s);err==nil{wins.Add(1)}
 }()}
 wg.Wait()
 if n:=wins.Load();n!=1{t.Fatalf("accepted %d duplicate approvals",n)}
}
func TestCrossIssuerNonceReuseDenied(t *testing.T){
 p,target,_,now,_:=sample(t)
 pub1,priv1,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 pub2,priv2,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 p.KeyID="synthetic-issuer-one"
 a,err:=Sign(priv1,p);if err!=nil{t.Fatal(err)}
 p.KeyID="synthetic-issuer-two"
 b,err:=Sign(priv2,p);if err!=nil{t.Fatal(err)}
 v,err:=NewVerifier(map[string]ed25519.PublicKey{"synthetic-issuer-one":pub1,"synthetic-issuer-two":pub2});if err!=nil{t.Fatal(err)}
 s:=&memoryOnce{}
 if err:=v.VerifyOnce(context.Background(),a,target,"HOST_INSTALL",now,s);err!=nil{t.Fatal(err)}
 if err:=v.VerifyOnce(context.Background(),b,target,"HOST_INSTALL",now,s);err==nil{t.Fatal("cross issuer nonce reused")}
}
