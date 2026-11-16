package lease

import (
 "crypto/ed25519"
 "crypto/rand"
 "testing"
 "time"
)
const stamp int64=1794800000
func keys(t *testing.T)(ed25519.PublicKey,ed25519.PrivateKey) {
 t.Helper()
 p,s,e:=ed25519.GenerateKey(rand.Reader); if e!=nil {t.Fatal(e)};return p,s
}
func fixture() Grant {
 return Grant{Actor:"unknown-agent",Sandbox:"disposable-01",Mission:"synthetic-rdte",Epoch:2,Nonce:"unique-1",IssuedAt:stamp,ExpiresAt:stamp+3600,
 Capabilities:[]string{"guest.root","guest.tools","guest.virtual_usb","guest.mock_network","external.synthetic_service_write"}}
}
func req(cap string)Request{return Request{Actor:"unknown-agent",Sandbox:"disposable-01",Mission:"synthetic-rdte",Capability:cap}}
func TestHighFreedomAndSyntheticApproval(t *testing.T){
 issuer,sk:=keys(t); owner,ownerKey:=keys(t)
 now:=time.Unix(stamp+10,0); g:=fixture()
 v:=Verifier{Issuer:issuer,Owner:owner,MinimumEpoch:2}
 for _,c:=range []string{"guest.root","guest.tools","guest.virtual_usb","guest.mock_network"} {
  g.Nonce="unique-"+c
  if err:=v.Authorize(now,SignGrant(sk,g),req(c),nil);err!=nil{t.Fatalf("%s: %v",c,err)}
 }
 g.Nonce="external-01"
 signed:=SignGrant(sk,g)
 if err:=v.Authorize(now,signed,req("external.synthetic_service_write"),nil);err==nil{t.Fatal("external synthetic effect without independent approval")}
 approval:=SignApproval(ownerKey,g,"external.synthetic_service_write","owner-approval-01",stamp+100)
 if err:=v.Authorize(now,signed,req("external.synthetic_service_write"),&approval);err!=nil{t.Fatal(err)}
 if err:=v.Authorize(now,signed,req("external.synthetic_service_write"),&approval);err==nil{t.Fatal("replayed capability allowed")}
}
func TestFailClosedScopeIntegrityEpochAndExpiry(t *testing.T){
 issuer,sk:=keys(t); owner,ownerKey:=keys(t);_ =ownerKey
 now:=time.Unix(stamp+10,0)
 cases:=[]struct{name string; tweak func(*Grant,*Request,*Envelope)}{
 {"revoked_epoch",func(g *Grant,r *Request,e *Envelope){g.Epoch=1;e.Grant=*g;e.Signature=ed25519.Sign(sk,payload(*g))}},
 {"expired",func(g *Grant,r *Request,e *Envelope){g.ExpiresAt=stamp+2;e.Grant=*g;e.Signature=ed25519.Sign(sk,payload(*g))}},
 {"future",func(g *Grant,r *Request,e *Envelope){g.IssuedAt=stamp+99;e.Grant=*g;e.Signature=ed25519.Sign(sk,payload(*g))}},
 {"tampered",func(g *Grant,r *Request,e *Envelope){e.Grant.Actor="another-actor"}},
 {"actor",func(g *Grant,r *Request,e *Envelope){r.Actor="wrong"}},
 {"sandbox",func(g *Grant,r *Request,e *Envelope){r.Sandbox="wrong"}},
 {"mission",func(g *Grant,r *Request,e *Envelope){r.Mission="wrong"}},
 {"host_tpm",func(g *Grant,r *Request,e *Envelope){r.Capability="host.physical_tpm"}},
 {"host_qmp",func(g *Grant,r *Request,e *Envelope){r.Capability="host.raw_qmp"}},
 {"real_cac",func(g *Grant,r *Request,e *Envelope){r.Capability="external.real_cac"}},
 {"real_network",func(g *Grant,r *Request,e *Envelope){r.Capability="external.real_network"}},
 {"unknown",func(g *Grant,r *Request,e *Envelope){r.Capability="unknown"}},
 {"forged_signature",func(g *Grant,r *Request,e *Envelope){e.Signature=[]byte("not-a-signature")}},
 {"duplicate_scope",func(g *Grant,r *Request,e *Envelope){g.Capabilities=[]string{"guest.root","guest.root"};e.Grant=*g;e.Signature=ed25519.Sign(sk,payload(*g))}},
 {"unrecognized_granted",func(g *Grant,r *Request,e *Envelope){g.Capabilities=append(g.Capabilities,"host.raw_qmp");e.Grant=*g;e.Signature=ed25519.Sign(sk,payload(*g))}},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   g:=fixture();e:=SignGrant(sk,g);r:=req("guest.root");tc.tweak(&g,&r,&e)
   v:=Verifier{Issuer:issuer,Owner:owner,MinimumEpoch:2}
   if err:=v.Authorize(now,e,r,nil);err==nil {t.Fatal("unexpected authorization")}
  })
 }
}
func TestOwnerApprovalCannotBeRepurposed(t *testing.T){
 issuer,sk:=keys(t);owner,osk:=keys(t);g:=fixture()
 valid:=SignGrant(sk,g);a:=SignApproval(osk,g,"external.synthetic_service_write","owner-1",stamp+100)
 now:=time.Unix(stamp+10,0)
 invalid:=[]Approval{a,a,a,a}
 invalid[0].Actor="other"
 invalid[1].Capability="external.production_write"
 invalid[2].GrantHash="bad"
 invalid[3].ExpiresAt=stamp+7200
 for i:=range invalid{
  v:=Verifier{Issuer:issuer,Owner:owner,MinimumEpoch:2}
  if err:=v.Authorize(now,valid,req("external.synthetic_service_write"),&invalid[i]);err==nil {t.Fatalf("case %d authorized",i)}
 }
}
func TestDelegationCannotExpand(t *testing.T){
 parent:=fixture()
 child:=parent
 child.Actor="subagent"
 child.Nonce="sub-2"
 child.Capabilities=[]string{"guest.tools"}
 child.ParentHash=fmtDigest(GrantDigest(parent))
 if err:=ValidateDelegation(parent,child);err!=nil{t.Fatal(err)}
 child.Capabilities=[]string{"guest.tools","host.raw_qmp"}
 if err:=ValidateDelegation(parent,child);err==nil{t.Fatal("escalating delegation allowed")}
 child.Capabilities=[]string{"guest.tools"}
 child.ExpiresAt=parent.ExpiresAt+1
 if err:=ValidateDelegation(parent,child);err==nil{t.Fatal("extended TTL allowed")}
 child.ExpiresAt=parent.ExpiresAt
 child.Sandbox="another"
 if err:=ValidateDelegation(parent,child);err==nil{t.Fatal("cross sandbox delegation allowed")}
}
