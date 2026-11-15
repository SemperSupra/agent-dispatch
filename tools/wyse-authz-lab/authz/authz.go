// Package authz implements explicit identity-bound audience grants.
// Caller MUST configure a TLS listener with RequireAndVerifyClientCert and
// a pinned trusted CA; VerifiedChains alone is not a substitute for that.
package authz

import (
 "crypto/sha256"
 "crypto/x509"
 "errors"
 "fmt"
 "net/http"
 "time"
)

type Audience string
const (
 Human Audience = "human"
 Automation Audience = "automation"
 Agent Audience = "agent"
)
type Capability string
const (
 InventoryRead Capability = "inventory.read"
 EnrollmentWitness Capability = "enrollment.witness"
 EnrollmentPropose Capability = "enrollment.propose"
 RecoveryPlan Capability = "recovery.plan"
 KeyRotationApprove Capability = "key.rotate.approve"
 EvidenceAppend Capability = "evidence.append"
)
type Principal struct {
 Audience Audience
 Identity string
}
type Grant struct {
 Role Audience
 Capabilities map[Capability]bool
 Disabled bool
}
// Authorizer is immutable after construction. Identity is pinned by the
// certificate's raw SubjectPublicKeyInfo hash, not its display subject.
type Authorizer struct {
 grants map[[32]byte]Grant
 now func()time.Time
}
func Fingerprint(cert *x509.Certificate) ([32]byte,error) {
 if cert==nil || len(cert.RawSubjectPublicKeyInfo)==0{return [32]byte{},errors.New("missing public key")}
 return sha256.Sum256(cert.RawSubjectPublicKeyInfo),nil
}
func New(grants map[[32]byte]Grant) (*Authorizer,error){
 if len(grants)==0{return nil,errors.New("empty grants fail closed")}
 clone:=make(map[[32]byte]Grant,len(grants))
 for id,g:=range grants {
  if g.Role!=Human&&g.Role!=Automation&&g.Role!=Agent{return nil,errors.New("unknown audience")}
  if len(g.Capabilities)==0 {return nil,errors.New("empty grants not useful")}
  scopes:=make(map[Capability]bool,len(g.Capabilities))
  for cap,allowed:=range g.Capabilities {
   switch cap {
   case InventoryRead,EnrollmentWitness,EnrollmentPropose,RecoveryPlan,KeyRotationApprove,EvidenceAppend:
   default:return nil,fmt.Errorf("unrecognized capability %q: fail closed",cap)
   }
   if !allowed{return nil,errors.New("false grant disallowed")}
   scopes[cap]=true
  }
  g.Capabilities=scopes
  clone[id]=g
 }
 return &Authorizer{grants:clone,now:time.Now},nil
}
func (a *Authorizer) Check(r *http.Request, action Capability) (Principal,error){
 if a==nil||r==nil||r.TLS==nil||len(r.TLS.PeerCertificates)==0||len(r.TLS.VerifiedChains)==0 {
  return Principal{},errors.New("mutual TLS verified certificate required")
 }
 cert:=r.TLS.PeerCertificates[0]
 // TLS handshake validates chain/EKU/revocation status as configured by the
 // server; check temporal validity again at decision time for long sessions.
 now:=a.now()
 if now.Before(cert.NotBefore)||!now.Before(cert.NotAfter) {
  return Principal{},errors.New("certificate not currently valid")
 }
 hasClientAuth:=false
 for _,use:=range cert.ExtKeyUsage {
  if use==x509.ExtKeyUsageClientAuth || use==x509.ExtKeyUsageAny {hasClientAuth=true}
 }
 if !hasClientAuth {return Principal{},errors.New("client-auth EKU missing")}
 id,err:=Fingerprint(cert);if err!=nil{return Principal{},err}
 g,found:=a.grants[id]
 if !found||g.Disabled{return Principal{},errors.New("client public key not admitted")}
 if !g.Capabilities[action]{return Principal{},errors.New("capability not granted")}
 // Request-supplied Actor/Role, X-Forwarded-Client-Cert, etc. are ignored.
 return Principal{Audience:g.Role,Identity:fmt.Sprintf("%x",id)},nil
}
