// Package lease is an intentionally public, synthetic policy/evidence fixture.
// It has no real signer, deployment broker, host isolation, or agent qualification.
package lease

import (
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/json"
 "errors"
 "sync"
 "time"
)

type Grant struct {
 Actor string
 Sandbox string
 Mission string
 Epoch uint64
 Nonce string
 IssuedAt int64
 ExpiresAt int64
 Capabilities []string
 ParentHash string
}
type Envelope struct {
 Grant Grant
 Signature []byte
}
type Request struct {
 Actor string
 Sandbox string
 Mission string
 Capability string
}
type Approval struct {
 GrantHash string
 Actor string
 Capability string
 ExpiresAt int64
 Nonce string
 Signature []byte
}
type Verifier struct {
 mu sync.Mutex
 Issuer ed25519.PublicKey
 Owner ed25519.PublicKey
 MinimumEpoch uint64
 seen map[string]bool
}

var ErrDenied = errors.New("synthetic policy denied")

func payload(grant Grant) []byte { b,_ := json.Marshal(grant); return b }
func GrantDigest(grant Grant) [32]byte { return sha256.Sum256(payload(grant)) }
func SignGrant(key ed25519.PrivateKey, grant Grant) Envelope {
 return Envelope{Grant:grant, Signature:ed25519.Sign(key,payload(grant))}
}
func validCapabilities(caps []string) bool {
 if len(caps)==0 || len(caps)>16 {return false}
 seen:=map[string]bool{}
 for _,s:=range caps {
  switch s {
  case "guest.root", "guest.tools", "guest.virtual_usb", "guest.mock_network",
       "external.synthetic_service_write":
  default: return false
  }
  if seen[s] {return false}
  seen[s]=true
 }
 return true
}
func isSyntheticGuest(s string) bool {
 switch s {case "guest.root", "guest.tools", "guest.virtual_usb", "guest.mock_network":return true}
 return false
}
func isAllowed(grant Grant, capability string) bool {
 for _,s:=range grant.Capabilities { if s==capability {return true} }
 return false
}

func approvalPayload(a Approval) []byte {
 tmp:=struct{GrantHash,Actor,Capability string; ExpiresAt int64; Nonce string}{
 a.GrantHash,a.Actor,a.Capability,a.ExpiresAt,a.Nonce,
 }
 b,_:=json.Marshal(tmp);return b
}
func SignApproval(key ed25519.PrivateKey, grant Grant, cap, nonce string, expiry int64) Approval {
 h:=GrantDigest(grant)
 a:=Approval{GrantHash:fmtDigest(h),Actor:grant.Actor,Capability:cap,ExpiresAt:expiry,Nonce:nonce}
 a.Signature=ed25519.Sign(key,approvalPayload(a))
 return a
}
func fmtDigest(h [32]byte) string {
 const hexchars="0123456789abcdef"
 var buf [64]byte
 for i,c:=range h {buf[i*2]=hexchars[c>>4];buf[i*2+1]=hexchars[c&15]}
 return string(buf[:])
}

func (v *Verifier) Authorize(now time.Time, env Envelope, req Request, approval *Approval) error {
 v.mu.Lock()
 defer v.mu.Unlock()
 g:=env.Grant
 if len(v.Issuer)!=ed25519.PublicKeySize || !ed25519.Verify(v.Issuer,payload(g),env.Signature) {return ErrDenied}
 if g.Epoch<v.MinimumEpoch || g.Nonce=="" || len(g.Nonce)>128 ||
    g.Actor=="" || g.Sandbox=="" || g.Mission=="" ||
    g.Actor!=req.Actor || g.Sandbox!=req.Sandbox || g.Mission!=req.Mission ||
    g.ExpiresAt<=g.IssuedAt || now.Unix()<g.IssuedAt || now.Unix()>=g.ExpiresAt ||
    !validCapabilities(g.Capabilities) || !isAllowed(g,req.Capability) {return ErrDenied}
 if !isSyntheticGuest(req.Capability) {
  // An unknown agent can never reach a real external action. This positive
  // synthetic fixture additionally requires an independent owner signature.
  if req.Capability!="external.synthetic_service_write" ||
     approval==nil || len(v.Owner)!=ed25519.PublicKeySize ||
     approval.GrantHash!=fmtDigest(GrantDigest(g)) ||
     approval.Capability!=req.Capability || approval.Actor!=req.Actor ||
     approval.Nonce=="" || approval.ExpiresAt<=now.Unix() ||
     approval.ExpiresAt>g.ExpiresAt ||
     !ed25519.Verify(v.Owner,approvalPayload(*approval),approval.Signature) {return ErrDenied}
 }
 id:=g.Actor+"/"+g.Sandbox+"/"+g.Nonce+"/"+req.Capability
 if v.seen==nil {v.seen=map[string]bool{}}
 if v.seen[id] {return ErrDenied}
 v.seen[id]=true
 return nil
}

// The parent and delegated grants must each have valid signatures. This
// checks the *scope* relation only; it does not itself grant any authority.
func ValidateDelegation(parent,child Grant) error {
 if parent.Actor=="" || child.Actor=="" || parent.Mission!=child.Mission ||
    parent.Sandbox!=child.Sandbox || child.Epoch<parent.Epoch ||
    child.IssuedAt<parent.IssuedAt || child.ExpiresAt>parent.ExpiresAt ||
    child.ExpiresAt<=child.IssuedAt || child.Nonce==parent.Nonce ||
    child.ParentHash!=fmtDigest(GrantDigest(parent)) ||
    !validCapabilities(parent.Capabilities) || !validCapabilities(child.Capabilities) {return ErrDenied}
 for _,cap:=range child.Capabilities {if !isAllowed(parent,cap) {return ErrDenied}}
 return nil
}
