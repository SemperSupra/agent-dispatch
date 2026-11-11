package gitops

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "slices"
)
type Belt struct { Owner string `json:"owner"`; Tools []string `json:"tools"` }
type Bundle struct { Schema string `json:"schema"`; Catalog []string `json:"catalog"`; Belts map[string]Belt `json:"belts"` }
type Snapshot struct { Digest string; Manifest Bundle }
type Policy struct { Grants map[string][]string; Epoch int64; Fresh bool }
type Request struct {
 Authenticated bool
 Principal, Belt, Tool, PinnedDigest string
 NativeAdmitted, AuditReady bool
 RequiredPolicyEpoch int64
}
type Verdict struct { Allow bool `json:"allow"`; Reason string `json:"reason"`; Snapshot string `json:"snapshot"` }
func Load(content []byte)(Snapshot,error){
 var b Bundle
 if e:=json.Unmarshal(content,&b);e!=nil{return Snapshot{},e}
 if b.Schema!="m1.gitops.synthetic/v1"{return Snapshot{},errors.New("unsupported bundle schema")}
 if len(b.Catalog)==0{return Snapshot{},errors.New("empty catalog")}
 seen:=make(map[string]bool)
 for _,t:=range b.Catalog {
  if t==""||seen[t]{return Snapshot{},fmt.Errorf("duplicate/empty catalog tool %q",t)}
  seen[t]=true
 }
 if len(b.Belts)==0{return Snapshot{},errors.New("no saved belts")}
 for name,belt:=range b.Belts {
  if name==""||belt.Owner==""||len(belt.Tools)==0{return Snapshot{},fmt.Errorf("invalid belt %q",name)}
  inBelt:=make(map[string]bool)
  for _,t:=range belt.Tools {
   if !seen[t]||inBelt[t]{return Snapshot{},fmt.Errorf("invalid/duplicate selection %q",t)}
   inBelt[t]=true
  }
 }
 h:=sha256.Sum256(content)
 return Snapshot{Digest:hex.EncodeToString(h[:]),Manifest:b},nil
}
// Offline reference oracle only. Authentication proof comes from an external issuer.
// Absolutely no global active-belt state or authorization grant inferred from selection.
func Check(s Snapshot,p Policy,r Request)Verdict{
 deny:=func(reason string)Verdict{return Verdict{Reason:reason,Snapshot:s.Digest}}
 if !r.Authenticated||r.Principal==""{return deny("identity-unverified")}
 if r.PinnedDigest!=s.Digest{return deny("snapshot-mismatch")}
 b,ok:=s.Manifest.Belts[r.Belt]
 if !ok||(b.Owner!="shared"&&b.Owner!=r.Principal){return deny("belt-not-owned")}
 if !slices.Contains(b.Tools,r.Tool){return deny("tool-not-selected")}
 if !p.Fresh||p.Epoch<r.RequiredPolicyEpoch{return deny("policy-stale")}
 if !slices.Contains(p.Grants[r.Principal],r.Tool){return deny("tool-not-granted")}
 if !r.NativeAdmitted{return deny("native-admission-denied")}
 if (r.Tool=="alpha.write"||r.Tool=="beta.write")&&!r.AuditReady{return deny("privileged-audit-unavailable")}
 return Verdict{Allow:true,Reason:"authorized",Snapshot:s.Digest}
}
