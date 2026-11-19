// Package mobilereceipt accepts short-lived consented mobile-app capability
// assertions ONLY against a controller-held enrollment record. This is
// offline code: no trust anchor, enrollment, OS permission or attestation is
// created by the module. Test keys are disposable and synthetic.
package mobilereceipt

import (
 "bytes"
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "errors"
 "io"
 "regexp"
)
const Schema="mobile-capability-envelope/v1"
type Claims struct {
 Schema string `json:"schema"`
 DeviceAlias string `json:"device_alias"`
 Platform string `json:"platform"`
 Substrate string `json:"substrate"`
 EnrollmentGeneration string `json:"enrollment_generation"`
 ConsentGeneration string `json:"consent_generation"`
 Nonce string `json:"nonce"`
 IssuedAt int64 `json:"issued_at_unix"`
 ExpiresAt int64 `json:"expires_at_unix"`
 Scope string `json:"scope"`
}
type Signed struct {
 Payload json.RawMessage `json:"payload"`
 SignatureBase64 string `json:"signature_b64"`
}
type Enrollment struct {
 // These MUST come from trusted private controller custody, never from a
 // model/guest request, signed app payload or public discovery metadata.
 DeviceAlias string
 Platform string
 Substrate string
 EnrollmentGeneration string
 ConsentGeneration string
 PublicKey ed25519.PublicKey
 ConsentLive bool
 RealDeviceAttested bool
 ApprovedScopes []string
}
type Ledger interface{
 ConsumeOnce(deviceAlias,nonce string,expiresAt int64)bool
}
type Verified struct{
 Scope string `json:"scope"`
 CapabilityClass string `json:"capability_class"`
}
var digestRE=regexp.MustCompile("^[a-f0-9]{64}$")
var aliasRE=regexp.MustCompile("^mob_[a-z0-9]{8,32}$")
var nonceRE=regexp.MustCompile("^[a-zA-Z0-9_-]{20,80}$")
var virtualHandleRE=regexp.MustCompile("^task_[a-z0-9]{12,30}$")
func denied(reason string)error{return errors.New("DENIED:"+reason)}
func Check(w Signed,registered Enrollment,nowUnix int64,ledger Ledger)(Verified,error){
 var zero Verified
 if ledger==nil||len(w.Payload)==0||len(w.Payload)>3072||
  len(registered.PublicKey)!=ed25519.PublicKeySize{return zero,denied("TRUST_RECORD_OR_PAYLOAD_INVALID")}
 var c Claims
 d:=json.NewDecoder(bytes.NewReader(w.Payload))
 d.DisallowUnknownFields()
 if e:=d.Decode(&c);e!=nil{return zero,denied("MALFORMED_OR_EXTRA_FIELDS")}
 if e:=d.Decode(&struct{}{});e!=io.EOF{return zero,denied("TRAILING_JSON")}
 canon,e:=json.Marshal(c)
 if e!=nil||!bytes.Equal(canon,w.Payload){return zero,denied("NONCANONICAL_OR_DUPLICATE_JSON_FIELDS")}
 sig,e:=base64.StdEncoding.Strict().DecodeString(w.SignatureBase64)
 if e!=nil||!ed25519.Verify(registered.PublicKey,canon,sig){
  return zero,denied("INVALID_OR_UNVERIFIED_SIGNATURE")
 }
 if c.Schema!=Schema||!aliasRE.MatchString(c.DeviceAlias)||!nonceRE.MatchString(c.Nonce)||
  !digestRE.MatchString(c.EnrollmentGeneration)||!digestRE.MatchString(c.ConsentGeneration){
  return zero,denied("MALFORMED_CLAIMS")
 }
 if c.Platform!="android"&&c.Platform!="ios"&&c.Platform!="ipados"{
  return zero,denied("UNSUPPORTED_PLATFORM")
 }
 if c.Substrate!="physical"&&c.Substrate!="android_emulator"&&c.Substrate!="ios_simulator"{
  return zero,denied("UNSUPPORTED_SUBSTRATE")
 }
 if c.DeviceAlias!=registered.DeviceAlias||c.Platform!=registered.Platform||
  c.Substrate!=registered.Substrate||c.EnrollmentGeneration!=registered.EnrollmentGeneration||
  c.ConsentGeneration!=registered.ConsentGeneration||!registered.ConsentLive{
  return zero,denied("ENROLLMENT_OR_CONSENT_MISMATCH")
 }
 if c.IssuedAt>nowUnix+30||c.ExpiresAt<nowUnix||
  c.ExpiresAt<=c.IssuedAt||c.ExpiresAt-c.IssuedAt>300||
  c.IssuedAt<nowUnix-300 {
  return zero,denied("STALE_FUTURE_OR_UNBOUNDED_RECEIPT")
 }
 hasScope:=false
 for _,s:=range registered.ApprovedScopes{if s==c.Scope{hasScope=true;break}}
 if !hasScope{return zero,denied("SCOPE_NOT_APPROVED")}
 if c.Substrate=="physical"{
  if !registered.RealDeviceAttested{return zero,denied("PHYSICAL_DEVICE_PROVENANCE_UNQUALIFIED")}
  if c.Scope=="simulator_ui_oracle"{return zero,denied("SIMULATOR_SCOPE_ON_PHYSICAL_DEVICE")}
 } else {
  if registered.RealDeviceAttested||c.Scope!="simulator_ui_oracle"{
   return zero,denied("SIMULATOR_CANNOT_ASSERT_FLEET_CAPACITY")
  }
 }
 if !ledger.ConsumeOnce(c.DeviceAlias,c.Nonce,c.ExpiresAt){
  return zero,denied("REPLAYED_DEVICE_NONCE")
 }
 classification:="SIMULATED_TEST_RECEIPT_NOT_FLEET_PLACEMENT"
 if c.Substrate=="physical" {classification="REGISTERED_PHYSICAL_APP_ASSERTION_NEEDS_RUNTIME_ADMISSION"}
 return Verified{Scope:c.Scope,CapabilityClass:classification},nil
}
type AssignedGuestView struct {
 VirtualTaskHandles []string `json:"virtual_task_handles"`
}
// Ordinary users receive only explicitly assigned opaque virtual task
// handles, not a device name/count, MAC/serial, CPU/GPU, IOMMU, app or
// hardware capability presence. Reject rather than silently ignore.
func ProjectAssignedGuest(handles []string)(AssignedGuestView,error){
 out:=AssignedGuestView{VirtualTaskHandles:[]string{}}
 seen:=map[string]struct{}{}
 for _,h:=range handles{
  if !virtualHandleRE.MatchString(h){return AssignedGuestView{},denied("INVALID_VIRTUAL_HANDLE")}
  if _,exists:=seen[h];exists{return AssignedGuestView{},denied("DUPLICATE_VIRTUAL_HANDLE")}
  seen[h]=struct{}{}
  out.VirtualTaskHandles=append(out.VirtualTaskHandles,h)
 }
 return out,nil
}
