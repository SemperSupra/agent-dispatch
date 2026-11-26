// Package heldledger is a tiny crash-consistent, payload-free record of the
// host actuator's synthetic held-key state. It is NOT a distributed lock or
// evidence of guest observation. Recover callers must issue QMP key-up before
// clearing Held and admitting a new lease.
package heldledger

import (
 "bytes"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
)

const (
 Version=1
 KeyA="key-a"
 maxBytes=4096
)
var ErrInvalid=errors.New("heldledger: invalid or unknown state")
var ErrConflict=errors.New("heldledger: stale or illegal transition")

type State struct {
 Version int `json:"version"`
 Sequence uint64 `json:"sequence"`
 Key string `json:"key,omitempty"`
 Held bool `json:"held"`
 // A v2 scoped HELD record is never eligible for a legacy v1 grant.
 Scope *GenesisScope `json:"scope,omitempty"`
 // v2 first-install nonce and proof commitment are not legacy credentials.
 GenesisNonce string `json:"genesis_nonce,omitempty"`
 GenesisOperation string `json:"genesis_operation,omitempty"`
 GenesisEvidenceHash string `json:"genesis_evidence_hash,omitempty"`
 // R27-S: write-ahead host admission intent, before any external lease or
 // USBIP device actuator can be exposed. An unobserved SIGKILL MUST leave a
 // durable non-clean state; only independently verified release can clear it.
 AdmissionIntent bool `json:"admission_intent,omitempty"`
 // None, release-intent, or qmp-acked. Guest evidence is still required
 // after the QMP acknowledgment. All stages remain Held=true until proof.
 ReleasePhase string `json:"release_phase,omitempty"`
 // R27-C: SHA256 of independently verified host kernel-isolation witness.
 // Present ONLY while held=true and release_phase=kernel-isolated; never a
 // bearer credential or proof that survives restart as fresh authority.
 KernelWitnessHash string `json:"kernel_witness_hash,omitempty"`
 // Audit-only receipt fingerprint and guest event monotonic sequence.
 // Neither field alone constitutes a fresh proof on process restart.
 LastReleaseEventSequence uint64 `json:"last_release_event_sequence,omitempty"`
 LastReleaseProofHash string `json:"last_release_proof_hash,omitempty"`
}

type Store struct {Path string}

// Read does not silently reset malformed records. A new file is safe only
// when caller also performs a QMP release before accepting input.
func (s Store) Read()(State,error){
 state,e:=s.readDecodedState()
 if e!=nil{return State{},e}
 if state.Version!=Version || state.Scope!=nil || state.GenesisNonce!="" || state.GenesisOperation!="" || state.GenesisEvidenceHash!=""{return State{},ErrInvalid}
 return validateLegacyState(state)
}

// readDecodedState owns the original bounded, no-follow and strict JSON
// read. Individual version-specific validators must decide eligibility.
func (s Store) readDecodedState()(State,error){
 if s.Path==""{return State{},ErrInvalid}
 // A symlink (including a dangling link) is not an absent journal.
 // Fail closed before following a path that could impersonate clean state.
 pathInfo,e:=os.Lstat(s.Path)
 if errors.Is(e,os.ErrNotExist){return State{Version:Version},nil}
 if e!=nil{return State{},e}
 if !pathInfo.Mode().IsRegular(){return State{},ErrInvalid}
 f,e:=openJournalNoFollow(s.Path)
 if errors.Is(e,os.ErrNotExist){return State{},ErrInvalid}
 if e!=nil{return State{},e}
 defer f.Close()
 info,e:=f.Stat();if e!=nil{return State{},e}
 if !info.Mode().IsRegular() || !os.SameFile(pathInfo,info) ||
  info.Size()>maxBytes || info.Size()<2{return State{},ErrInvalid}
 raw,e:=io.ReadAll(io.LimitReader(f,maxBytes+1));if e!=nil{return State{},e}
 if len(raw)>maxBytes{return State{},ErrInvalid}
 // Reject duplicate top-level JSON keys BEFORE decoding into State.
 // encoding/json otherwise accepts last-key-wins values: a damaged HELD
 // journal could be interpreted as clean. Case aliases are duplicates too.
 if err:=rejectDuplicateJournalKeys(raw);err!=nil{return State{},err}
 decoder:=json.NewDecoder(bytes.NewReader(raw))
 decoder.DisallowUnknownFields()
 var state State
 if e=decoder.Decode(&state);e!=nil{return State{},fmt.Errorf("%w: %v",ErrInvalid,e)}
 var extra any
 if e=decoder.Decode(&extra);!errors.Is(e,io.EOF){return State{},ErrInvalid}
 return state,nil
}

func validateLegacyState(state State)(State,error){
 if state.Version!=Version || state.Scope!=nil || (state.Held && state.Key!=KeyA) ||
  (!state.Held && state.Key!="") || state.Sequence==^uint64(0) {
  return State{},ErrInvalid
 }
 // Reject torn, unpaired or malformed receipt audit data. These fields
 // cannot become live authentication just because they survived a reboot.
 if (state.LastReleaseEventSequence==0)!=(state.LastReleaseProofHash==""){
  return State{},ErrInvalid
 }
 if state.LastReleaseProofHash!="" {
  d,err:=hex.DecodeString(state.LastReleaseProofHash)
  if err!=nil||len(d)!=32{return State{},ErrInvalid}
 }
 if state.ReleasePhase!="" && state.ReleasePhase!="release-intent" &&
  state.ReleasePhase!="qmp-acked" && state.ReleasePhase!="kernel-isolated" {
  return State{},ErrInvalid
 }
 if state.ReleasePhase=="kernel-isolated" {
  digest,err:=hex.DecodeString(state.KernelWitnessHash)
  if err!=nil||len(digest)!=32 {return State{},ErrInvalid}
 } else if state.KernelWitnessHash!="" {return State{},ErrInvalid}
 if !state.Held && state.ReleasePhase!="" {return State{},ErrInvalid}
 if state.AdmissionIntent && (state.Held || state.ReleasePhase!="" ||
  state.Sequence<2 || state.Sequence%2!=0) {return State{},ErrInvalid}
 return state,nil
}

// Transition is ONLY a write-ahead held=true record before key down.
// Legacy held=false without an independent guest receipt is denied.
// The caller serializes access; expected sequence prevents stale updates.
// rejectDuplicateJournalKeys validates the single bounded top-level object.
// The subsequent strict State decoder still owns schema/type validation.
func rejectDuplicateJournalKeys(raw []byte)error{
 d:=json.NewDecoder(bytes.NewReader(raw))
 first,err:=d.Token()
 if err!=nil||first!=json.Delim('{'){return ErrInvalid}
 seen:=make(map[string]struct{},8)
 for d.More(){
  token,err:=d.Token()
  if err!=nil{return ErrInvalid}
  name,ok:=token.(string)
  if !ok{return ErrInvalid}
  key:=strings.ToLower(name)
  if _,exists:=seen[key];exists{return ErrInvalid}
  seen[key]=struct{}{}
  var value json.RawMessage
  if err=d.Decode(&value);err!=nil{return ErrInvalid}
 }
 last,err:=d.Token()
 if err!=nil||last!=json.Delim('}'){return ErrInvalid}
 var extra any
 if err=d.Decode(&extra);!errors.Is(err,io.EOF){return ErrInvalid}
 return nil
}

func (s Store) Transition(expected uint64,held bool)(State,error){
 current,e:=s.Read();if e!=nil{return State{},e}
 // Legacy ACK-only release must never clear a key. An independently
 // verified guest evdev receipt must use ConfirmGuestRelease instead.
 if !held{return State{},ErrUnverified}
 if current.Sequence!=expected || current.Held==held {return State{},ErrConflict}
 next:=State{Version:Version,Sequence:current.Sequence+1,Held:held,
  LastReleaseEventSequence:current.LastReleaseEventSequence,
  LastReleaseProofHash:current.LastReleaseProofHash}
 if held{next.Key=KeyA}
 if e=s.writeAtomic(next);e!=nil{return State{},e}
 return next,nil
}
func (s Store) writeAtomic(state State)error{
 dir:=filepath.Dir(s.Path)
 f,e:=os.CreateTemp(dir,".r26-heldledger-*")
 if e!=nil{return e}
 name:=f.Name()
 defer os.Remove(name)
 if e=f.Chmod(0600);e!=nil{f.Close();return e}
 data,e:=json.Marshal(state);if e!=nil{f.Close();return e}
 data=append(data,'\n')
 if _,e=f.Write(data);e!=nil{f.Close();return e}
 if e=f.Sync();e!=nil{f.Close();return e}
 if e=f.Close();e!=nil{return e}
 if e=os.Rename(name,s.Path);e!=nil{return e}
 parent,e:=os.Open(dir);if e!=nil{return e}
 defer parent.Close()
 return parent.Sync()
}

// BeginAdmission is the original heldledger's durable write-ahead fence.
// Call only while holding the canonical host-local OS owner, before handing
// the original Go Manager to any client capable of Reserve/Attach/Input.
// A crash after this fsync but before key-down must quarantine successors.
// Never clear AdmissionIntent simply because a process/lock died.
func (s Store) BeginAdmission(expected uint64)(State,error){
 st,err:=s.Read();if err!=nil{return State{},err}
 if st.Sequence!=expected || st.Sequence<2 || st.Sequence%2!=0 ||
  st.Held || st.AdmissionIntent || st.ReleasePhase!="" {
  return State{},ErrConflict
 }
 st.AdmissionIntent=true
 if err:=s.writeAtomic(st);err!=nil{return State{},err}
 return st,nil
}
