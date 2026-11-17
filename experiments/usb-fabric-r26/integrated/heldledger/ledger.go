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
 // None, release-intent, or qmp-acked. Guest evidence is still required
 // after the QMP acknowledgment. All stages remain Held=true until proof.
 ReleasePhase string `json:"release_phase,omitempty"`
 // Audit-only receipt fingerprint and guest event monotonic sequence.
 // Neither field alone constitutes a fresh proof on process restart.
 LastReleaseEventSequence uint64 `json:"last_release_event_sequence,omitempty"`
 LastReleaseProofHash string `json:"last_release_proof_hash,omitempty"`
}

type Store struct {Path string}

// Read does not silently reset malformed records. A new file is safe only
// when caller also performs a QMP release before accepting input.
func (s Store) Read()(State,error){
 if s.Path==""{return State{},ErrInvalid}
 f,e:=os.Open(s.Path)
 if errors.Is(e,os.ErrNotExist){return State{Version:Version},nil}
 if e!=nil{return State{},e}
 defer f.Close()
 info,e:=f.Stat();if e!=nil{return State{},e}
 if !info.Mode().IsRegular() || info.Size()>maxBytes || info.Size()<2{return State{},ErrInvalid}
 raw,e:=io.ReadAll(io.LimitReader(f,maxBytes+1));if e!=nil{return State{},e}
 if len(raw)>maxBytes{return State{},ErrInvalid}
 decoder:=json.NewDecoder(bytes.NewReader(raw))
 decoder.DisallowUnknownFields()
 var state State
 if e=decoder.Decode(&state);e!=nil{return State{},fmt.Errorf("%w: %v",ErrInvalid,e)}
 var extra any
 if e=decoder.Decode(&extra);!errors.Is(e,io.EOF){return State{},ErrInvalid}
 if state.Version!=Version || (state.Held && state.Key!=KeyA) ||
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
  state.ReleasePhase!="qmp-acked" {return State{},ErrInvalid}
 if !state.Held && state.ReleasePhase!="" {return State{},ErrInvalid}
 return state,nil
}

// Transition is ONLY a write-ahead held=true record before key down.
// Legacy held=false without an independent guest receipt is denied.
// The caller serializes access; expected sequence prevents stale updates.
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
