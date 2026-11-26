package heldledger

import (
 "bytes"
 "encoding/json"
 "io"
)

const ScopedVersion = 2

// GenesisScope separates stable enrolled resource keys from boot incarnations.
// These are host-supplied observations, NOT self-authenticating credentials.
// Do not derive a global identity from busid or arbitrary USB iSerial alone.
type GenesisScope struct {
 SourceAuthority string `json:"source_authority"`
 SourceController string `json:"source_controller"`
 DownstreamPort string `json:"downstream_port"`
 DeviceResource string `json:"device_resource"`
 SourceHostIncarnation string `json:"source_host_incarnation"`
 SourceControllerIncarnation string `json:"source_controller_incarnation"`
 ConflictGroup string `json:"conflict_group"`
}

// Scope is bounded and canonical. Reject duplicate aliases at the nested
// object boundary as well as at the original journal's top level.
func (s *GenesisScope) UnmarshalJSON(raw []byte) error {
 if err:=rejectDuplicateJournalKeys(raw);err!=nil{return ErrInvalid}
 type wire GenesisScope
 var v wire
 d:=json.NewDecoder(bytes.NewReader(raw))
 d.DisallowUnknownFields()
 if err:=d.Decode(&v);err!=nil{return ErrInvalid}
 var extra any
 if err:=d.Decode(&extra);err!=io.EOF{return ErrInvalid}
 *s=GenesisScope(v)
 if !s.valid(){return ErrInvalid}
 return nil
}
func (s GenesisScope) valid()bool{
 for _,v:=range []string{s.SourceAuthority,s.SourceController,s.DownstreamPort,s.DeviceResource,s.SourceHostIncarnation,s.SourceControllerIncarnation,s.ConflictGroup}{
  if len(v)<1||len(v)>128{return false}
  for _,r:=range v{
   if !(r>='a'&&r<='z'||r>='A'&&r<='Z'||r>='0'&&r<='9'||r=='-'||r=='_'||r=='.'||r==':'||r=='/'){return false}
  }
 }
 return true
}
func validateScopedHeldGenesis(st State,expected GenesisScope)error{
 if !expected.valid()||st.Version!=ScopedVersion||st.Scope==nil||*st.Scope!=expected||
  st.Sequence!=1||!st.Held||st.Key!=KeyA||st.AdmissionIntent||st.ReleasePhase!=""||
  st.KernelWitnessHash!=""||st.LastReleaseEventSequence!=0||st.LastReleaseProofHash!=""{
  return ErrInvalid
 }
 return nil
}

// ReadScopedHeldGenesis recognizes only a v2 HELD bootstrap record matching
// the entire expected scope. A missing, v1, different-boot, altered or clean
// record cannot be admitted. It does not clear HELD or issue any lease.
func(s Store)ReadScopedHeldGenesis(expected GenesisScope)(State,error){
 st,err:=s.readDecodedState()
 if err!=nil{return State{},err}
 if err=validateScopedHeldGenesis(st,expected);err!=nil{return State{},err}
 return st,nil
}
