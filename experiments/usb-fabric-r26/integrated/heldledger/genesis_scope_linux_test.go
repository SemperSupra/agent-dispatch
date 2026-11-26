//go:build linux

package heldledger

import (
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func scopedFixture(t *testing.T)(Store,GenesisScope){
 t.Helper()
 dir:=t.TempDir()
 if err:=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
 return Store{Path:filepath.Join(dir,"held.json")},GenesisScope{
  SourceAuthority:"authority-1",SourceController:"controller-1",DownstreamPort:"1-2.3",
  DeviceResource:"enrolled-device-1",SourceHostIncarnation:"host-boot-A",
  SourceControllerIncarnation:"controller-boot-A",ConflictGroup:"hub-1"}
}

func TestScopedHeldGenesisPersistAndLegacyDeny(t *testing.T){
 st,scope:=scopedFixture(t)
 if _,err:=st.ReadScopedHeldGenesis(scope);!errors.Is(err,ErrInvalid){t.Fatalf("absent v2 accepted: %v",err)}
 created,err:=st.CreateScopedHeldGenesis(scope)
 if err!=nil{t.Fatal(err)}
 got,err:=st.ReadScopedHeldGenesis(scope)
 if err!=nil||got.Scope==nil||*got.Scope!=scope||got.Version!=ScopedVersion||!got.Held||created.Sequence!=1{t.Fatalf("readback=%+v %v",got,err)}
 before,err:=os.ReadFile(st.Path)
 if err!=nil{t.Fatal(err)}
 if _,err=st.Read();!errors.Is(err,ErrInvalid){t.Fatalf("legacy read v2 accepted: %v",err)}
 if _,err=st.BeginAdmission(1);!errors.Is(err,ErrInvalid){t.Fatalf("legacy admission v2 accepted: %v",err)}
 if _,err=st.Transition(1,true);!errors.Is(err,ErrInvalid){t.Fatalf("legacy transition v2 accepted: %v",err)}
 if _,err=st.CreateHeldGenesis();!errors.Is(err,ErrConflict){t.Fatalf("legacy overwrite accepted: %v",err)}
 if _,err=st.CreateScopedHeldGenesis(scope);!errors.Is(err,ErrConflict){t.Fatalf("duplicate v2 accepted: %v",err)}
 for _,edit:=range []func(*GenesisScope){
  func(x *GenesisScope){x.SourceAuthority="authority-2"},
  func(x *GenesisScope){x.SourceController="controller-2"},
  func(x *GenesisScope){x.DownstreamPort="1-2.4"},
  func(x *GenesisScope){x.DeviceResource="replacement"},
  func(x *GenesisScope){x.SourceHostIncarnation="host-boot-B"},
  func(x *GenesisScope){x.SourceControllerIncarnation="controller-boot-B"},
  func(x *GenesisScope){x.ConflictGroup="hub-2"},
 }{
  wrong:=scope;edit(&wrong)
  if _,err=st.ReadScopedHeldGenesis(wrong);!errors.Is(err,ErrInvalid){t.Fatalf("foreign scope accepted: %+v %v",wrong,err)}
 }
 after,err:=os.ReadFile(st.Path)
 if err!=nil||string(after)!=string(before){t.Fatal("denial changed original scoped ledger")}
 t.Log("SCOPED_V2_HELD_EXACT_SCOPE_LEGACY_DENIED=PASS")
}
func TestScopedGenesisMalformedAndDowngrade(t *testing.T){
 st,scope:=scopedFixture(t)
 bad:=scope;bad.DeviceResource=""
 if _,err:=st.CreateScopedHeldGenesis(bad);!errors.Is(err,ErrInvalid){t.Fatal("invalid scope accepted")}
 if _,err:=os.Lstat(st.Path);!errors.Is(err,os.ErrNotExist){t.Fatal("invalid scope created file")}
 if _,err:=st.CreateHeldGenesis();err!=nil{t.Fatal(err)}
 if _,err:=st.ReadScopedHeldGenesis(scope);!errors.Is(err,ErrInvalid){t.Fatal("legacy journal accepted as v2")}
 if _,err:=st.CreateScopedHeldGenesis(scope);!errors.Is(err,ErrConflict){t.Fatal("v1 overwritten")}
 state:=State{Version:ScopedVersion,Sequence:1,Key:KeyA,Held:true,Scope:&scope}
 raw,err:=json.Marshal(state)
 if err!=nil{t.Fatal(err)}
 mutations:=[]string{
  strings.Replace(string(raw),`"version":2`,`"version":1`,1),
  strings.Replace(string(raw),`"held":true`,`"held":false`,1),
  strings.Replace(string(raw),`"scope":{`,`"scope":{"source_authority":"forged",`,1),
  strings.Replace(string(raw),`"scope":{`,`"scope":{"unrecognized":"foreign",`,1),
 }
 for _,v:=range mutations{
  if v==string(raw){t.Fatal("mutation did not apply")}
  if err:=os.WriteFile(st.Path,[]byte(v),0600);err!=nil{t.Fatal(err)}
  if _,err:=st.ReadScopedHeldGenesis(scope);!errors.Is(err,ErrInvalid){t.Fatalf("mutated scope accepted: %s %v",v,err)}
  if _,err:=st.Read();!errors.Is(err,ErrInvalid){t.Fatalf("legacy downgrade accepted: %s %v",v,err)}
 }
 t.Log("SCOPED_V2_MALFORMED_DOWNGRADE_DENIED=PASS")
}
func TestScopedGenesisParentSyncFailureRetainsHeld(t *testing.T){
 st,scope:=scopedFixture(t)
 injected:=errors.New("injected parent sync failure")
 if _,err:=st.createScopedHeldGenesis(scope,(*os.File).Sync,func(*os.File)error{return injected});!errors.Is(err,injected){t.Fatalf("wrong error: %v",err)}
 got,err:=st.ReadScopedHeldGenesis(scope)
 if err!=nil||!got.Held{t.Fatalf("visible state no longer HELD: %+v %v",got,err)}
 if _,err:=st.CreateScopedHeldGenesis(scope);!errors.Is(err,ErrConflict){t.Fatalf("ambiguous genesis overwritten: %v",err)}
 if _,err:=st.BeginAdmission(1);!errors.Is(err,ErrInvalid){t.Fatal("ambiguous genesis admitted")}
 t.Log("SCOPED_V2_PARENT_SYNC_AMBIGUITY_REMAINS_HELD=PASS")
}
