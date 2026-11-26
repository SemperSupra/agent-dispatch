//go:build linux

package blue

import (
 "crypto/ed25519"
 "errors"
 "path/filepath"
 "sort"
 "sync"

 "example.org/usb-fabric-r26-integrated/heldledger"
)

// ScopedGenesisOwner retains the original OS owner primitives for every
// stable conflict key while performing the original heldledger transaction.
// It is not a second Manager, distributed lock, or grant authority. The
// controller must supply enrolled scope/path and independently pinned keys.
// Legacy unscoped endpoints must not operate on an enrolled v2 resource.
type ScopedGenesisOwner struct{
 mu sync.Mutex
 scope heldledger.GenesisScope
 store heldledger.Store
 locks []*USBIPRecoveredOwner
 closed bool
}

func OpenScopedGenesisOwner(scope heldledger.GenesisScope,store heldledger.Store)(*ScopedGenesisOwner,error){
 if !filepath.IsAbs(store.Path)||filepath.Clean(store.Path)!=store.Path{return nil,ErrQuarantined}
 parent,e:=filepath.EvalSymlinks(filepath.Dir(store.Path))
 if e!=nil||parent!=filepath.Dir(store.Path){return nil,ErrQuarantined}
 keys,e:=scope.StableConflictKeys()
 if e!=nil{return nil,ErrQuarantined}
 // Prevent two different enrolled scopes from concurrently writing the same
 // configured journal pathname as well. Parent must be trusted and stable.
 keys=append(keys,"journal:"+store.Path)
 sort.Strings(keys)
 o:=&ScopedGenesisOwner{scope:scope,store:store}
 for _,key:=range keys{
  lock,e:=acquireUSBIPRecoveredOwner("scoped-v2:"+key,"resource-conflict",store.Path)
  if e!=nil{_ = o.Close();return nil,e}
  o.locks=append(o.locks,lock)
 }
 return o,nil
}

func(o *ScopedGenesisOwner)CreateHeldGenesis()(heldledger.State,error){
 if o==nil{return heldledger.State{},ErrQuarantined}
 o.mu.Lock()
 defer o.mu.Unlock()
 if o.closed{return heldledger.State{},ErrQuarantined}
 return o.store.CreateScopedHeldGenesis(o.scope)
}
func(o *ScopedGenesisOwner)PrepareAdmission(operation string,witnesses []heldledger.GenesisWitness,pins map[string]ed25519.PublicKey)(heldledger.State,error){
 if o==nil{return heldledger.State{},ErrQuarantined}
 o.mu.Lock()
 defer o.mu.Unlock()
 if o.closed{return heldledger.State{},ErrQuarantined}
 return o.store.PrepareScopedAdmission(o.scope,operation,witnesses,pins)
}
func(o *ScopedGenesisOwner)Close()error{
 if o==nil{return nil}
 o.mu.Lock()
 defer o.mu.Unlock()
 if o.closed{return nil}
 o.closed=true
 var err error
 for i:=len(o.locks)-1;i>=0;i--{err=errors.Join(err,o.locks[i].Close())}
 o.locks=nil
 return err
}
