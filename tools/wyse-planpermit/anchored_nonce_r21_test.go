//go:build linux

package planpermit

import (
 "context"
 "errors"
 "os"
 "strings"
 "sync"
 "sync/atomic"
 "testing"
)

type testIndependentWitness struct{
 mu sync.Mutex
 used map[string]bool
 unavailable bool
}
func (w *testIndependentWitness)ReserveOutsideRollbackDomain(ctx context.Context,key string)error{
 if err:=ctx.Err();err!=nil{return err}
 w.mu.Lock();defer w.mu.Unlock()
 if w.unavailable{return errors.New("external authority offline")}
 if w.used==nil{w.used=map[string]bool{}}
 if w.used[key]{return errors.New("nonce burned globally")}
 w.used[key]=true
 return nil
}
type testLocalFailure struct{}
func (testLocalFailure)ConsumeOnce(context.Context,string)error{return errors.New("injected fsync failed")}

func TestR21CounterexampleLocalSnapshotRollbackCanReplay(t *testing.T){
 // An explicit counterexample, not a ZFS experiment: an authorized caller
 // can roll the local directory pathname back to its initial empty state.
 root:=secureRoot(t)
 key:=strings.Repeat("a",64)
 first,err:=NewLinuxNonceStore(root);if err!=nil{t.Fatal(err)}
 if err:=first.ConsumeOnce(context.Background(),key);err!=nil{t.Fatal(err)}
 if err:=first.Close();err!=nil{t.Fatal(err)}
 if err:=os.Rename(root,root+"-spent");err!=nil{t.Fatal(err)}
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 restored,err:=NewLinuxNonceStore(root);if err!=nil{t.Fatal(err)}
 defer restored.Close()
 // Expected accepted reuse demonstrates why the local store alone must NOT
 // be certified for snapshot-rollback defense.
 if err:=restored.ConsumeOnce(context.Background(),key);err!=nil{t.Fatalf("counterexample not reproduced: %v",err)}
}

func TestR21IndependentWitnessRejectsRestoredLocalReplay(t *testing.T){
 root:=secureRoot(t)
 key:=strings.Repeat("b",64)
 ext:=&testIndependentWitness{} // test double outside the replaced root
 first,err:=NewLinuxNonceStore(root);if err!=nil{t.Fatal(err)}
 gated,err:=NewAnchoredNonceStore(first,ext);if err!=nil{t.Fatal(err)}
 if err:=gated.ConsumeOnce(context.Background(),key);err!=nil{t.Fatal(err)}
 if err:=first.Close();err!=nil{t.Fatal(err)}
 if err:=os.Rename(root,root+"-spent");err!=nil{t.Fatal(err)}
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 restored,err:=NewLinuxNonceStore(root);if err!=nil{t.Fatal(err)}
 defer restored.Close()
 second,err:=NewAnchoredNonceStore(restored,ext);if err!=nil{t.Fatal(err)}
 if err:=second.ConsumeOnce(context.Background(),key);err==nil{t.Fatal("snapshot-rolled local ledger admitted globally consumed nonce")}
 entries,err:=os.ReadDir(root);if err!=nil{t.Fatal(err)}
 if len(entries)!=0{t.Fatalf("global reject must not write restored local ledger: %v",entries)}
}
func TestR21ExternalFailureAndUncertainLocalFailureBurnRules(t *testing.T){
 key:=strings.Repeat("c",64)
 ext:=&testIndependentWitness{unavailable:true}
 store,err:=NewAnchoredNonceStore(testLocalFailure{},ext);if err!=nil{t.Fatal(err)}
 if err:=store.ConsumeOnce(context.Background(),key);err==nil{t.Fatal("offline external authority accepted")}
 ext.unavailable=false
 if err:=store.ConsumeOnce(context.Background(),key);err==nil{t.Fatal("local fsync failure accepted")}
 // This nonce is burned externally despite uncertain local state.
 if err:=store.ConsumeOnce(context.Background(),key);err==nil{t.Fatal("reapproval after unknown local commit accepted")}
 if _,err:=NewAnchoredNonceStore(nil,ext);err==nil{t.Fatal("missing local ledger accepted")}
 if _,err:=NewAnchoredNonceStore(testLocalFailure{},nil);err==nil{t.Fatal("missing external authority accepted")}
}
func TestR21ConcurrentIndependentWitnessAtMostOne(t *testing.T){
 root:=secureRoot(t)
 local,err:=NewLinuxNonceStore(root);if err!=nil{t.Fatal(err)}
 defer local.Close()
 gate,err:=NewAnchoredNonceStore(local,&testIndependentWitness{});if err!=nil{t.Fatal(err)}
 key:=strings.Repeat("d",64)
 var good atomic.Int32
 var wg sync.WaitGroup
 for i:=0;i<48;i++{
  wg.Add(1);go func(){defer wg.Done()
   if err:=gate.ConsumeOnce(context.Background(),key);err==nil{good.Add(1)}
  }()
 }
 wg.Wait()
 if good.Load()!=1{t.Fatalf("expected exactly one global+local reservation: %d",good.Load())}
}
