package armgate

import(
 "context"
 "errors"
 "os"
 "path/filepath"
 "sync"
 "testing"

 planpermit "github.com/SemperSupra/agent-dispatch/tools/wyse-planpermit"
 modeplan "github.com/SemperSupra/agent-dispatch/tools/wyse-modeplan/modeplan"
)
type syntheticExternalAnchor struct {mu sync.Mutex; used map[string]bool}
func (a *syntheticExternalAnchor)ReserveOutsideRollbackDomain(ctx context.Context,key string)error{
 if err:=ctx.Err();err!=nil{return err}
 a.mu.Lock();defer a.mu.Unlock()
 if a.used==nil{a.used=map[string]bool{}}
 if a.used[key]{return errors.New("globally used nonce")}
 a.used[key]=true
 return nil
}
func TestR21TLSScopedArmRejectsReplayAfterLocalLedgerRestore(t *testing.T){
 n,p,peer,grant,audience,now:=scopedFixture(t)
 _,_,token,verifier,_:=prepared(t)
 basedir:=t.TempDir()
 root:=filepath.Join(basedir,"ledger")
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 local,err:=planpermit.NewLinuxNonceStore(root);if err!=nil{t.Fatal(err)}
 external:=&syntheticExternalAnchor{} // IN-MEMORY TEST DOUBLE, never production
 dual,err:=planpermit.NewAnchoredNonceStore(local,external);if err!=nil{t.Fatal(err)}
 armed,err:=AuthorizeTLSScopedArm(context.Background(),n,p,token,verifier,dual,now,peer,audience,grant)
 if err!=nil||armed.Stage!=modeplan.Armed{t.Fatalf("exact scoped synthetic arm failed: %v",err)}
 if err:=local.Close();err!=nil{t.Fatal(err)}
 if err:=os.Rename(root,root+"-consumed");err!=nil{t.Fatal(err)}
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 restored,err:=planpermit.NewLinuxNonceStore(root);if err!=nil{t.Fatal(err)}
 defer restored.Close()
 dual,err=planpermit.NewAnchoredNonceStore(restored,external);if err!=nil{t.Fatal(err)}
 if _,err:=AuthorizeTLSScopedArm(context.Background(),n,p,token,verifier,dual,now,peer,audience,grant);err==nil{
  t.Fatal("globally consumed permit was rearmed after synthetic local rollback")
 }
 if records,err:=os.ReadDir(root);err!=nil||len(records)>0{t.Fatalf("restored ledger wrongly consumed after global rejection: %v",err)}
 if !n.GARMHold{t.Fatal("synthetic arming changed GARM authority")}
}
