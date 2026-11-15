//go:build linux
package planpermit

import(
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "sync/atomic"
 "testing"
)

func secureRoot(t *testing.T)string {
 t.Helper()
 root:=filepath.Join(t.TempDir(),"nonce-state")
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 return root
}
func TestLinuxStorePersistsReuseRejectionAcrossCloseAndReopen(t *testing.T){
 root:=secureRoot(t)
 store,err:=NewLinuxNonceStore(root);if err!=nil{t.Fatal(err)}
 key:=strings.Repeat("a",64)
 if err:=store.ConsumeOnce(context.Background(),key);err!=nil{t.Fatal(err)}
 if err:=store.Close();err!=nil{t.Fatal(err)}
 reopened,err:=NewLinuxNonceStore(root);if err!=nil{t.Fatal(err)}
 defer reopened.Close()
 if err:=reopened.ConsumeOnce(context.Background(),key);!errors.Is(err,ErrNonceConsumed){t.Fatalf("accepted reused reservation: %v",err)}
 dir,err:=os.ReadDir(root);if err!=nil{t.Fatal(err)}
 if len(dir)!=1||dir[0].Name()!="nonce-"+key{t.Fatalf("wrong receipt files: %v",dir)}
 info,err:=os.Stat(filepath.Join(root,dir[0].Name()));if err!=nil{t.Fatal(err)}
 if info.Mode().Perm()!=0600{t.Fatalf("weak nonce file perms: %v",info.Mode())}
}
func TestLinuxStoreConcurrentAcrossSeparateHandles(t *testing.T){
 root:=secureRoot(t)
 a,err:=NewLinuxNonceStore(root);if err!=nil{t.Fatal(err)};defer a.Close()
 b,err:=NewLinuxNonceStore(root);if err!=nil{t.Fatal(err)};defer b.Close()
 var success atomic.Int32
 var wg sync.WaitGroup
 key:=strings.Repeat("b",64)
 for i:=0;i<48;i++{
  wg.Add(1);go func(i int){defer wg.Done()
   store:=a;if i%2==1{store=b}
   if err:=store.ConsumeOnce(context.Background(),key);err==nil{success.Add(1)}else if !errors.Is(err,ErrNonceConsumed){t.Errorf("unexpected reserve error: %v",err)}
  }(i)
 }
 wg.Wait()
 if success.Load()!=1{t.Fatalf("expected one reservation: %d",success.Load())}
}
func TestLinuxStoreRejectsInsecurePathsAndSymlinks(t *testing.T){
 root:=secureRoot(t)
 if _,err:=NewLinuxNonceStore("relative-dir");err==nil{t.Fatal("relative accepted")}
 if _,err:=NewLinuxNonceStore("/");err==nil{t.Fatal("root accepted")}
 link:=filepath.Join(filepath.Dir(root),"symlinked-state")
 if err:=os.Symlink(root,link);err!=nil{t.Fatal(err)}
 if _,err:=NewLinuxNonceStore(link);err==nil{t.Fatal("symlink accepted")}
 if err:=os.Chmod(root,0755);err!=nil{t.Fatal(err)}
 if _,err:=NewLinuxNonceStore(root);err==nil{t.Fatal("permissive directory accepted")}
}
func TestLinuxStoreRejectsUnsafeKeysAndClosedStore(t *testing.T){
 root:=secureRoot(t)
 s,err:=NewLinuxNonceStore(root);if err!=nil{t.Fatal(err)}
 for _,key:=range []string{"",strings.Repeat("X",64),strings.Repeat("z",64),"../../etc/passwd",strings.Repeat("a",65)}{
  if err:=s.ConsumeOnce(context.Background(),key);err==nil{t.Fatalf("unsafe key accepted %q",key)}
 }
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if err:=s.ConsumeOnce(ctx,strings.Repeat("a",64));!errors.Is(err,context.Canceled){t.Fatalf("cancel ignored %v",err)}
 if err:=s.Close();err!=nil{t.Fatal(err)}
 if err:=s.ConsumeOnce(context.Background(),strings.Repeat("a",64));!errors.Is(err,ErrNonceStoreClosed){t.Fatalf("closed store accepted %v",err)}
}
func TestLinuxStoreVerifiedPermitAcrossRestart(t *testing.T){
 root:=secureRoot(t)
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 p,target,_,now,_:=sample(t)
 p.KeyID="verified-persistent-issuer"
 p,err=Sign(priv,p);if err!=nil{t.Fatal(err)}
 verifier,err:=NewVerifier(map[string]ed25519.PublicKey{p.KeyID:pub});if err!=nil{t.Fatal(err)}
 one,err:=NewLinuxNonceStore(root);if err!=nil{t.Fatal(err)}
 if err:=verifier.VerifyOnce(context.Background(),p,target,"HOST_INSTALL",now,one);err!=nil{t.Fatal(err)}
 if err:=one.Close();err!=nil{t.Fatal(err)}
 two,err:=NewLinuxNonceStore(root);if err!=nil{t.Fatal(err)}
 defer two.Close()
 if err:=verifier.VerifyOnce(context.Background(),p,target,"HOST_INSTALL",now,two);!errors.Is(err,ErrNonceConsumed){t.Fatalf("replayed signed permit: %v",err)}
}
