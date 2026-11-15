//go:build linux

package planpermit

import (
 "context"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestR21NonceDirectoryRejectsSymlinkInEveryAncestor(t *testing.T){
 // The existing store used O_NOFOLLOW for only the LAST component; with
 // /tmp/<alias>/<dir> a symlinked ancestor silently redirected the durable
 // anti-replay ledger to an unexpected tree. No privileged filesystem needed.
 base:=t.TempDir()
 actual:=filepath.Join(base,"actual")
 if err:=os.Mkdir(actual,0700);err!=nil{t.Fatal(err)}
 ledger:=filepath.Join(actual,"ledger")
 if err:=os.Mkdir(ledger,0700);err!=nil{t.Fatal(err)}
 alias:=filepath.Join(base,"alias")
 if err:=os.Symlink(actual,alias);err!=nil{t.Fatal(err)}
 for _,root:=range []string{filepath.Join(alias,"ledger")} {
  t.Run(strings.ReplaceAll(root,base,"TEST"),func(t *testing.T){
   store,err:=NewLinuxNonceStore(root)
   if err==nil{store.Close();t.Fatal("symlink in persistent path accepted")}
  })
 }
 // The original leaf-only symlink denial stays intact, and an exact
 // component walk must continue to accept a real, non-symlink root.
 store,err:=NewLinuxNonceStore(ledger)
 if err!=nil{t.Fatalf("real secure root denied: %v",err)}
 defer store.Close()
}
func TestR21NonceFDIsBoundAcrossAuthorizedDirectoryRename(t *testing.T){
 // We do not claim rollback defense if an authorized owner renames or
 // restores a path. This test only proves the store cannot be silently
 // redirected by a second process replacing its pathname after open.
 base:=t.TempDir()
 old:=filepath.Join(base,"persist")
 moved:=filepath.Join(base,"moved")
 if err:=os.Mkdir(old,0700);err!=nil{t.Fatal(err)}
 store,err:=NewLinuxNonceStore(old);if err!=nil{t.Fatal(err)}
 defer store.Close()
 if err:=os.Rename(old,moved);err!=nil{t.Fatal(err)}
 if err:=os.Mkdir(old,0700);err!=nil{t.Fatal(err)}
 if err:=store.ConsumeOnce(context.Background(),strings.Repeat("a",64));err!=nil{t.Fatal(err)}
 if _,err:=os.Stat(filepath.Join(moved,"nonce-"+strings.Repeat("a",64)));err!=nil{t.Fatalf("opened FD redirected after path rename: %v",err)}
 if _,err:=os.Stat(filepath.Join(old,"nonce-"+strings.Repeat("a",64)));!os.IsNotExist(err){t.Fatalf("unexpected path accepted record: %v",err)}
}
