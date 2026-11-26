//go:build linux

package blue

// R27-Q: Linux host-local recovered USB/IP owner gate. Composed from the
// qualified R26-L10 owner primitives (persistent O_NOFOLLOW flock + AF_UNIX
// abstract ownership), adapted to a canonical *USB/IP resource* rather than
// incorrectly treating a QMP VM socket as Linux vhci_hcd authority.
//
// This is NOT distributed fencing, device attestation, or protection against
// arbitrary privileged actors, separate network namespaces or different
// kernel USB/IP export names. Production integration must pin the canonical
// resource to independently trusted host kernel sensors and enforce OS ACLs.
import (
 "crypto/sha256"
 "errors"
 "fmt"
 "net"
 "os"
 "path/filepath"
 "sync"
 "syscall"

 "example.org/usb-fabric-r26-integrated/heldledger"
)

type USBIPRecoveredOwner struct {
 mu sync.Mutex
 file *os.File
 alias net.Listener
 manager *Manager
}

func (o *USBIPRecoveredOwner) Close() error {
 if o==nil{return nil}
 o.mu.Lock()
 defer o.mu.Unlock()
 if o.manager!=nil {
  // Fence the original Manager under its own mutex BEFORE dropping either
  // OS owner handle. Snapshot-then-close would race Reserve and permit
  // a retained old Manager to claim a new lease after owner relinquishment.
  if err:=o.manager.retireOwner();err!=nil{return err}
 }
 if o.alias!=nil { _=o.alias.Close();o.alias=nil }
 if o.file!=nil {err:=o.file.Close();o.file=nil;return err}
 return nil
}

func acquireUSBIPRecoveredOwner(device,port,journalPath string)(*USBIPRecoveredOwner,error){
 if device=="" || port=="" || journalPath=="" || !filepath.IsAbs(journalPath) {
  return nil,fmt.Errorf("%w: invalid recovery owner scope",ErrQuarantined)
 }
 // Require an already protected, stable journal parent. A world writable
 // /tmp journal can be renamed/replaced by another actor and is unsafe.
 dir:=filepath.Dir(journalPath)
 info,err:=os.Lstat(dir)
 if err!=nil || !info.IsDir() || info.Mode().Perm()!=0700 {
  return nil,fmt.Errorf("%w: journal directory integrity",ErrQuarantined)
 }
 stat,ok:=info.Sys().(*syscall.Stat_t)
 if !ok || stat.Uid!=uint32(os.Geteuid()){return nil,fmt.Errorf("%w: journal directory owner",ErrQuarantined)}
 uid:=os.Geteuid()
 // Use a kernel-resident name first so unlinking/replacing a lock inode
 // cannot create a second owner in this same Linux network namespace.
 digest:=sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s",uid,device,port)))
 aliasName:=fmt.Sprintf("@r27q-usbip-%x",digest[:16])
 alias,err:=net.Listen("unix",aliasName)
 if err!=nil{return nil,fmt.Errorf("%w: linux abstract owner busy: %v",ErrQuarantined,err)}
 root:=fmt.Sprintf("/tmp/.r27q-usbip-owner-%d",uid)
 if e:=os.Mkdir(root,0700);e!=nil && !errors.Is(e,os.ErrExist) {
  _=alias.Close();return nil,fmt.Errorf("%w: owner root create",ErrQuarantined)
 }
 rootInfo,e:=os.Lstat(root)
 if e!=nil || !rootInfo.IsDir() || rootInfo.Mode().Perm()!=0700 {
  _=alias.Close();return nil,fmt.Errorf("%w: owner root integrity",ErrQuarantined)
 }
 rootStat,ok:=rootInfo.Sys().(*syscall.Stat_t)
 if !ok || rootStat.Uid!=uint32(uid) {
  _=alias.Close();return nil,fmt.Errorf("%w: owner root UID",ErrQuarantined)
 }
 name:=filepath.Join(root,fmt.Sprintf("usbip-%x.lock",digest[:16]))
 fd,e:=syscall.Open(name,syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,0600)
 if e!=nil{_=alias.Close();return nil,fmt.Errorf("%w: lock open: %v",ErrQuarantined,e)}
 file:=os.NewFile(uintptr(fd),name)
 if file==nil{_ = syscall.Close(fd);_ = alias.Close();return nil,ErrQuarantined}
 state,e:=file.Stat()
 if e!=nil || !state.Mode().IsRegular() || state.Mode().Perm()!=0600 {
  _=file.Close();_=alias.Close();return nil,fmt.Errorf("%w: lock mode integrity",ErrQuarantined)
 }
 if e=syscall.Flock(fd,syscall.LOCK_EX|syscall.LOCK_NB);e!=nil {
  _=file.Close();_=alias.Close();return nil,fmt.Errorf("%w: lock busy: %v",ErrQuarantined,e)
 }
 // Never unlink the inode on close: retain it to preclude lock-path ABA.
 return &USBIPRecoveredOwner{file:file,alias:alias},nil
}

// NewAfterExclusiveJournalRecovery binds both exclusive host owner and
// durable HELD journal *before* returning a reservable original Manager.
// The only caller-visible manager is returned with a retained owner handle.
// Callers must keep the owner for the entire Manager lifecycle.
func NewAfterExclusiveJournalRecovery(device,port string,exec Executor,
 store heldledger.Store)(*Manager,*USBIPRecoveredOwner,error){
 owner,err:=acquireUSBIPRecoveredOwner(device,port,store.Path)
 if err!=nil{return nil,nil,err}
 m,err:=NewAfterJournalRecovery(device,port,exec,store)
 if err!=nil{
  _=owner.Close()
  return m,nil,fmt.Errorf("%w: recovered journal verification",ErrQuarantined)
 }
 owner.manager=m
 return m,owner,nil
}
