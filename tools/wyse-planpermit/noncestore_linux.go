//go:build linux

// Package planpermit also provides a Linux-local durable nonce reservation
// for a controller-mounted, owner-managed persistent state dataset.
// This is NOT a distributed lock or a tested TrueNAS ZFS deployment.
package planpermit

import (
 "context"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "sync"
 "syscall"
)

var ErrNonceConsumed=errors.New("approval nonce already reserved")
var ErrNonceStoreClosed=errors.New("approval nonce store closed")

// LinuxNonceStore reserves exact hashed nonces using O_EXCL, fsync(file),
// fsync(directory) and an already-open, non-symlink directory fd. It never
// removes a consumed nonce. Ambiguous write/sync failures leave the marker
// in place and return an error. Durability depends on filesystem/mount
// guarantees and must be separately verified on the actual TrueNAS dataset.
type LinuxNonceStore struct {
 mu sync.RWMutex
 fd int
}

// NewLinuxNonceStore requires a pre-existing 0700, locally-owned directory
// with an absolute canonical path. It does not create or chmod a directory,
// mount filesystems, or authorize one. Callers must provision and back up the
// correct persistent host-path outside the disposable container.
func NewLinuxNonceStore(root string)(*LinuxNonceStore,error){
 if root==""||!filepath.IsAbs(root)||filepath.Clean(root)!=root||root=="/"{
  return nil,errors.New("absolute canonical dedicated nonce directory required")
 }
 fd,err:=syscall.Open(root,syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
 if err!=nil{return nil,fmt.Errorf("nonce directory open denied: %w",err)}
 var stat syscall.Stat_t
 if err=syscall.Fstat(fd,&stat);err!=nil{syscall.Close(fd);return nil,err}
 if stat.Mode&syscall.S_IFMT!=syscall.S_IFDIR||stat.Uid!=uint32(os.Geteuid())||stat.Mode&0777!=0700{
  syscall.Close(fd)
  return nil,errors.New("nonce store directory must be user-owned mode 0700")
 }
 return &LinuxNonceStore{fd:fd},nil
}
func validNonceKey(key string)bool{
 if len(key)!=64{return false}
 for _,c:=range key{
  if !(c>='0'&&c<='9'||c>='a'&&c<='f'){return false}
 }
 return true
}
// ConsumeOnce implements NonceStore. The key is the 64-char lowercase SHA256
// digest supplied by VerifyOnce, never the raw nonce or a caller-chosen path.
func (s *LinuxNonceStore)ConsumeOnce(ctx context.Context,key string)error{
 if s==nil||!validNonceKey(key){return errors.New("invalid nonce store/key")}
 if err:=ctx.Err();err!=nil{return err}
 s.mu.RLock()
 defer s.mu.RUnlock()
 if s.fd<0{return ErrNonceStoreClosed}
 fd,err:=syscall.Openat(s.fd,"nonce-"+key,syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0600)
 if errors.Is(err,syscall.EEXIST){return ErrNonceConsumed}
 if err!=nil{return fmt.Errorf("reserve nonce failed closed: %w",err)}
 f:=os.NewFile(uintptr(fd),"nonce-record")
 marker:=[]byte("wyse-planpermit-nonce-consumed-v1\n")
 _,werr:=f.Write(marker)
 if werr==nil {werr=f.Sync()}
 cerr:=f.Close()
 if werr!=nil{return fmt.Errorf("nonce reservation sync uncertain: %w",werr)}
 if cerr!=nil{return fmt.Errorf("nonce record close uncertain: %w",cerr)}
 if err=syscall.Fsync(s.fd);err!=nil{return fmt.Errorf("nonce directory sync uncertain: %w",err)}
 return nil
}
func(s *LinuxNonceStore)Close()error{
 if s==nil{return nil}
 s.mu.Lock()
 defer s.mu.Unlock()
 if s.fd<0{return nil}
 fd:=s.fd;s.fd=-1
 return syscall.Close(fd)
}
