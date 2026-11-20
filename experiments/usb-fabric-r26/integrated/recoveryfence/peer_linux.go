// Package recoveryfence bounds a disposable post-crash recovery observer
// to ONE kernel-observed QEMU peer and a cooperative same-host lock.
//
// THREAT LIMIT: a malicious same-UID process with existing raw QMP access
// can still bypass this lock (H7 RED). This is NOT exclusive privileged
// hypervisor control, host attestation, or a production security boundary.
package recoveryfence

import(
 "crypto/sha256"
 "errors"
 "fmt"
 "net"
 "os"
 "strconv"
 "strings"
 "syscall"
)
var ErrUntrusted=errors.New("recoveryfence: untrusted QEMU peer or duplicate recovery")
type Peer struct{
 UID uint32
 PID int32
 Boot string
 Start string
}
func Identify(conn net.Conn)(Peer,error){
 unix,ok:=conn.(*net.UnixConn)
 if !ok{return Peer{},ErrUntrusted}
 raw,err:=unix.SyscallConn()
 if err!=nil{return Peer{},err}
 var cred *syscall.Ucred
 var sockErr error
 if err=raw.Control(func(fd uintptr){cred,sockErr=syscall.GetsockoptUcred(int(fd),syscall.SOL_SOCKET,syscall.SO_PEERCRED)});err!=nil{return Peer{},err}
 if sockErr!=nil{return Peer{},sockErr}
 if cred==nil||cred.Pid<=1||cred.Uid!=uint32(os.Geteuid()){return Peer{},ErrUntrusted}
 statRaw,err:=os.ReadFile("/proc/"+strconv.Itoa(int(cred.Pid))+"/stat")
 if err!=nil{return Peer{},err}
 end:=strings.LastIndexByte(string(statRaw),')')
 if end<0{return Peer{},ErrUntrusted}
 fields:=strings.Fields(string(statRaw[end+1:]))
 if len(fields)<20||fields[19]==""{return Peer{},ErrUntrusted}
 bootRaw,err:=os.ReadFile("/proc/sys/kernel/random/boot_id")
 if err!=nil{return Peer{},err}
 boot:=strings.TrimSpace(string(bootRaw))
 if len(boot)<8{return Peer{},ErrUntrusted}
 return Peer{UID:cred.Uid,PID:cred.Pid,Boot:boot,Start:fields[19]},nil
}
type Lock struct{listener net.Listener;Peer Peer}
func(l *Lock)Close()error{
 if l==nil||l.listener==nil{return nil}
 return l.listener.Close()
}
func Acquire(qmp,receipt net.Conn)(*Lock,error){
 a,err:=Identify(qmp);if err!=nil{return nil,err}
 b,err:=Identify(receipt);if err!=nil{return nil,err}
 if a!=b{return nil,ErrUntrusted}
 sum:=sha256.Sum256([]byte(fmt.Sprintf("%d/%d/%s/%s",a.UID,a.PID,a.Boot,a.Start)))
 // A live Linux abstract AF_UNIX bind cannot be replaced by unlinking a
 // pathname. This only arbitrates cooperating controllers in THIS netns.
 name:=fmt.Sprintf("@r27-recovery-fence-%x",sum[:16])
 ln,err:=net.Listen("unix",name)
 if err!=nil{return nil,fmt.Errorf("%w: %v",ErrUntrusted,err)}
 return &Lock{listener:ln,Peer:a},nil
}
