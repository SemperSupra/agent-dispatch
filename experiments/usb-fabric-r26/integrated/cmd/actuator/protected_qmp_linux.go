//go:build linux

package main

import (
 "encoding/json"
 "errors"
 "fmt"
 "net"
 "os"
 "path/filepath"
 "syscall"
 "time"
)

// connectProtectedQMP is the native actuator's opt-in protected pathname
// transport. Its expected PID is supplied by a TRUSTED launch controller,
// never by a frontend request. The dedicated QEMU/controller UID must be
// trusted. This does NOT revoke an intentionally transferred descriptor,
// authenticate a guest or prove a distributed owner.
func connectProtectedQMP(path string, expectedPID int)(*qmp,error){
 if expectedPID<=1 || uint64(expectedPID)>uint64(1<<31-1) || !filepath.IsAbs(path) || filepath.Clean(path)!=path {
  return nil,errors.New("protected QMP: invalid path or controller PID")
 }
 dir:=filepath.Dir(path)
 fd,err:=syscall.Open(dir,syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
 if err!=nil{return nil,fmt.Errorf("protected QMP directory: %w",err)}
 defer syscall.Close(fd)
 var stat syscall.Stat_t
 if err=syscall.Fstat(fd,&stat);err!=nil{return nil,err}
 if stat.Mode&syscall.S_IFMT!=syscall.S_IFDIR || stat.Mode&0777!=0700 || stat.Uid!=uint32(os.Geteuid()){
  return nil,errors.New("protected QMP: directory not private controller-owned mode 0700")
 }
 // Connect through the retained directory descriptor. A pathname rename
 // cannot switch the containing directory during this operation.
 target:=fmt.Sprintf("/proc/self/fd/%d/%s",fd,filepath.Base(path))
 info,err:=os.Lstat(target)
 if err!=nil{return nil,err}
 peerStat,ok:=info.Sys().(*syscall.Stat_t)
 if !ok || info.Mode()&os.ModeSocket==0 || peerStat.Uid!=uint32(os.Geteuid()){
  return nil,errors.New("protected QMP: socket is not controller-owned")
 }
 conn,err:=net.DialTimeout("unix",target,2*time.Second)
 if err!=nil{return nil,err}
 keep:=false
 defer func(){if !keep{_=conn.Close()}}()
 identity,err:=kernelPeer(conn)
 if err!=nil || identity.PID!=int32(expectedPID) || identity.UID!=uint32(os.Geteuid()){
  return nil,errors.New("protected QMP: kernel peer does not match pinned controller PID/UID")
 }
 // No protocol bytes are sent here. The caller must retain the existing
 // claimAndNegotiateQMP owner fence before any QMP capability is negotiated.
 keep=true
 return &qmp{conn:conn,enc:json.NewEncoder(conn),dec:json.NewDecoder(conn)},nil
}
