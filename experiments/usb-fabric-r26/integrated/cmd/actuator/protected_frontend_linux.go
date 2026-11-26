//go:build linux

package main

import (
 "errors"
 "net"
 "os"
 "path/filepath"
 "syscall"
)

func validateProtectedFrontend(qmpPID,peerUID int,p operationPolicy,scoped bool,keyPath,receiptPath string)error{
 if qmpPID<=1||peerUID<=0||uint64(peerUID)>=uint64(^uint32(0))||peerUID==os.Geteuid()||!p.configured{
  return errors.New("require protected QMP, distinct non-root frontend UID and explicit operations")
 }
 for op:=range p.allowed{
  if op!="status"&&op!="ports"&&(!scoped||keyPath==""||receiptPath==""){
   return errors.New("mutating operations require configured scoped signed guest proof channel")
  }
 }
 return nil
}

// The trusted deployment provisions a distinct controller account and group.
// Directory 0710 permits traversal by that group only; SO_PEERCRED in handle
// independently restricts the actual UID. No group member can rename sockets.
// This is not isolation against the trusted controller UID or root.
func listenActuatorFrontend(path string,protected bool)(*net.UnixListener,error){
 if protected{
  if !filepath.IsAbs(path)||filepath.Clean(path)!=path{return nil,errors.New("noncanonical frontend path")}
  dir:=filepath.Dir(path)
  info,err:=os.Lstat(dir)
  if err!=nil{return nil,err}
  st,ok:=info.Sys().(*syscall.Stat_t)
  if !ok||!info.IsDir()||info.Mode().Perm()!=0710||st.Uid!=uint32(os.Geteuid())||st.Gid!=uint32(os.Getegid()){
   return nil,errors.New("frontend directory must be controller-owned mode 0710, effective group")
  }
 }
 if _,err:=os.Lstat(path);err==nil{return nil,errors.New("refusing existing frontend socket")}else if !errors.Is(err,os.ErrNotExist){return nil,err}
 l,err:=net.ListenUnix("unix",&net.UnixAddr{Name:path,Net:"unix"})
 if err!=nil{return nil,err}
 l.SetUnlinkOnClose(true)
 mode:=os.FileMode(0600)
 if protected{
  mode=0660
  if err=os.Chown(path,os.Geteuid(),os.Getegid());err!=nil{_ = l.Close();return nil,err}
 }
 if err=os.Chmod(path,mode);err!=nil{_ = l.Close();return nil,err}
 return l,nil
}
