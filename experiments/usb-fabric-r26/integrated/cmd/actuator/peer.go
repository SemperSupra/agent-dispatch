package main

import (
 "errors"
 "fmt"
 "net"
 "os"
 "syscall"
)

// ErrPeerDenied means the caller is not authorized by the local OS kernel.
// The frontend's Actor string is a synthetic selector, NOT authentication.
var ErrPeerDenied=errors.New("actuator: untrusted Unix peer credentials")

type PeerIdentity struct {
 UID uint32
 GID uint32
 PID int32
}

// Peer credentials are read from the actual connected Linux Unix socket.
// No caller-provided UID, header, PID or JSON field is ever trusted.
func kernelPeer(conn net.Conn)(PeerIdentity,error){
 uc,ok:=conn.(*net.UnixConn)
 if !ok{return PeerIdentity{},ErrPeerDenied}
 raw,err:=uc.SyscallConn()
 if err!=nil{return PeerIdentity{},err}
 var cred *syscall.Ucred
 var socketErr error
 if err=raw.Control(func(fd uintptr){
  cred,socketErr=syscall.GetsockoptUcred(int(fd),syscall.SOL_SOCKET,syscall.SO_PEERCRED)
 });err!=nil{return PeerIdentity{},err}
 if socketErr!=nil{return PeerIdentity{},socketErr}
 if cred==nil||cred.Pid<=1{return PeerIdentity{},ErrPeerDenied}
 return PeerIdentity{UID:cred.Uid,GID:cred.Gid,PID:cred.Pid},nil
}

// authorizePeer is an opt-in synthetic same-UID fence. True secure multiuser
// authorization additionally requires a distinct service account, a
// protected socket directory and narrowly scoped peer capabilities.
// Production must NOT accept a convenient --authorized-peer-uid equal to an
// untrusted user's UID as an authority boundary.
func authorizePeer(conn net.Conn,authorizedUID int)error {
 if authorizedUID<0{return nil} // old synthetic contract only
 if authorizedUID>int(^uint32(0)){return ErrPeerDenied}
 identity,err:=kernelPeer(conn)
 if err!=nil{return err}
 if identity.UID!=uint32(authorizedUID){return fmt.Errorf("%w: UID mismatch",ErrPeerDenied)}
 return nil
}

func currentUID()int{return os.Geteuid()}
