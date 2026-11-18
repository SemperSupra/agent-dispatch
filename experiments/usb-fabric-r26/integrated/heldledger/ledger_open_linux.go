//go:build linux

package heldledger

import (
 "errors"
 "os"
 "syscall"
)

// O_NOFOLLOW is enforced by the Linux kernel atomically with open(2).
// R13's Lstat and SameFile checks remain as defense in depth.
func openJournalNoFollow(path string)(*os.File,error){
 fd,err:=syscall.Open(path,syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,0)
 if err!=nil{
  if errors.Is(err,syscall.ELOOP)||errors.Is(err,syscall.ENOENT){
   return nil,ErrInvalid
  }
  return nil,err
 }
 return os.NewFile(uintptr(fd),path),nil
}
