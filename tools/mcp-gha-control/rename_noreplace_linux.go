//go:build linux

package main

// Atomic no-replace directory promotion. Linux renameat2(RENAME_NOREPLACE)
// forbids replacing an existing empty destination directory even if an
// adversary wins the race between the candidate's initial Lstat and commit.
// The source and destination must be on the same filesystem.
import (
 "errors"
 "runtime"
 "syscall"
 "unsafe"
)

func renameDirectoryNoReplace(source,destination string) error {
 src,err:=syscall.BytePtrFromString(source)
 if err!=nil{return err}
 dst,err:=syscall.BytePtrFromString(destination)
 if err!=nil{return err}
 var nr uintptr
 switch runtime.GOARCH {
 case "amd64":nr=316
 case "arm64":nr=276
 default:return errors.New("renameat2 no-replace not qualified on this Linux architecture")
 }
 const atFDCWD = ^uintptr(99) // -100 encoded as unsigned machine word
 const renameNoReplace uintptr = 1
 _,_,errno:=syscall.Syscall6(nr,atFDCWD,uintptr(unsafe.Pointer(src)),atFDCWD,uintptr(unsafe.Pointer(dst)),renameNoReplace,0)
 runtime.KeepAlive(src)
 runtime.KeepAlive(dst)
 if errno!=0{return errno}
 return nil
}
