package main

import(
 "errors"
 "syscall"
 "unsafe"
)

// Linux EVIOCGKEY(n) reads the *kernel* device's currently pressed key
// bitset, not a cached host flag, previous signed event or QMP response.
// This workcell targets disposable x86_64 Linux guests; no production
// cross-architecture ioctl ABI claim is made.
const keyA=30
const keyBytes=96
const evioCGKey=uintptr((2<<30)|(keyBytes<<16)|(int('E')<<8)|0x18)
func kernelHeldKey(fd uintptr)(bool,error){
 if fd==^uintptr(0){return false,errors.New("invalid evdev descriptor")}
 var keys [keyBytes]byte
 _,_,e:=syscall.Syscall(syscall.SYS_IOCTL,fd,evioCGKey,uintptr(unsafe.Pointer(&keys[0])))
 if e!=0{return false,e}
 return heldFromKeyBits(keys[:]),nil
}
func heldFromKeyBits(keys []byte)bool{
 if len(keys)<=keyA/8{return false}
 return keys[keyA/8]&(1<<uint(keyA%8))!=0
}
