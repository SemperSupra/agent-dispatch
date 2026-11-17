// Package guestwire implements a disposable USB evdev receipt wire for R26.
// The MAC key below is PUBLIC, TEST-ONLY and provides NO production trust.
// Real guest identity must instead be attested with host-controlled secrets
// bound to a specific VM epoch through an authenticated transport.
package guestwire

import (
 "crypto/hmac"
 "crypto/sha256"
 "encoding/hex"
 "fmt"

 releasegate "example.org/usb-fabric-r26-releasegate"
 "example.org/usb-fabric-r26-releasegate/evidence"
)

var testOnlyKey=[]byte("R26-L8-SYNTHETIC-DO-NOT-USE-IN-PRODUCTION")

func Scope()releasegate.Scope {
 return releasegate.Scope{
  GuestID:"r26-l8-qemu-linux",DeviceID:"usb-kbd-a",
  HostEpoch:"synthetic-host-1",GuestEpoch:"synthetic-vm-1",
  LeaseEpoch:"synthetic-lease-1",Generation:1,ReleaseSequence:1,
 }
}

func mac(e evidence.Event)[]byte {
 h:=hmac.New(sha256.New,testOnlyKey)
 _,_ = fmt.Fprintf(h,"%s|%s|%s|%s|%s|%d|%d|%s|%s|%t|%d",
  e.Scope.GuestID,e.Scope.DeviceID,e.Scope.HostEpoch,
  e.Scope.GuestEpoch,e.Scope.LeaseEpoch,e.Scope.Generation,
  e.Scope.ReleaseSequence,e.Source,e.KeyCode,e.Down,e.EventSequence)
 return h.Sum(nil)
}

func SignForSyntheticGuest(e evidence.Event)evidence.Event {
 e.Proof=hex.EncodeToString(mac(e))
 return e
}

func VerifySyntheticGuest(e evidence.Event)bool {
 got,err:=hex.DecodeString(e.Proof)
 return err==nil && hmac.Equal(mac(e),got)
}
