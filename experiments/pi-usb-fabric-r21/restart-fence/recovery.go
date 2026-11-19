// Package restartfence provides a fail-closed bootstrap adapter for the
// existing disposable Go blue.Manager and heldledger.Store. This is a
// qualification adapter, not a production recovery supervisor.
package restartfence

import (
 "errors"

 "example.org/usb-fabric-r26-integrated/blue"
 "example.org/usb-fabric-r26-integrated/heldledger"
)

var ErrNeedsIndependentRelease = errors.New("restartfence: actual QMP and guest release required before admission")

// BootFenced constructs a new manager WITHOUT publishing it to any frontend.
// It fences admission BEFORE returning. Even a clean on-disk record cannot
// prove external USB/IP export and QMP topology are safe after host restart.
// The caller needs independent release evidence and host export control before
// allowing any lease. Never expose the fresh blue.New state directly.
func BootFenced(store heldledger.Store, device, port string)(*blue.Manager,heldledger.State,error){
 m:=blue.New(device,port,nil)
 m.Offline()
 state,err:=store.Read()
 if err!=nil{return m,heldledger.State{},err}
 return m,state,ErrNeedsIndependentRelease
}
