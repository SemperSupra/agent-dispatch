// Package identity is a small fail-closed join contract between a REAL QMP
// release WITNESS and a REAL USB/IP guest event WITNESS. Neither raw QMP
// ACK nor transport detach can be independently trusted as host authorization.
// Existing R26 actuator, R23 Guard and R22 exporter implement the effects;
// this package never implements another QMP/USBIP protocol or controller.
package identity

import (
 "errors"
 "sync"

 "example.org/usb-fabric-r26-integrated/blue"
 releasegate "example.org/usb-fabric-r26-releasegate"
)

var ErrUnbound=errors.New("r24: QMP/USBIP witness does not bind same VM, lease and physical endpoint")
type Topology struct {
 VMIncarnation string
 QMPObjectID string
 USBIPExporter string
 GuestInputDeviceID string
}
type QMPWitness struct {
 VMIncarnation string
 ObjectID string
 LeaseEpoch string
 Generation uint64
 ReleaseSequence uint64
 ActualAck bool // Only trusted R26 actuator may set this in integrated run.
}
type USBIPWitness struct {
 VMIncarnation string
 Exporter string
 InputDeviceID string
 LeaseEpoch string
 Generation uint64
 ReleaseSequence uint64
 EventSequence uint64
 GuestUP bool
}
type Pair struct{
 mu sync.Mutex
 Lease blue.Lease
 Scope releasegate.Scope
 Topology Topology
 qmpVerify func(QMPWitness)bool
 guestVerify func(USBIPWitness)bool
 consumed bool
}
// New requires independently supplied callbacks for the original R26
// SO_PEERCRED/QMP owner and the R22 signed guest VHCI evidence; passing
// arbitrary booleans cannot authorize export. Unit callbacks are TEST-ONLY.
func New(lease blue.Lease,scope releasegate.Scope,topology Topology,
 qmpVerify func(QMPWitness)bool,guestVerify func(USBIPWitness)bool)(*Pair,error){
 if lease.Generation==0 || lease.Epoch==""||lease.Device==""||
  scope.LeaseEpoch!=lease.Epoch||scope.Generation!=lease.Generation||
  scope.DeviceID!=lease.Device||scope.ReleaseSequence==0||
  scope.GuestID==""||scope.GuestEpoch==""||scope.HostEpoch==""||
  topology.VMIncarnation==""||topology.QMPObjectID==""||
  topology.USBIPExporter==""||topology.GuestInputDeviceID==""||
  qmpVerify==nil||guestVerify==nil{return nil,ErrUnbound}
 return &Pair{Lease:lease,Scope:scope,Topology:topology,qmpVerify:qmpVerify,guestVerify:guestVerify},nil
}
// Authorize consumes exactly one pair. All fields are validated before
// invoking the user-supplied verified witness callbacks. No raw USB/IP
// client or provider gets a release capability from this function alone.
func(p *Pair)Authorize(q QMPWitness,u USBIPWitness)error{
 if p==nil{return ErrUnbound}
 p.mu.Lock();defer p.mu.Unlock()
 if p.consumed||!q.ActualAck||!u.GuestUP||
  q.VMIncarnation!=p.Topology.VMIncarnation||
  u.VMIncarnation!=p.Topology.VMIncarnation||
  q.ObjectID!=p.Topology.QMPObjectID||
  u.Exporter!=p.Topology.USBIPExporter||
  u.InputDeviceID!=p.Topology.GuestInputDeviceID||
  q.LeaseEpoch!=p.Lease.Epoch||u.LeaseEpoch!=p.Lease.Epoch||
  q.Generation!=p.Lease.Generation||u.Generation!=p.Lease.Generation||
  q.ReleaseSequence!=p.Scope.ReleaseSequence||
  u.ReleaseSequence!=p.Scope.ReleaseSequence||
  u.EventSequence==0||!p.qmpVerify(q)||!p.guestVerify(u){
  return ErrUnbound
 }
 p.consumed=true
 return nil
}
