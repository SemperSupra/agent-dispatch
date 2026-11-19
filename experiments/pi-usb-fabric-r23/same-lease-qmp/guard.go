// Package samelease composes existing R26 releasegate/evidence and heldledger
// with the existing R22 ExportGate. It provides NO QMP client and NO USBIP
// kernel driver. A trustworthy R26 actuator must supply the real QMP ACK.
// Unit tests use public R26 synthetic guest MAC and simulated QMP ACK.
package samelease

import (
 "errors"

 "example.org/usb-fabric-r26-integrated/blue"
 "example.org/usb-fabric-r26-integrated/heldledger"
 releasegate "example.org/usb-fabric-r26-releasegate"
 "example.org/usb-fabric-r26-releasegate/evidence"
 composition "example.org/usb-fabric-r22-qmp-usbip-compose"
)

var ErrNotProven=errors.New("r23: same-lease QMP ACK and guest UP not independently proven")
type Guard struct{
 Lease blue.Lease
 Scope releasegate.Scope
 Gate *releasegate.Gate
 Bridge *evidence.Bridge
 Store heldledger.Store
 Export *composition.Interlock
 down evidence.Event
}
func New(lease blue.Lease,scope releasegate.Scope,store heldledger.Store,udc composition.ExportGate,verify evidence.Verifier)(*Guard,error){
 if lease.Generation==0||lease.Epoch==""||scope.LeaseEpoch!=lease.Epoch||
  scope.Generation!=lease.Generation||scope.DeviceID!=lease.Device||
  scope.GuestID==""||scope.HostEpoch==""||scope.GuestEpoch==""||
  scope.ReleaseSequence==0||verify==nil{return nil,ErrNotProven}
 rg,err:=releasegate.New(scope);if err!=nil{return nil,err}
 bridge,err:=evidence.New(rg,scope,verify);if err!=nil{return nil,err}
 exporter,err:=composition.NewFenced(store,udc,lease.Device,lease.Port)
 if err!=nil{return nil,err}
 return &Guard{Lease:lease,Scope:scope,Gate:rg,Bridge:bridge,Store:store,Export:exporter},nil
}
func(g *Guard)ObserveDown(event evidence.Event)error{
 if g==nil{return ErrNotProven}
 if err:=g.Bridge.ObserveDown(event);err!=nil{return err}
 g.down=event
 return nil
}
// Caller is the existing trusted R26 actuator after it executes actual
// input-send-event and observes QMP ACK. The policy layer cannot authenticate
// arbitrary callers by itself: this is a TEST-only composition contract.
func(g *Guard)AcknowledgeQMP()error{
 if g==nil{return ErrNotProven}
 if err:=g.Gate.RequestRelease(g.Scope);err!=nil{return err}
 return g.Gate.AcknowledgeQMP(g.Scope)
}
func(g *Guard)ConfirmAndBind(up evidence.Event)error{
 if g==nil||g.down.EventSequence==0{return ErrNotProven}
 if err:=g.Bridge.ConfirmUp(up);err!=nil{return err}
 if !g.Bridge.Reclaimable()||g.Gate.Snapshot().Scope!=g.Scope{return ErrNotProven}
 st,err:=g.Store.Read()
 if err!=nil{return err}
 if !st.Held || st.ReleasePhase!="qmp-acked" || st.Sequence!=g.Scope.ReleaseSequence {
  return ErrNotProven
 }
 if up.Scope!=g.Scope || up.Down || up.EventSequence<=g.down.EventSequence {
  return ErrNotProven
 }
 claim:=heldledger.ReleaseClaim{
  GuestID:g.Scope.GuestID,DeviceID:g.Scope.DeviceID,
  HostEpoch:g.Scope.HostEpoch,GuestEpoch:g.Scope.GuestEpoch,
  LeaseEpoch:g.Scope.LeaseEpoch,Generation:g.Scope.Generation,
  ReleaseSequence:g.Scope.ReleaseSequence,DownEventSequence:g.down.EventSequence,
  EventSequence:up.EventSequence,Source:"guest.evdev",Key:heldledger.KeyA,
  KeyReleased:true,Proof:up.Proof,
 }
 verify:=func(candidate heldledger.ReleaseClaim)bool{
  return candidate==claim && g.Gate.Reclaimable() && g.Bridge.Reclaimable()
 }
 return g.Export.ReleaseAndBind(st.Sequence,claim,verify)
}
func(g *Guard)ReserveNext(actor string)(blue.Lease,error){
 if g==nil{return blue.Lease{},ErrNotProven}
 return g.Export.Reserve(actor,g.Lease.Device,g.Lease.Port)
}
