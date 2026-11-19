package identity

import (
 "errors"
 "testing"

 "example.org/usb-fabric-r26-integrated/blue"
 releasegate "example.org/usb-fabric-r26-releasegate"
)
func makePair(t *testing.T)(*Pair,QMPWitness,USBIPWitness){
 t.Helper()
 m:=blue.New("keyboard","xhci0/auto",nil)
 lease,err:=m.Reserve("consumer-A","keyboard","xhci0/auto");if err!=nil{t.Fatal(err)}
 scope:=releasegate.Scope{GuestID:"consumer-A",DeviceID:lease.Device,
  HostEpoch:"host-boot-r24",GuestEpoch:"vm-start-r24",
  LeaseEpoch:lease.Epoch,Generation:lease.Generation,ReleaseSequence:1}
 topo:=Topology{VMIncarnation:"qemu-process-100/boot-12",QMPObjectID:"r26-l-kbd",
  USBIPExporter:"usbip-vudc.0",GuestInputDeviceID:"linux-vhci-hid"}
 q:=QMPWitness{VMIncarnation:topo.VMIncarnation,ObjectID:topo.QMPObjectID,
  LeaseEpoch:lease.Epoch,Generation:lease.Generation,ReleaseSequence:1,ActualAck:true}
 u:=USBIPWitness{VMIncarnation:topo.VMIncarnation,Exporter:topo.USBIPExporter,
  InputDeviceID:topo.GuestInputDeviceID,LeaseEpoch:lease.Epoch,
  Generation:lease.Generation,ReleaseSequence:1,EventSequence:11,GuestUP:true}
 p,err:=New(lease,scope,topo,
  func(w QMPWitness)bool{return w==q},
  func(w USBIPWitness)bool{return w==u})
 if err!=nil{t.Fatal(err)}
 return p,q,u
}
func TestR24CrossVMQMPCannotReleaseUSBIPExport(t *testing.T){
 p,q,u:=makePair(t)
 q.VMIncarnation="other-qemu-vm"
 if err:=p.Authorize(q,u);!errors.Is(err,ErrUnbound){t.Fatal("foreign VM QMP ACK admitted")}
 p,q,u=makePair(t)
 u.VMIncarnation="other-qemu-vm"
 if err:=p.Authorize(q,u);!errors.Is(err,ErrUnbound){t.Fatal("foreign VHCI guest release admitted")}
 p,q,u=makePair(t)
 q.ObjectID="unrelated-qmp-tablet"
 if err:=p.Authorize(q,u);!errors.Is(err,ErrUnbound){t.Fatal("unrelated QMP device admitted")}
 p,q,u=makePair(t)
 u.InputDeviceID="qmp-virtual-kbd-not-usbip"
 if err:=p.Authorize(q,u);!errors.Is(err,ErrUnbound){t.Fatal("wrong physical Linux input permitted")}
 t.Log("R24_A_CROSS_VM_AND_CROSS_DEVICE_QMP_USBIP_WITNESS_DENIED=PASS")
}
func TestR24NoStaleOrUnverifiedGuestQMPJoin(t *testing.T){
 p,q,u:=makePair(t)
 q.ActualAck=false
 if err:=p.Authorize(q,u);!errors.Is(err,ErrUnbound){t.Fatal("raw QMP request admitted")}
 p,q,u=makePair(t)
 u.GuestUP=false
 if err:=p.Authorize(q,u);!errors.Is(err,ErrUnbound){t.Fatal("USBIP transport detach admitted")}
 p,q,u=makePair(t)
 u.Generation++
 if err:=p.Authorize(q,u);!errors.Is(err,ErrUnbound){t.Fatal("generation replay admitted")}
 p,q,u=makePair(t)
 q.LeaseEpoch="stale-lease"
 if err:=p.Authorize(q,u);!errors.Is(err,ErrUnbound){t.Fatal("old lease ACK admitted")}
 p,q,u=makePair(t)
 u.Exporter="other-vudc"
 if err:=p.Authorize(q,u);!errors.Is(err,ErrUnbound){t.Fatal("different VUDC admitted")}
 p,q,u=makePair(t)
 if err:=p.Authorize(q,u);err!=nil{t.Fatal(err)}
 if err:=p.Authorize(q,u);!errors.Is(err,ErrUnbound){t.Fatal("release evidence used twice")}
 t.Log("R24_A_SAME_LEASE_QMP_AND_USBIP_WITNESS_ONCE_ONLY=PASS")
 t.Log("R24_A_ACTUAL_SOLE_QMP_TO_REAL_VUDC_SAME_RUN=NOT_TESTED")
}
func TestR24NeverUseEmptyOrCallerOnlyQMPProof(t *testing.T){
 p,q,u:=makePair(t)
 if _,err:=New(p.Lease,p.Scope,p.Topology,nil,func(USBIPWitness)bool{return true});!errors.Is(err,ErrUnbound){
  t.Fatal("no real QMP verifier dependency admitted")
 }
 if _,err:=New(p.Lease,p.Scope,p.Topology,func(QMPWitness)bool{return true},nil);!errors.Is(err,ErrUnbound){
  t.Fatal("no authenticated guest verifier dependency admitted")
 }
 _=q;_=u
 t.Log("R24_A_MISSING_INDEPENDENT_QMP_OR_GUEST_PROVER_REFUSED=PASS")
}
