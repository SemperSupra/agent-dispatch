package composition

import (
 "errors"
 "fmt"
 "sync"

 "example.org/usb-fabric-r26-integrated/blue"
 "example.org/usb-fabric-r26-integrated/heldledger"
)

// Test-only composition adaptor; does not duplicate the existing Go manager.
// ONLY this coordinator may publish its private manager to a frontend.
// A raw USBIP client can bypass it unless the kernel ConfigFS UDC is
// independently held unbound; real kernel acceptance remains NOT_TESTED.
var ErrIsolationUnknown=errors.New("usb fabric: export isolation cannot be established")
var ErrProofRequired=errors.New("usb fabric: verified guest release required before UDC bind")

type ExportGate interface {
 Unbind()error
 Bind()error
 Bound()(bool,error)
}
type Interlock struct {
 mu sync.Mutex
 m *blue.Manager
 store heldledger.Store
 udc ExportGate
 ready bool
}

// NewFenced constructs a fresh existing Go manager in an unpublished scope,
// fences it BEFORE probing the disk or touching the UDC, then withdraws the
// export. Clean/missing journal alone never permits B re-admission.
func NewFenced(store heldledger.Store,udc ExportGate,device,port string)(*Interlock,error) {
 if udc==nil{return nil,ErrIsolationUnknown}
 m:=blue.New(device,port,nil)
 m.Offline()
 c:=&Interlock{m:m,store:store,udc:udc}
 if err:=udc.Unbind();err!=nil{return c,fmt.Errorf("%w: withdraw UDC: %v",ErrIsolationUnknown,err)}
 bound,err:=udc.Bound()
 if err!=nil||bound{return c,ErrIsolationUnknown}
 if _,err=store.Read();err!=nil{return c,err}
 return c,nil
}

// Reserve is the only frontend-visible admission path. The callback and
// exporter are serialized under one lock; no new B can slip between
// durable release and actual UDC bind acceptance.
func(c *Interlock)Reserve(actor,device,port string)(blue.Lease,error){
 if c==nil{return blue.Lease{},ErrIsolationUnknown}
 c.mu.Lock();defer c.mu.Unlock()
 if !c.ready{return blue.Lease{},ErrProofRequired}
 bound,err:=c.udc.Bound()
 if err!=nil||!bound{c.ready=false;c.m.Offline();return blue.Lease{},ErrIsolationUnknown}
 return c.m.Reserve(actor,device,port)
}

// ReleaseAndBind admits export ONLY after existing heldledger guest-proof
// confirmation has fsynced. The private blue.Manager is not visible to
// clients until physical export bind has both succeeded and been observed.
func(c *Interlock)ReleaseAndBind(sequence uint64,claim heldledger.ReleaseClaim,verify heldledger.ReleaseVerifier)error {
 if c==nil{return ErrIsolationUnknown}
 c.mu.Lock();defer c.mu.Unlock()
 if c.ready{return ErrProofRequired}
 if err:=c.m.RestoreAfterVerifiedGuestUp(c.store,sequence,claim,verify);err!=nil{return err}
 if err:=c.udc.Bind();err!=nil{
  c.m.Offline()
  c.ready=false
  // Even a partially successful bind must be withdrawn. If withdrawing
  // cannot be independently observed, refuse to claim isolation.
  if e:=c.udc.Unbind();e!=nil{return ErrIsolationUnknown}
  still,e:=c.udc.Bound()
  if e!=nil||still{return ErrIsolationUnknown}
  return fmt.Errorf("UDC bind rejected and withdrawn: %w",err)
 }
 bound,err:=c.udc.Bound()
 if err!=nil||!bound{
  c.m.Offline();c.ready=false
  if e:=c.udc.Unbind();e!=nil{return ErrIsolationUnknown}
  still,e:=c.udc.Bound()
  if e!=nil||still{return ErrIsolationUnknown}
  return ErrIsolationUnknown
 }
 c.ready=true
 return nil
}
