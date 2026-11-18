// Package blue contains a disposable, host-local USB fabric lease and input
// executor model. It does not implement real QMP or USB transfers.
package blue

import (
 "crypto/rand"
 "encoding/hex"
 "errors"
 "io"
 "sync"

 heldledger "example.org/usb-fabric-r26-integrated/heldledger"
)

var (
 ErrDenied = errors.New("usb fabric: denied")
 ErrUnavailable = errors.New("usb fabric: unavailable")
 ErrQuarantined = errors.New("usb fabric: quarantined")
)

type State string

const (
 Available State = "available"
 Reserved State = "reserved"
 Attached State = "attached"
 Quarantined State = "quarantined"
)

type Lease struct {
 Device string
 Port string
 Actor string
 Epoch string
 Generation uint64
}

type Executor interface {
 Input(command string) error
 ReleaseAll() error
}

type Manager struct {
 mu sync.Mutex
 state State
 device, port string
 active Lease
 generation uint64
 epoch string
 executor Executor
}

// New creates one synthetic device on one logical port. No external effects.
func New(device, port string, exec Executor) *Manager {
 return newWithEntropy(device,port,exec,rand.Reader)
}

// The incarnation epoch distinguishes otherwise identical leases across
// crashes/restarts. Entropy failure quarantines instead of permitting an
// ambiguous owner epoch. This does not authenticate remote actors.
func newWithEntropy(device,port string,exec Executor,reader io.Reader)*Manager {
 m:=&Manager{state:Quarantined,device:device,port:port,executor:exec}
 if reader==nil{return m}
 var epoch [16]byte
 if _,err:=io.ReadFull(reader,epoch[:]);err!=nil{return m}
 if epoch==([16]byte{}){return m}
 m.epoch=hex.EncodeToString(epoch[:])
 m.state=Available
 return m
}

func (m *Manager) Reserve(actor, device, port string) (Lease,error) {
 m.mu.Lock()
 defer m.mu.Unlock()
 if actor=="" || device=="" || port=="" || device!=m.device || port!=m.port {
  return Lease{},ErrDenied
 }
 if m.state==Quarantined {return Lease{},ErrQuarantined}
 if m.state!=Available{return Lease{},ErrUnavailable}
 m.generation++
 m.active=Lease{Device:device,Port:port,Actor:actor,Epoch:m.epoch,Generation:m.generation}
 m.state=Reserved
 return m.active,nil
}

func (m *Manager) authorized(l Lease) bool {
 return l.Generation>0 && l==m.active && m.state!=Quarantined
}

func (m *Manager) Attach(l Lease) error {
 m.mu.Lock();defer m.mu.Unlock()
 if !m.authorized(l) || m.state!=Reserved{return ErrDenied}
 m.state=Attached
 return nil
}

// Input and Revoke serialize under one host-local lock. No successful Input
// can execute after Revoke returns for the same lease.
func (m *Manager) Input(l Lease, command string) error {
 m.mu.Lock();defer m.mu.Unlock()
 if command!="key-a-down" && command!="key-a-up" && command!="mouse-left-down" && command!="mouse-left-up" {
  return ErrDenied
 }
 if !m.authorized(l) || m.state!=Attached{return ErrDenied}
 if m.executor==nil{return ErrUnavailable}
 if err:=m.executor.Input(command);err!=nil {
  m.quarantine()
  return err
 }
 return nil
}

func (m *Manager) quarantine() {
 m.generation++
 m.state=Quarantined
 m.active=Lease{}
}

// Revoke retains exclusive ownership if forced input release cannot be
// confirmed. The device stays quarantined, never silently reassigned.
func (m *Manager) Revoke(l Lease) error {
 m.mu.Lock();defer m.mu.Unlock()
 if !m.authorized(l) {return ErrDenied}
 if m.state==Attached {
  if m.executor==nil {m.quarantine();return ErrUnavailable}
  if err:=m.executor.ReleaseAll();err!=nil {m.quarantine();return err}
 }
 m.generation++
 m.active=Lease{}
 m.state=Available
 return nil
}

// RestoreAfterVerifiedGuestUp is called ONLY by the sole host actuator's
// independent guest event reader. It serializes the actual fsynced guest-
// confirmed ledger transition and lease-state re-admission under one manager
// mutex, so a new frontend cannot reserve between those two steps.
// The passed verifier MUST bind the actual guest evdev UP to scope, QMP
// ACK and prior verified DOWN. No external frontend op exposes this method.
func (m *Manager)RestoreAfterVerifiedGuestUp(
 journal heldledger.Store,expected uint64,
 claim heldledger.ReleaseClaim,verify heldledger.ReleaseVerifier,
)error{
 m.mu.Lock();defer m.mu.Unlock()
 if m.state!=Quarantined{return ErrDenied}
 if _,err:=journal.ConfirmGuestRelease(expected,claim,verify);err!=nil{
  return err
 }
 m.generation++
 m.active=Lease{}
 m.state=Available
 return nil
}

// BeginDetach atomically fences new reservations before QMP device_del.
// The device remains Quarantined; a later independent topology witness is
// required before advertising a reusable port. No frontend can renew it.
func (m *Manager)BeginDetach()error{
 m.mu.Lock();defer m.mu.Unlock()
 if m.state!=Available{return ErrDenied}
 m.quarantine()
 return nil
}

// Offline fences the old lease. Safe physical reassignment requires a
// separate proof of host/device isolation and is NOT implemented here.
func (m *Manager) Offline() {
 m.mu.Lock();defer m.mu.Unlock()
 m.quarantine()
}

func (m *Manager) Snapshot() (State,Lease,uint64) {
 m.mu.Lock();defer m.mu.Unlock()
 return m.state,m.active,m.generation
}
