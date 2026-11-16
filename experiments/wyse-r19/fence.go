// Synthetic single-Linux-host USB HID execution fence. This is deliberately
// NOT a cross-host lock, production lease issuer, real QMP operation or
// persistent crash-safe service. All effects in this package are mock events.
package fence

import (
 "errors"
 "fmt"
 "sync"
 "time"
)
var ErrUnavailable=errors.New("epoch authority unavailable")
var ErrDenied=errors.New("capability request denied")
type Store struct {
 mu sync.Mutex
 epoch uint64
 available bool
}
func NewStore()*Store{return &Store{epoch:0,available:true}}
func (s *Store) setAvailable(ok bool){s.mu.Lock();defer s.mu.Unlock();s.available=ok}
func (s *Store) read()(uint64,error){
 s.mu.Lock();defer s.mu.Unlock()
 if !s.available{return 0,ErrUnavailable}
 return s.epoch,nil
}
func (s *Store) advance()(uint64,error){
 s.mu.Lock();defer s.mu.Unlock()
 if !s.available{return 0,ErrUnavailable}
 s.epoch++
 return s.epoch,nil
}
type Lease struct {
 ID,Actor,Guest,Mission string
 Epoch uint64
 Expires time.Time
}
type Request struct {
 Lease Lease
 Actor,Guest,Mission string
 Capability,Idempotency string
 At time.Time
}
type Event struct {
 Kind string
 RequestID string
 Epoch uint64
}
type Gate struct {
 mu sync.Mutex
 store *Store
 epoch uint64
 lease Lease
 issued bool
 used map[string]bool
 events []Event
 counter uint64
 unsafe bool
}
func NewGate(store *Store)(*Gate,error){
 if store==nil{return nil,ErrUnavailable}
 epoch,e:=store.advance()
 if e!=nil{return nil,e}
 return &Gate{store:store,epoch:epoch,used:make(map[string]bool)},nil
}
func (g *Gate) aliveLocked()error{
 if g.unsafe{return ErrUnavailable}
 epoch,e:=g.store.read()
 if e!=nil||epoch!=g.epoch{
  g.unsafe=true
  return ErrUnavailable
 }
 return nil
}
func (g *Gate) Claim(actor,guest,mission string,expires time.Time)(Lease,error){
 g.mu.Lock();defer g.mu.Unlock()
 if e:=g.aliveLocked();e!=nil{return Lease{},e}
 if g.issued||actor==""||guest==""||mission==""||!expires.After(time.Now()){
  return Lease{},ErrDenied
 }
 g.counter++
 lease:=Lease{ID:fmt.Sprintf("fixture-%d-%d",g.epoch,g.counter),
  Actor:actor,Guest:guest,Mission:mission,Epoch:g.epoch,Expires:expires}
 g.lease=lease;g.issued=true
 return lease,nil
}
func (g *Gate) Do(r Request,emit func()error)error{
 g.mu.Lock()
 defer g.mu.Unlock()
 if e:=g.aliveLocked();e!=nil{return e}
 if !g.issued||!time.Now().Before(g.lease.Expires)||r.Lease.ID!=g.lease.ID||r.Lease.Epoch!=g.epoch||
  r.Actor!=g.lease.Actor||r.Guest!=g.lease.Guest||r.Mission!=g.lease.Mission||
  r.Lease.Actor!=g.lease.Actor||r.Lease.Guest!=g.lease.Guest||r.Lease.Mission!=g.lease.Mission||
  r.Idempotency==""||r.At.IsZero()||!r.At.Before(g.lease.Expires)||
  r.At.After(time.Now().Add(5*time.Second))||
  (r.Capability!="hid.key_a" && r.Capability!="hid.button_left")||
  g.used[r.Idempotency]{
   return ErrDenied
 }
 // A mock effect is serialized inside the SAME owner mutex as revocation.
 // In production this must be a host-owned actual QMP/USB operation, or it
 // still has a check/use race.
 if e:=emit();e!=nil{
  g.unsafe=true
  return ErrUnavailable // ambiguous effect => quarantine this owner
 }
 g.used[r.Idempotency]=true
 g.events=append(g.events,Event{Kind:"EXEC",RequestID:r.Idempotency,Epoch:g.epoch})
 return nil
}
func (g *Gate) Revoke()error{
 g.mu.Lock();defer g.mu.Unlock()
 if e:=g.aliveLocked();e!=nil{return e}
 next,e:=g.store.advance()
 if e!=nil{g.unsafe=true;return e}
 g.issued=false;g.lease=Lease{}
 g.epoch=next
 g.used=make(map[string]bool)
 g.events=append(g.events,Event{Kind:"REVOKE",Epoch:g.epoch})
 return nil
}
func (g *Gate) Snapshot()[]Event{
 g.mu.Lock();defer g.mu.Unlock()
 return append([]Event(nil),g.events...)
}
