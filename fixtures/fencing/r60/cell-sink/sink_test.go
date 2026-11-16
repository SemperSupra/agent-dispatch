package sink
import (
  "sync"
  "testing"
)
// Tests use a purely synthetic in-memory authority and effect receiver.
// A real executor must itself honor this boundary, or be isolated
// behind a verified exclusive gateway.
type Envelope struct { Scope, Owner, Key string; Epoch uint64; Cost uint64 }
type Store struct { sync.Mutex; scope,owner string; epoch uint64; budget,held uint64; online bool; effects map[string]bool }
func newStore() *Store {return &Store{scope:"budget-A",epoch:1,owner:"old",budget:1,online:true,effects:map[string]bool{}}}
func (s *Store) changeOwner(newOwner string) {s.Lock(); defer s.Unlock();s.epoch++;s.owner=newOwner}
func (s *Store) commit(e Envelope) string {
 s.Lock();defer s.Unlock()
 if !s.online {return "AUTHORITY_UNAVAILABLE"}
 if e.Scope!=s.scope||e.Owner!=s.owner||e.Epoch!=s.epoch {return "STALE_OR_WRONG_SCOPE"}
 if s.effects[e.Key] {return "IDEMPOTENT_ALREADY_ACCEPTED"}
 if s.held+e.Cost>s.budget {return "BUDGET_EXHAUSTED"}
 s.held+=e.Cost;s.effects[e.Key]=true;return "UNKNOWN_RESERVED"
}
func TestStaleOwnerDeniedAtSyntheticCommitBoundary(t *testing.T) {
 s:=newStore();old:=Envelope{"budget-A","old","a",1,1};s.changeOwner("new")
 if v:=s.commit(old);v!="STALE_OR_WRONG_SCOPE"{t.Fatal(v)}
 if v:=s.commit(Envelope{"budget-A","new","b",2,1});v!="UNKNOWN_RESERVED"{t.Fatal(v)}
}
func TestScopeSubstitutionDenied(t *testing.T) {
 s:=newStore();if v:=s.commit(Envelope{"budget-B","old","x",1,1});v!="STALE_OR_WRONG_SCOPE"{t.Fatal(v)}
}
func TestLostAckIdempotentAndUnknownHeld(t *testing.T) {
 s:=newStore();e:=Envelope{"budget-A","old","same-key",1,1}
 if v:=s.commit(e);v!="UNKNOWN_RESERVED"{t.Fatal(v)}
 if v:=s.commit(e);v!="IDEMPOTENT_ALREADY_ACCEPTED"{t.Fatal(v)}
 if v:=s.commit(Envelope{"budget-A","old","other",1,1});v!="BUDGET_EXHAUSTED"{t.Fatal(v)}
 if s.held!=1||len(s.effects)!=1 {t.Fatal("UNKNOWN lost")}
}
func TestPartitionFailsClosedAtSyntheticSink(t *testing.T) {
 s:=newStore();s.online=false
 if v:=s.commit(Envelope{"budget-A","old","x",1,1});v!="AUTHORITY_UNAVAILABLE"{t.Fatal(v)}
}
func TestNegativePreflightTOCTOU(t *testing.T) {
 s:=newStore();verified:=make(chan struct{});resume:=make(chan struct{});done:=make(chan struct{})
 old:=Envelope{"budget-A","old","x",1,1};accepted:=false
 go func(){s.Lock();seen:=s.owner==old.Owner&&s.epoch==old.Epoch;s.Unlock();close(verified);<-resume
   // Unfenced external sink trusts a stale PREPARE decision. Bad by design.
   if seen {accepted=true};close(done)
 }()
 <-verified;s.changeOwner("new");close(resume);<-done
 if !accepted {t.Fatal("EXPECTED RED stale preflight was not reproduced")}
 t.Log("EXPECTED RED: old PREPARE succeeds; new owner elected; unfenced sink accepts late effect")
}
