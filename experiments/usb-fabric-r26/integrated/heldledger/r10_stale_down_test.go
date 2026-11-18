package heldledger

import (
 "bytes"
 "errors"
 "os"
 "path/filepath"
 "testing"
)

// A new signed release must NOT recycle a down-event from an earlier lease.
// This is a direct test of the existing journal implementation, not a new broker.
func TestR10StaleDownAcrossReAdmittedLeaseNeverClearsHeld(t *testing.T) {
 store:=Store{Path:filepath.Join(t.TempDir(),"held.json")}
 initial,err:=store.Transition(0,true)
 if err!=nil||initial.Sequence!=1 {t.Fatalf("initial held: %+v %v",initial,err)}
 stage(t,store,1)
 first,err:=store.ConfirmGuestRelease(1,claim(1,10,11),signed)
 if err!=nil||first.Held||first.LastReleaseEventSequence!=11 {t.Fatalf("first verified release: %+v %v",first,err)}
 second,err:=store.Transition(first.Sequence,true)
 if err!=nil||second.Sequence!=3||!second.Held{t.Fatalf("second lease key down: %+v %v",second,err)}
 stage(t,store,3)
 before,err:=os.ReadFile(store.Path)
 if err!=nil{t.Fatal(err)}
 // Valid TEST-ONLY signed MAC; up event 14 is new, but down 10 is from
 // the previous lease. This cannot justify releasing the current held key.
 stale:=claim(3,10,14)
 if !signed(stale){t.Fatal("fixture must be independently valid MAC")}
 if _,err=store.ConfirmGuestRelease(3,stale,signed);!errors.Is(err,ErrUnverified){
  t.Fatalf("R10_RED_STALE_DOWN_WAS_ADMITTED=%v",err)
 }
 after,err:=os.ReadFile(store.Path)
 if err!=nil||!bytes.Equal(before,after){
  t.Fatalf("R10_RED_DENIAL_CHANGED_DURABLE_HELD_JOURNAL err=%v",err)
 }
 retained,err:=store.Read()
 if err!=nil||!retained.Held||retained.ReleasePhase!="qmp-acked"||retained.Sequence!=3{
  t.Fatalf("R10_RED_HELD_RELEASE_STATE_CHANGED %+v %v",retained,err)
 }
 t.Log("R10_SIGNED_STALE_KEYDOWN_REPLAY_DENIED=PASS")
 // Positive control: the next real key down must be newer than prior up.
 fresh:=claim(3,12,14)
 clean,err:=store.ConfirmGuestRelease(3,fresh,signed)
 if err!=nil||clean.Held||clean.LastReleaseEventSequence!=14{
  t.Fatalf("R10_FRESH_DOWN_UP_PROOF_SHOULD_RELEASE %+v %v",clean,err)
 }
 t.Log("R10_NEW_GUEST_KEYDOWN_AFTER_HIGH_WATER_ACCEPTED=PASS")
}
