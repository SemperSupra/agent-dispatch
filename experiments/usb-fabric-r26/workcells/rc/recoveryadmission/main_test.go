package main
import(
 "strings"
 "testing"
)
func sample()Gate{return Gate{Schema:1,GuestSignedUp:Evidence{Cell:"R27H20",Commit:strings.Repeat("a",40),RunID:1,JobID:2,Verified:true}}}
func ready(g Gate)bool{b,e:=assess(g);return e==nil&&len(b)==0}
func TestH20SignedGuestUpAloneNotRelease(t *testing.T){if ready(sample()){t.Fatal("signed guest UP admitted new lease")}}
func TestH7HostileQMPRedRemainsBlocker(t *testing.T){b,e:=assess(sample());if e!=nil{t.Fatal(e)};found:=false;for _,x:=range b{if x=="hostile-raw-qmp-red"{found=true}};if !found{t.Fatal("historical RED lost")}}
func TestNoTopologyNoRelease(t *testing.T){g:=all();g.TopologyAbsent=false;if ready(g){t.Fatal("topology absent not proven")}}
func TestNoExclusiveOwnerNoRelease(t *testing.T){g:=all();g.ControllerExclusive=false;if ready(g){t.Fatal("QMP ownership missing")}}
func TestNoJournalFsyncNoRelease(t *testing.T){g:=all();g.JournalFsyncedClear=false;if ready(g){t.Fatal("HELD clear without fsync")}}
func TestNoNewLeaseNoRelease(t *testing.T){g:=all();g.NewLeaseObserved=false;if ready(g){t.Fatal("readmission not proven")}}
func TestNoProductionKeyTrustNoRelease(t *testing.T){g:=all();g.ProductionGuestTrust=false;if ready(g){t.Fatal("extractable key accepted as attestation")}}
func TestNoOwnerApprovalNoRelease(t *testing.T){g:=all();g.OwnerReleaseApproval=false;if ready(g){t.Fatal("automatic release authorization")}}
func TestWrongSourceFails(t *testing.T){g:=all();g.GuestSignedUp.Commit="main";if ready(g){t.Fatal("mutable head qualified")}}
func TestMissingJobFails(t *testing.T){g:=all();g.GuestSignedUp.JobID=0;if ready(g){t.Fatal("source without job")}}
func TestNoSelfAssertedGuestUp(t *testing.T){g:=all();g.GuestSignedUp.Verified=false;if ready(g){t.Fatal("declarative guest proof")}}
func TestEpochMismatchBlocks(t *testing.T){g:=all();g.EpochReconciled=false;if ready(g){t.Fatal("stale epoch admitted")}}
func TestVMIncarnationMissingBlocks(t *testing.T){g:=all();g.SameVMOwnerVerified=false;if ready(g){t.Fatal("unknown surviving VM")}}
func TestUnknownSchemaFails(t *testing.T){g:=all();g.Schema=2;if _,e:=assess(g);e==nil{t.Fatal("unknown schema")}}
func all()Gate{g:=sample();g.SameVMOwnerVerified=true;g.NoHostileRawQMP=true;g.EpochReconciled=true;g.TopologyAbsent=true;g.ControllerExclusive=true;g.JournalFsyncedClear=true;g.NewLeaseObserved=true;g.ProductionGuestTrust=true;g.OwnerReleaseApproval=true;return g}
func TestOnlyCompleteInputCanBeOfflineCandidate(t *testing.T){if !ready(all()){t.Fatal("complete positive fixture rejected")}}
