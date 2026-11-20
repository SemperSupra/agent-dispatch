package main
import(
 "encoding/json"
 "strings"
 "testing"
)
func sample(t *testing.T)Manifest{
 t.Helper()
 // The fixture reproduces the pinned manifest not a mutable branch.
 const raw=`{"schema":1,"repo":"SemperSupra/agent-dispatch","release_ready":false,"owner_merge_approved":false,"integrated_single_head":"","security_red":["H7-same-service-uid-raw-qmp","H24-inherited-qmp-fd-primitive"],"nodes":[{"id":"H20","pr":925,"head":"53ca3a5e74c5b23a00420f11db438be61aacd24b","role":"carry","parent":"","scope":"synthetic signed postcrash HELD and evdev UP; journal remains HELD"},{"id":"H21","pr":929,"head":"e0c0f6423d3f1d06f1a3c0f24b395b75b1b7fdbe","role":"carry","parent":"H20","scope":"cooperative kernel peer and abstract owner fence; not hostile same-UID guard"},{"id":"H22","pr":934,"head":"68990e43e4f01cbf849a9a983d99b0da4b339e6c","role":"carry","parent":"H21","scope":"signed guest UP followed by QOM device disappearance"},{"id":"H23","pr":937,"head":"40123405310b4d48c964a911c22670346c34d3e3","role":"carry","parent":"H22","scope":"exact DEVICE_DELETED event and QOM absent with HELD retained"},{"id":"E12","pr":930,"head":"308b482c4bfd230616a449f348d0a24dde1cbb8f","role":"critic","parent":"","scope":"offline nine known release blockers"},{"id":"E13","pr":935,"head":"1281bddb9255c99c8e55e5c6693f3a49391dc94f","role":"critic","parent":"E12","scope":"six live source PR run job log proofs, admission still blocked"}],"blockers":["hostile-raw-qmp","trusted-VM-epochs","exclusive-QMP-controller","fsynced-journal-release","safe-next-lease","production-guest-attestation","owner-release-approval"]}`
 var m Manifest;if e:=json.Unmarshal([]byte(raw),&m);e!=nil{t.Fatal(e)};return m
}
func TestCurrentInventoryIsBlocked(t *testing.T){if e:=check(sample(t));e!=nil{t.Fatal(e)}}
func TestNoSelfDeclaredRelease(t *testing.T){m:=sample(t);m.ReleaseReady=true;if check(m)==nil{t.Fatal("release claimed")}}
func TestNoOwnerApprovalWithoutEvidence(t *testing.T){m:=sample(t);m.OwnerMergeApproved=true;if check(m)==nil{t.Fatal("owner approval claimed")}}
func TestNoSyntheticIntegratedSHA(t *testing.T){m:=sample(t);m.IntegratedSingleHead=strings.Repeat("f",40);if check(m)==nil{t.Fatal("no integrated head exists")}}
func TestRedCannotDisappear(t *testing.T){m:=sample(t);m.SecurityRed=nil;if check(m)==nil{t.Fatal("RED erased")}}
func TestMissingParentRejected(t *testing.T){m:=sample(t);m.Nodes[3].Parent="not-found";if check(m)==nil{t.Fatal("missing ancestor")}}
func TestCycleRejected(t *testing.T){m:=sample(t);m.Nodes[0].Parent="H23";if check(m)==nil{t.Fatal("cycle")}}
func TestMutableHeadRejected(t *testing.T){m:=sample(t);m.Nodes[3].Head="main";if check(m)==nil{t.Fatal("mutable source accepted")}}
func TestDuplicateSourceRejected(t *testing.T){m:=sample(t);m.Nodes[3].Head=m.Nodes[2].Head;if check(m)==nil{t.Fatal("duplicate source accepted")}}
func TestDuplicatePRRejected(t *testing.T){m:=sample(t);m.Nodes[3].PR=m.Nodes[2].PR;if check(m)==nil{t.Fatal("duplicate PR accepted")}}
func TestCrossRoleParentRejected(t *testing.T){m:=sample(t);m.Nodes[5].Parent="H23";if check(m)==nil{t.Fatal("critic attached to feature as ancestry")}}
func TestNoRawQMPBlockerRemoval(t *testing.T){m:=sample(t);m.Blockers=[]string{"fsynced-journal-release","safe-next-lease","owner-release-approval","other","another"};if check(m)==nil{t.Fatal("H7 red admission omitted")}}
func TestNoUnknownDisposition(t *testing.T){m:=sample(t);m.Nodes[0].Role="merge-now";if check(m)==nil{t.Fatal("automatic merge policy")}}
