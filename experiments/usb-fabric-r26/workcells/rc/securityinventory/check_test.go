package main
import(
 "encoding/json"
 "strings"
 "testing"
)
const fixture=`{"schema":1,"release_admission":"BLOCKED","evidence":[{"cell":"H7","pr":858,"commit":"eceb8405f5c9f35ba215f38bfc39417810abf11b","result":"RED","surface":"actual QEMU same-service-UID raw-QMP device add/delete"},{"cell":"H24","pr":939,"commit":"c35988b83e4aff0e62ff693bd05a49bb66080752","result":"RED","surface":"inherited connected Linux Unix FD can still transmit after pathname unlink"},{"cell":"H26","pr":943,"commit":"beedb0877f3619729576980c387c7c2f6c2036d1","result":"PASS_LIMITED","surface":"synthetic private QMP path denied across UID and no ordinary exec inherited FD"},{"cell":"H27","pr":945,"commit":"a5c26d1ea06cc6877712fb21bd02168b4f9af806","result":"NOT_TESTED","surface":"real QEMU private QMP path across UID under public CI"}],"known_gates":{"same_uid_attacker_mitigated":false,"inherited_existing_fd_revoked":false,"production_exclusive_qmp_controller":false,"epoch_lineage_verified":false,"fsynced_release_committed":false,"safe_next_lease":false,"owner_approved":false}}`
func current(t *testing.T)Manifest{t.Helper();var m Manifest;if err:=json.Unmarshal([]byte(fixture),&m);err!=nil{t.Fatal(err)};return m}
func TestCurrentThreatInventoryRemainsBlocked(t *testing.T){if e:=validate(current(t));e!=nil{t.Fatal(e)}}
func TestCannotRewriteH7RedAsPass(t *testing.T){m:=current(t);m.Evidence[0].Result="PASS_LIMITED";if validate(m)==nil{t.Fatal("rewrote actual QEMU RED")}}
func TestCannotRewriteH24FDRed(t *testing.T){m:=current(t);m.Evidence[1].Result="PASS_LIMITED";if validate(m)==nil{t.Fatal("rewrote inherited FD RED")}}
func TestCannotPromoteH26ToProduction(t *testing.T){m:=current(t);m.Evidence[2].Result="PASS";if validate(m)==nil{t.Fatal("synthetic test promoted")}}
func TestCannotSelfCertifyPendingH27(t *testing.T){m:=current(t);m.Evidence[3].Result="PASS";if validate(m)==nil{t.Fatal("narrow real QEMU UID proof promoted to release-grade protection")}}
func TestNoUnsignedSourceHead(t *testing.T){m:=current(t);m.Evidence[0].Commit="main";if validate(m)==nil{t.Fatal("mutable SHA")}}
func TestNoDuplicateHistory(t *testing.T){m:=current(t);m.Evidence[1].Cell="H7";if validate(m)==nil{t.Fatal("duplicate RED erased actual history")}}
func TestNoReleaseClaim(t *testing.T){m:=current(t);m.ReleaseAdmission="PASS";if validate(m)==nil{t.Fatal("release without controller")}}
func TestNoOwnerApproval(t *testing.T){m:=current(t);m.Gates.OwnerApproval=true;if validate(m)==nil{t.Fatal("fake approval")}}
func TestNoUnsafeQMPClosure(t *testing.T){m:=current(t);m.Gates.SameUID=true;if validate(m)==nil{t.Fatal("H7 still RED")}}
func TestNoFsyncPretense(t *testing.T){m:=current(t);m.Gates.FsyncedRelease=true;if validate(m)==nil{t.Fatal("journal release not demonstrated")}}
func TestNoSafeLeasePretense(t *testing.T){m:=current(t);m.Gates.NextLease=true;if validate(m)==nil{t.Fatal("next lease not qualified")}}
func TestExactSHAFormats(t *testing.T){m:=current(t);m.Evidence[2].Commit=strings.Repeat("z",40);if validate(m)==nil{t.Fatal("non hex ref")}}
