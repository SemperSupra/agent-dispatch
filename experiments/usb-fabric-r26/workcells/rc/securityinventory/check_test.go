package main
import(
 _ "embed"
 "encoding/json"
 "strings"
 "testing"
)
//go:embed current.json
var fixture string
func current(t *testing.T)Manifest{t.Helper();var m Manifest;if err:=json.Unmarshal([]byte(fixture),&m);err!=nil{t.Fatal(err)};return m}
func TestCurrentThreatInventoryRemainsBlocked(t *testing.T){if e:=validate(current(t));e!=nil{t.Fatal(e)}}
func TestCannotRewriteH7RedAsPass(t *testing.T){m:=current(t);m.Evidence[0].Result="PASS_LIMITED";if validate(m)==nil{t.Fatal("rewrote actual QEMU RED")}}
func TestCannotRewriteH24FDRed(t *testing.T){m:=current(t);m.Evidence[1].Result="PASS_LIMITED";if validate(m)==nil{t.Fatal("rewrote inherited FD RED")}}
func TestCannotPromoteH26ToProduction(t *testing.T){m:=current(t);m.Evidence[2].Result="PASS";if validate(m)==nil{t.Fatal("synthetic test promoted")}}
func TestCannotPromoteNarrowH27ToRelease(t *testing.T){m:=current(t);m.Evidence[3].Result="PASS";if validate(m)==nil{t.Fatal("narrow real QEMU UID proof promoted to release-grade protection")}}
func TestNoUnsignedSourceHead(t *testing.T){m:=current(t);m.Evidence[0].Commit="main";if validate(m)==nil{t.Fatal("mutable SHA")}}
func TestNoDuplicateHistory(t *testing.T){m:=current(t);m.Evidence[1].Cell="H7";if validate(m)==nil{t.Fatal("duplicate RED erased actual history")}}
func TestNoReleaseClaim(t *testing.T){m:=current(t);m.ReleaseAdmission="PASS";if validate(m)==nil{t.Fatal("release without controller")}}
func TestNoOwnerApproval(t *testing.T){m:=current(t);m.Gates.OwnerApproval=true;if validate(m)==nil{t.Fatal("fake approval")}}
func TestNoUnsafeQMPClosure(t *testing.T){m:=current(t);m.Gates.SameUID=true;if validate(m)==nil{t.Fatal("H7 still RED")}}
func TestNoFsyncPretense(t *testing.T){m:=current(t);m.Gates.FsyncedRelease=true;if validate(m)==nil{t.Fatal("journal release not demonstrated")}}
func TestNoSafeLeasePretense(t *testing.T){m:=current(t);m.Gates.NextLease=true;if validate(m)==nil{t.Fatal("next lease not qualified")}}
func TestExactSHAFormats(t *testing.T){m:=current(t);m.Evidence[2].Commit=strings.Repeat("z",40);if validate(m)==nil{t.Fatal("non hex ref")}}
