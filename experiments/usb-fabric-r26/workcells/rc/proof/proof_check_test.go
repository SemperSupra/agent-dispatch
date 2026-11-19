package main
import("strings";"testing")
func ledger()Ledger{return Ledger{Schema:1,Proofs:[]Proof{
 {Cell:"R27H9",SourceSHA:strings.Repeat("a",40),RunID:1,JobID:2,Conclusion:"success",Disposition:"PASS",Assertion:"R27H9_SIGNED_TWO_LEASES=PASS",Boundary:"synthetic",IndependentlyVerified:true},
 {Cell:"R27H7",SourceSHA:strings.Repeat("b",40),RunID:3,JobID:4,Conclusion:"success",Disposition:"RED",Assertion:"R27H7_SAME_UID_BYPASS=REPRODUCED",Boundary:"synthetic",IndependentlyVerified:true},
}}}
func TestLedgerPositiveIncludesRed(t *testing.T){if e:=check(ledger());e!=nil{t.Fatal(e)}}
func TestCannotClaimReleaseReady(t *testing.T){m:=ledger();m.ReleaseReady=true;if check(m)==nil{t.Fatal("proof log promoted release")}}
func TestRejectMutableHead(t *testing.T){m:=ledger();m.Proofs[0].SourceSHA="main";if check(m)==nil{t.Fatal("mutable source")}}
func TestRejectUnverifiedSource(t *testing.T){m:=ledger();m.Proofs[0].IndependentlyVerified=false;if check(m)==nil{t.Fatal("unchecked source")}}
func TestRejectRedAsPass(t *testing.T){m:=ledger();m.Proofs[1].Disposition="PASS";if check(m)==nil{t.Fatal("hostile bypass mislabeled green")}}
func TestRejectUnknownDisposition(t *testing.T){m:=ledger();m.Proofs[0].Disposition="NOT_TESTED";if check(m)==nil{t.Fatal("untested accepted as proof")}}
func TestRejectMissingJob(t *testing.T){m:=ledger();m.Proofs[0].JobID=0;if check(m)==nil{t.Fatal("missing job")}}
func TestRejectForgedCrossCell(t *testing.T){m:=ledger();m.Proofs[0].Assertion="R27H8_SIGNED_TWO_LEASES=PASS";if check(m)==nil{t.Fatal("cross-cell proof")}}
func TestRejectMultilineAssertion(t *testing.T){m:=ledger();m.Proofs[0].Assertion+="\nNOT_TESTED";if check(m)==nil{t.Fatal("injected multiline")}}
func TestRejectMissingBoundary(t *testing.T){m:=ledger();m.Proofs[0].Boundary="";if check(m)==nil{t.Fatal("unscoped claim")}}
func TestRejectDuplicateEvidence(t *testing.T){m:=ledger();m.Proofs[1].Cell="R27H9";if check(m)==nil{t.Fatal("duplicate evidence")}}
func TestRejectRedWithoutActualReproduction(t *testing.T){m:=ledger();m.Proofs[1].Assertion="R27H7_BYPASS=PASS";if check(m)==nil{t.Fatal("RED without witness")}}
