package main
import ("testing";"strings")
func mitigated()RC {
 m:=baseRC()
 m.Candidates[1].MitigatedBy="H9"
 return m
}
func TestMitigatedRedCanBePreservedWithoutPermanentDeadlock(t *testing.T){
 m:=mitigated();ready,err:=assess(m)
 if err!=nil||!ready{t.Fatalf("mitigated historical RED blocked indefinitely: %v %v",ready,err)}
}
func TestUnmitigatedRedStillBlocks(t *testing.T){m:=baseRC();ready,err:=assess(m);if err!=nil||ready{t.Fatal(ready,err)}}
func TestREDMitigationMustPointToQualifiedCarry(t *testing.T){
 m:=mitigated();m.Candidates[0].Gate="NOT_TESTED"
 if _,err:=assess(m);err==nil{t.Fatal("unqualified mitigation accepted")}
}
func TestREDMitigationNotSelfReference(t *testing.T){
 m:=mitigated();m.Candidates[1].MitigatedBy="H7"
 if _,err:=assess(m);err==nil{t.Fatal("RED self-reference admitted")}
}
func TestREDMitigationCannotReferenceMissingSource(t *testing.T){
 m:=mitigated();m.Candidates[1].MitigatedBy="missing"
 if _,err:=assess(m);err==nil{t.Fatal("unknown mitigation admitted")}
}
func TestMitigationSourceImmutable(t *testing.T){
 m:=mitigated();m.Candidates[0].Head="mutable-main"
 if _,err:=assess(m);err==nil{t.Fatal("mutable mitigation source admitted")}
}
func TestDeferredBlockersStillBlockMitigatedRed(t *testing.T){
 m:=mitigated();m.Blockers=[]string{"reconciliation NOT_TESTED"}
 ready,err:=assess(m);if err!=nil||ready{t.Fatal(ready,err)}
}
func TestMitigationCannotRewriteHistoricalRED(t *testing.T){
 m:=mitigated();m.Candidates[1].Gate="PASS"
 if _,err:=assess(m);err==nil{t.Fatal("RED history erased")}
}
func TestNoDuplicateSHAAdoptionProof(t *testing.T){
 m:=mitigated()
 m.Candidates[0].Head=strings.Repeat("b",40)
 ready,err:=assess(m);if err!=nil||!ready{t.Fatal(ready,err)}
}
