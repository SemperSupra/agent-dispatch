package main
import("strings";"testing")
func passingEvidence() (Cell,EvidenceRecord) {
 c:=Cell{ID:"R27-H5",Priority:"P0",Lane:"qmp",Base:strings.Repeat("a",40),Writes:[]string{"qmp.go"},Acceptance:"real QMP"}
 e:=EvidenceRecord{CellID:c.ID,HeadSHA:strings.Repeat("b",40),JobID:135371278239,CIConclusion:"success",Verdict:"PASS",Marker:"R27H5_DISTINCT_UID_RAW_REAL_QMP_DENIED=PASS",SourceVerified:true}
 return c,e
}
func TestEvidenceValidPass(t *testing.T){c,e:=passingEvidence();ok,err:=evidenceReady(c,e);if err!=nil||!ok{t.Fatal(ok,err)}}
func TestEvidenceGreenButNotTestedDenied(t *testing.T){c,e:=passingEvidence();e.Verdict="NOT_TESTED";if ok,_:=evidenceReady(c,e);ok{t.Fatal("green workflow incorrectly qualified skipped security")}}
func TestEvidenceGreenButRedDenied(t *testing.T){c,e:=passingEvidence();e.Verdict="RED";if ok,_:=evidenceReady(c,e);ok{t.Fatal("expected security bypass promoted")}}
func TestEvidenceMissingJobOrHeadDenied(t *testing.T){c,e:=passingEvidence();e.JobID=0;if ok,_:=evidenceReady(c,e);ok{t.Fatal("missing job promoted")};_,e=passingEvidence();e.HeadSHA="mutable-main";if ok,_:=evidenceReady(c,e);ok{t.Fatal("mutable ref promoted")}}
func TestEvidenceUnverifiedSourceDenied(t *testing.T){c,e:=passingEvidence();e.SourceVerified=false;if ok,_:=evidenceReady(c,e);ok{t.Fatal("unverified source promoted")}}
func TestEvidenceUnsuccessfulCIDenied(t *testing.T){c,e:=passingEvidence();e.CIConclusion="cancelled";if ok,_:=evidenceReady(c,e);ok{t.Fatal("cancelled CI promoted")}}
func TestEvidenceWrongCellDenied(t *testing.T){c,e:=passingEvidence();e.CellID="R27-H6";if ok,_:=evidenceReady(c,e);ok{t.Fatal("other workcell proof reused")}}
func TestEvidenceMissingAssertionDenied(t *testing.T){c,e:=passingEvidence();e.Marker="R27H5_NOT_TESTED";if ok,_:=evidenceReady(c,e);ok{t.Fatal("non-PASS assertion promoted")}}
