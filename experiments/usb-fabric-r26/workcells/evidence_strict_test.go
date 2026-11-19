package main
import ("strings";"testing")
func TestRejectNonhex40CharacterHead(t *testing.T) {
 c,e:=passingEvidence()
 e.HeadSHA=strings.Repeat("z",40)
 if ok,_:=evidenceReady(c,e);ok{t.Fatal("40-char non-SHA admitted")}
}
func TestRejectOtherCellAssertion(t *testing.T) {
 c,e:=passingEvidence()
 e.Marker="R27H6_DISTINCT_UID_RAW_REAL_QMP_DENIED=PASS"
 if ok,_:=evidenceReady(c,e);ok{t.Fatal("foreign workcell assertion admitted")}
}
func TestRejectMultilineForgedAssertion(t *testing.T) {
 c,e:=passingEvidence()
 e.Marker="R27H5_ASSERTION=PASS\nR27H5_REAL_FAIL=RED"
 if ok,_:=evidenceReady(c,e);ok{t.Fatal("multiline marker admitted")}
}
func TestRejectRedDisguisedAsPass(t *testing.T) {
 c,e:=passingEvidence()
 e.Marker="R27H5_RED_RAW_BYPASS=PASS"
 if ok,_:=evidenceReady(c,e);ok{t.Fatal("red marker promoted")}
}
func TestRejectNotTestedDisguisedAsPass(t *testing.T) {
 c,e:=passingEvidence()
 e.Marker="R27H5_NOT_TESTED=PASS"
 if ok,_:=evidenceReady(c,e);ok{t.Fatal("skipped marker promoted")}
}
func TestAcceptUppercaseGitHexSHA(t *testing.T) {
 c,e:=passingEvidence()
 e.HeadSHA=strings.Repeat("ABCDEF12",5)
 if ok,err:=evidenceReady(c,e);!ok||err!=nil{t.Fatal(err)}
}
