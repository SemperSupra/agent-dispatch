package main
import ("errors";"fmt";"strings")

// EvidenceRecord is an actor-produced claim, never a substitute for fetching
// actual immutable GitHub run/job records during final DLE reconciliation.
type EvidenceRecord struct {
 CellID string `json:"cell_id"`
 HeadSHA string `json:"head_sha"`
 JobID int64 `json:"job_id"`
 CIConclusion string `json:"ci_conclusion"`
 Verdict string `json:"verdict"`
 Marker string `json:"marker"`
 SourceVerified bool `json:"source_verified"`
}
func evidenceReady(cell Cell,e EvidenceRecord)(bool,error){
 if cell.ID==""||e.CellID!=cell.ID{return false,errors.New("cell identity mismatch")}
 if len(e.HeadSHA)!=40||e.JobID<=0||!e.SourceVerified{return false,errors.New("missing immutable evidence identity")}
 if e.CIConclusion!="success"{return false,errors.New("CI not successful")}
 // A successful workflow is NOT a security PASS when its test was skipped
 // or deliberately reproduced a RED finding.
 if e.Verdict!="PASS"{return false,fmt.Errorf("evidence disposition %q is not PASS",e.Verdict)}
 if e.Marker==""||!strings.HasSuffix(e.Marker,"=PASS") {
  return false,errors.New("explicit PASS assertion marker absent")
 }
 return true,nil
}
