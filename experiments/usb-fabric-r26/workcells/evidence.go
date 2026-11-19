package main
import ("errors";"fmt";"strings";"regexp")

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
var gitHexSHA=regexp.MustCompile(`^[a-fA-F0-9]{40}package main
import ("errors";"fmt";"strings";"regexp")

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
)
var assertionToken=regexp.MustCompile(`^[A-Z][A-Z0-9_]*=PASSpackage main
import ("errors";"fmt";"strings";"regexp")

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
)
func evidenceReady(cell Cell,e EvidenceRecord)(bool,error){
 if cell.ID==""||e.CellID!=cell.ID{return false,errors.New("cell identity mismatch")}
 if !gitHexSHA.MatchString(e.HeadSHA)||e.JobID<=0||!e.SourceVerified{return false,errors.New("missing immutable evidence identity")}
 if e.CIConclusion!="success"{return false,errors.New("CI not successful")}
 // A successful workflow is NOT a security PASS when its test was skipped
 // or deliberately reproduced a RED finding.
 if e.Verdict!="PASS"{return false,fmt.Errorf("evidence disposition %q is not PASS",e.Verdict)}
 if !assertionToken.MatchString(e.Marker)||strings.Contains(e.Marker,"NOT_TESTED")||strings.Contains(e.Marker,"RED_") {
  return false,errors.New("explicit PASS assertion marker absent")
 }
 expectedCellPrefix:=strings.ReplaceAll(strings.ToUpper(cell.ID),"-","")
 if !strings.HasPrefix(e.Marker,expectedCellPrefix+"_") {
  return false,errors.New("assertion belongs to a different workcell")
 }
 return true,nil
}
