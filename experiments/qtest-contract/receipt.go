package experiment

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "strings"
)

type Receipt struct {
 Scope string
 SourceCommit string
 ProposalSHA256 string
 EvidenceSHA256 string
 Status string
 ExitCode *int
 Planned, Exercised, Failed, Skipped uint32
 Cleanup bool
}

func validHex(s string,n int) bool {
 if len(s)!=n || s!=strings.ToLower(s){return false}
 _,err:=hex.DecodeString(s)
 return err==nil
}
func digest(b []byte) string {v:=sha256.Sum256(b);return hex.EncodeToString(v[:])}

// VerifyReceipt checks internal consistency and byte binding only.
// It does not authenticate the producer, prove observations truthful,
// or authorize execution or release.
func VerifyReceipt(r Receipt, proposal, evidence []byte) error {
 if r.Scope!="synthetic-device-model" || !validHex(r.SourceCommit,40) {
  return errors.New("invalid scope/source")
 }
 e,err:=Decode(strings.NewReader(string(proposal)))
 if err!=nil{return err}
 if r.ProposalSHA256!=digest(proposal) || r.EvidenceSHA256!=digest(evidence){
  return errors.New("digest mismatch")
 }
 if r.Planned!=uint32(len(e.Operations)) || r.Exercised>r.Planned ||
  r.Skipped>r.Planned-r.Exercised || r.Failed>r.Exercised {
  return errors.New("inconsistent counts")
 }
 switch r.Status {
 case "PASS":
  if r.ExitCode==nil || *r.ExitCode!=0 || !r.Cleanup || len(evidence)==0 ||
    r.Exercised!=r.Planned || r.Failed!=0 || r.Skipped!=0 {
   return errors.New("incomplete or failed execution")
  }
 case "FAIL":
  if r.ExitCode==nil || *r.ExitCode==0 || len(evidence)==0 {
   return errors.New("missing failure evidence")
  }
 case "NOT_RUN":
  if r.Exercised!=0 || r.Failed!=0 || r.ExitCode!=nil {
   return errors.New("contradictory non-execution")
  }
 case "UNKNOWN":
  // No promotion of inconclusive or incomplete receipts.
 default:
  return errors.New("unknown status")
 }
 return nil
}
