package main
import("encoding/json";"errors";"fmt";"os";"regexp";"strings")
type Proof struct{
 Cell string `json:"cell"`
 SourceSHA string `json:"source_sha"`
 RunID int64 `json:"run_id"`
 JobID int64 `json:"job_id"`
 Conclusion string `json:"conclusion"`
 Disposition string `json:"disposition"`
 Assertion string `json:"assertion"`
 Boundary string `json:"boundary"`
 IndependentlyVerified bool `json:"independently_verified"`
}
type Ledger struct{
 Schema int `json:"schema"`
 Proofs []Proof `json:"proofs"`
 ReleaseReady bool `json:"release_ready"`
}
var sha=regexp.MustCompile(`^[0-9a-f]{40}$`)
var statement=regexp.MustCompile(`^[A-Z][A-Z0-9_]*=(PASS|REPRODUCED)$`)
var redLabel=regexp.MustCompile(`(^|_)RED(_|=|$)`)
func check(m Ledger)error{
 if m.Schema!=1||len(m.Proofs)<2{return errors.New("missing immutable proof inventory")}
 if m.ReleaseReady{return errors.New("proof catalog is not release authority")}
 ids:=map[string]bool{}
 for _,p:=range m.Proofs{
  if p.Cell==""||ids[p.Cell]||!sha.MatchString(p.SourceSHA)||p.RunID<=0||p.JobID<=0{
   return fmt.Errorf("missing, mutable or duplicate proof identity %s",p.Cell)
  }
  ids[p.Cell]=true
  if !p.IndependentlyVerified||p.Conclusion!="success"||p.Boundary==""||!statement.MatchString(p.Assertion){
   return fmt.Errorf("unverified or incomplete evidence for %s",p.Cell)
  }
  if !strings.HasPrefix(p.Assertion,strings.ReplaceAll(strings.ToUpper(p.Cell),"-","")+"_"){
   return fmt.Errorf("foreign proof assertion for %s",p.Cell)
  }
  if p.Disposition!="PASS"&&p.Disposition!="RED" {return fmt.Errorf("invalid disposition for %s",p.Cell)}
  if p.Disposition=="PASS"&&(!strings.HasSuffix(p.Assertion,"=PASS")||redLabel.MatchString(p.Assertion)){
   return fmt.Errorf("positive proof forged for %s",p.Cell)
  }
  if p.Disposition=="RED"&& !strings.HasSuffix(p.Assertion,"=REPRODUCED"){
   return fmt.Errorf("RED event falsely interpreted as blue: %s",p.Cell)
  }
 }
 return nil
}
func main(){
 if len(os.Args)!=2{fmt.Fprintln(os.Stderr,"usage: proof_check.go evidence.json");os.Exit(2)}
 raw,e:=os.ReadFile(os.Args[1]);if e!=nil{panic(e)}
 var m Ledger;if e=json.Unmarshal(raw,&m);e!=nil{panic(e)}
 if e=check(m);e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}
 fmt.Printf("R27_RC_IMMUTABLE_EVIDENCE_INDEX=PASS proofs=%d RELEASE_NOT_ADMITTED\n",len(m.Proofs))
}
