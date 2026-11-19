package main
import("encoding/json";"fmt";"os";"regexp")
type Candidate struct{ID string `json:"id"`;PR int `json:"pr"`;Head string `json:"head"`;Decision string `json:"decision"`;Gate string `json:"gate"`;Reason string `json:"reason"`;MitigatedBy string `json:"mitigated_by,omitempty"`}
type RC struct{Schema int `json:"schema"`;Release string `json:"release"`;Authority string `json:"authority"`;Baseline string `json:"baseline"`;Scope string `json:"scope"`;Candidates []Candidate `json:"candidates"`;Blockers []string `json:"blockers"`}
var hexSHA=regexp.MustCompile(`^[0-9a-f]{40}$`)
func assess(m RC)(bool,error){
 if m.Schema!=1||m.Release==""||m.Authority==""||!hexSHA.MatchString(m.Baseline)||len(m.Candidates)<2{return false,fmt.Errorf("invalid RC authority/schema")}
 ids:=map[string]bool{};prs:=map[int]bool{};byID:=map[string]Candidate{};blocked:=len(m.Blockers)>0
 for _,c:=range m.Candidates{
  if c.ID==""||ids[c.ID]||c.Reason=="" {return false,fmt.Errorf("duplicate or incomplete cell")}
  ids[c.ID]=true;byID[c.ID]=c
  if c.PR>0 {if prs[c.PR]{return false,fmt.Errorf("duplicate PR")};prs[c.PR]=true}
  switch c.Decision{
  case "carry":
   if c.PR<=0||!hexSHA.MatchString(c.Head)||c.Gate!="PASS"{return false,fmt.Errorf("unqualified carry: %s",c.ID)}
  case "preserve-red":
   if c.PR<=0||c.Gate!="RED"||!hexSHA.MatchString(c.Head){return false,fmt.Errorf("lost red evidence: %s",c.ID)}
  case "defer","pending":
   blocked=true
  default:return false,fmt.Errorf("unknown adoption decision %s",c.ID)
  }
  if c.Gate=="NOT_TESTED"{blocked=true}
 }
 // Historic RED findings must remain visible. A mitigation is credited
 // only when it references a carried, qualified, immutable source.
 // Never rewrite the RED verdict itself as PASS.
 for _,c:=range m.Candidates{
  if c.Decision!="preserve-red"{continue}
  if c.MitigatedBy==""{blocked=true;continue}
  m,ok:=byID[c.MitigatedBy]
  if !ok||m.Decision!="carry"||m.Gate!="PASS"||!hexSHA.MatchString(m.Head){
   return false,fmt.Errorf("RED %s has invalid mitigation %s",c.ID,c.MitigatedBy)
  }
 }
 return !blocked,nil
}
func main(){
 if len(os.Args)!=2{fmt.Fprintln(os.Stderr,"usage: rc_gate.go manifest.json");os.Exit(2)}
 bytes,err:=os.ReadFile(os.Args[1]);if err!=nil{panic(err)}
 var m RC
 if err=json.Unmarshal(bytes,&m);err!=nil{panic(err)}
 ready,err:=assess(m);if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
 if ready {fmt.Println("USB_FABRIC_RC_ADMISSION=READY")} else{fmt.Printf("USB_FABRIC_RC_ADMISSION=BLOCKED blockers=%d cells=%d\n",len(m.Blockers),len(m.Candidates))}
}
