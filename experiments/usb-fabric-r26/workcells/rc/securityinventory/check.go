package main

import (
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "regexp"
 "sort"
)

type Entry struct{
 Cell string `json:"cell"`
 PR int `json:"pr"`
 Commit string `json:"commit"`
 Result string `json:"result"`
 Surface string `json:"surface"`
}
type Gates struct{
 SameUID bool `json:"same_uid_attacker_mitigated"`
 InheritedFD bool `json:"inherited_existing_fd_revoked"`
 ExclusiveQMP bool `json:"production_exclusive_qmp_controller"`
 Epochs bool `json:"epoch_lineage_verified"`
 FsyncedRelease bool `json:"fsynced_release_committed"`
 NextLease bool `json:"safe_next_lease"`
 OwnerApproval bool `json:"owner_approved"`
}
type Manifest struct{
 Schema int `json:"schema"`
 ReleaseAdmission string `json:"release_admission"`
 Evidence []Entry `json:"evidence"`
 Gates Gates `json:"known_gates"`
}
var sha=regexp.MustCompile(`^[0-9a-f]{40}$`)
var expected=map[string]string{"H7":"RED","H24":"RED","H26":"PASS_LIMITED","H27":"NOT_TESTED"}
func validate(m Manifest)error{
 if m.Schema!=1||m.ReleaseAdmission!="BLOCKED"{return errors.New("premature or unsupported release assertion")}
 if len(m.Evidence)!=len(expected){return errors.New("missing or extra evidence")}
 seen:=map[string]bool{}
 for _,e:=range m.Evidence{
  want,ok:=expected[e.Cell]
  if !ok||seen[e.Cell]||e.PR<=0||!sha.MatchString(e.Commit)||e.Surface==""||e.Result!=want{
   return fmt.Errorf("scope or disposition changed for %s",e.Cell)
  }
  seen[e.Cell]=true
 }
 for k:=range expected{if !seen[k]{return errors.New("required historical security witness absent")}}
 g:=m.Gates
 if g.SameUID||g.InheritedFD||g.ExclusiveQMP||g.Epochs||g.FsyncedRelease||g.NextLease||g.OwnerApproval{
  return errors.New("unqualified release gate promoted")
 }
 return nil
}
func main(){
 if len(os.Args)!=2{fmt.Fprintln(os.Stderr,"usage: securityinventory inventory.json");os.Exit(2)}
 raw,e:=os.ReadFile(os.Args[1]);if e!=nil{panic(e)}
 var m Manifest;if e=json.Unmarshal(raw,&m);e!=nil{panic(e)}
 if e=validate(m);e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}
 cells:=[]string{};for _,e:=range m.Evidence{cells=append(cells,e.Cell+":"+e.Result)}
 sort.Strings(cells)
 for _,s:=range cells{fmt.Println("EVIDENCE",s)}
 fmt.Println("R27_E16_RELEASE_GATE=BLOCKED")
 fmt.Println("R27_E16_QMP_BLUE_PRIMITIVE_NOT_RED_CLOSURE=PASS")
 fmt.Println("R27_E16_ACTUAL_GIT_MERGE_BASE=NOT_TESTED")
}
