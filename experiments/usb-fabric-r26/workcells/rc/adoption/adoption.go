package main
import(
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "regexp"
 "sort"
)
type Node struct{
 ID string `json:"id"`
 PR int `json:"pr"`
 Head string `json:"head"`
 Role string `json:"role"`
 Parent string `json:"parent"`
 Scope string `json:"scope"`
}
type Manifest struct{
 Schema int `json:"schema"`
 Repo string `json:"repo"`
 ReleaseReady bool `json:"release_ready"`
 OwnerMergeApproved bool `json:"owner_merge_approved"`
 IntegratedSingleHead string `json:"integrated_single_head"`
 SecurityRed []string `json:"security_red"`
 Nodes []Node `json:"nodes"`
 Blockers []string `json:"blockers"`
}
var sha=regexp.MustCompile(`^[0-9a-f]{40}$`)
func check(m Manifest)error{
 if m.Schema!=1||m.Repo!="SemperSupra/agent-dispatch"||
   m.ReleaseReady||m.OwnerMergeApproved||m.IntegratedSingleHead!=""{
  return errors.New("inventory cannot assert integrated release or owner approval")
 }
 if len(m.Nodes)<6||len(m.SecurityRed)<2||len(m.Blockers)<5{return errors.New("missing required project evidence")}
 byID:=map[string]Node{}
 prs:=map[int]bool{}
 head:=map[string]bool{}
 roles:=map[string]int{}
 for _,n:=range m.Nodes{
  if n.ID==""||n.PR<=0||n.Scope==""||!sha.MatchString(n.Head)||prs[n.PR]||head[n.Head]{
   return fmt.Errorf("invalid duplicate or unscoped PR %s",n.ID)
  }
  if n.Role!="carry"&&n.Role!="critic"&&n.Role!="defer"{return fmt.Errorf("unknown disposition %s",n.Role)}
  if _,ok:=byID[n.ID];ok{return fmt.Errorf("duplicate workcell %s",n.ID)}
  byID[n.ID]=n;prs[n.PR]=true;head[n.Head]=true;roles[n.Role]++
 }
 if roles["carry"]<4||roles["critic"]<2{return errors.New("missing separate proof/critic workcells")}
 for _,n:=range m.Nodes{
  if n.Parent==""{continue}
  if n.ID==n.Parent{return errors.New("self parent")}
  parent,ok:=byID[n.Parent]
  if !ok{return fmt.Errorf("missing parent for %s",n.ID)}
  if parent.Role!=n.Role{return fmt.Errorf("unexpected cross-role merge for %s",n.ID)}
  visited:=map[string]bool{n.ID:true}
  cursor:=n.Parent
  for cursor!=""{
   if visited[cursor]{return fmt.Errorf("cycle at %s",cursor)}
   visited[cursor]=true
   cursor=byID[cursor].Parent
  }
 }
 required:=map[string]bool{"hostile-raw-qmp":false,"fsynced-journal-release":false,"safe-next-lease":false,"owner-release-approval":false}
 for _,name:=range m.Blockers{if _,ok:=required[name];ok{required[name]=true}}
 for key,ok:=range required{if !ok{return fmt.Errorf("missing P0 blocker %s",key)}}
 red:=map[string]bool{}
 for _,name:=range m.SecurityRed{if red[name]{return errors.New("duplicate RED proof")};red[name]=true}
 if !red["H7-same-service-uid-raw-qmp"]||!red["H24-inherited-qmp-fd-primitive"]{
  return errors.New("H7 and H24 RED history must be legible")
 }
 return nil
}
func main(){
 if len(os.Args)!=2{fmt.Fprintln(os.Stderr,"usage: adoption evidence.json");os.Exit(2)}
 raw,e:=os.ReadFile(os.Args[1]);if e!=nil{panic(e)}
 var m Manifest;if e=json.Unmarshal(raw,&m);e!=nil{panic(e)}
 if e=check(m);e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}
 sort.Strings(m.Blockers)
 fmt.Printf("R27_E14_REVIEWED_DRAFT_DAG=PASS nodes=%d blockers=%d\n",len(m.Nodes),len(m.Blockers))
 fmt.Println("R27_E14_INTEGRATED_ONE_HEAD_RC=NOT_TESTED")
 fmt.Println("R27_E14_RELEASE_ADMISSION=BLOCKED")
}
