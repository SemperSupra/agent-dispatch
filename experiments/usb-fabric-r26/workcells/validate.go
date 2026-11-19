package main
import("encoding/json";"errors";"fmt";"os";"path";"strings")
type Cell struct{ID string `json:"id"`;Priority string `json:"priority"`;Lane string `json:"lane"`;Base string `json:"base"`;Writes []string `json:"write_paths"`;Depends []string `json:"depends_on"`;Acceptance string `json:"acceptance"`}
type Manifest struct{Schema int `json:"schema"`;MaxParallel int `json:"max_parallel"`;Cells []Cell `json:"workcells"`}
func validate(m Manifest)error{
 if m.Schema!=1||m.MaxParallel<2||m.MaxParallel>4{return errors.New("invalid schema or parallel limit")}
 if len(m.Cells)<2{return errors.New("batch collapsed below two workcells")}
 seen:=map[string]bool{};owners:=map[string]string{}
 for _,c:=range m.Cells{
  if c.ID==""||seen[c.ID]||c.Priority==""||c.Lane==""||len(c.Base)<12||c.Acceptance==""||len(c.Writes)==0{return fmt.Errorf("invalid workcell %q",c.ID)}
  seen[c.ID]=true
  for _,p:=range c.Writes{
   if p==""||path.IsAbs(p)||path.Clean(p)!=p||p=="."||p==".."||strings.HasPrefix(p,"../")||strings.ContainsRune(p,92) {return fmt.Errorf("invalid or ambiguous write path %q for %s",p,c.ID)}
   for existing,who:=range owners{
    if existing==p||strings.HasPrefix(p,existing+"/")||strings.HasPrefix(existing,p+"/"){
     return fmt.Errorf("parallel write collision %s and %s: %s versus %s",who,c.ID,existing,p)
    }
   }
   owners[p]=c.ID
  }
 }
 for _,c:=range m.Cells{
  for _,d:=range c.Depends{if !seen[d]||d==c.ID{return fmt.Errorf("invalid dependency %s -> %s",c.ID,d)}}
 }
 active:=map[string]bool{};done:=map[string]bool{};byID:=map[string]Cell{}
 for _,c:=range m.Cells{byID[c.ID]=c}
 var visit func(string)error
 visit=func(id string)error{
  if active[id]{return fmt.Errorf("dependency cycle at %s",id)}
  if done[id]{return nil}
  active[id]=true
  for _,d:=range byID[id].Depends{if err:=visit(d);err!=nil{return err}}
  active[id]=false;done[id]=true;return nil
 }
 for id:=range byID{if err:=visit(id);err!=nil{return err}}
 return nil
}
func main(){
 if len(os.Args)!=2{fmt.Fprintln(os.Stderr,"usage: go run validate.go <manifest.json>");os.Exit(2)}
 b,err:=os.ReadFile(os.Args[1]);if err!=nil{panic(err)}
 var m Manifest
 if err=json.Unmarshal(b,&m);err!=nil{panic(err)}
 if err=validate(m);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
 fmt.Printf("USB_FABRIC_PARALLEL_WORKCELL_MANIFEST=PASS cells=%d slots=%d\n",len(m.Cells),m.MaxParallel)
 waves,err:=planWaves(m)
 if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
 encoded,err:=json.Marshal(waves)
 if err!=nil{panic(err)}
 fmt.Printf("USB_FABRIC_DETERMINISTIC_EXECUTION_WAVES=%s\n",string(encoded))
}
