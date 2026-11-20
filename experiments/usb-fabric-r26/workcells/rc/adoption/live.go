package main

import(
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net/http"
 "os"
 "strconv"
 "strings"
 "time"
)
type Head struct{SHA string `json:"sha"`;Ref string `json:"ref"`}
type RemotePR struct{
 Number int `json:"number"`
 Head Head `json:"head"`
 Base Head `json:"base"`
 Draft bool `json:"draft"`
 State string `json:"state"`
 MergedAt *string `json:"merged_at"`
}
type Source struct{
 Endpoint string
 Token string
 HTTP *http.Client
}
func (s Source)Get(ctx context.Context,prNumber int)(RemotePR,error){
 var result RemotePR
 if s.HTTP==nil||s.Endpoint==""||s.Token==""||prNumber<=0{return result,errors.New("incomplete authenticated GitHub request")}
 req,e:=http.NewRequestWithContext(ctx,"GET",strings.TrimSuffix(s.Endpoint,"/")+"/repos/SemperSupra/agent-dispatch/pulls/"+strconv.Itoa(prNumber),nil)
 if e!=nil{return result,e}
 req.Header.Set("Accept","application/vnd.github+json")
 req.Header.Set("Authorization","Bearer "+s.Token)
 req.Header.Set("X-GitHub-Api-Version","2022-11-28")
 r,e:=s.HTTP.Do(req);if e!=nil{return result,e}
 defer r.Body.Close()
 if r.StatusCode!=200{return result,fmt.Errorf("GitHub PR %d HTTP %d",prNumber,r.StatusCode)}
 if e=json.NewDecoder(io.LimitReader(r.Body,1<<20)).Decode(&result);e!=nil{return result,e}
 return result,nil
}
func verify(ctx context.Context,s Source,m Manifest)error{
 if e:=check(m);e!=nil{return e}
 byID:=map[string]Node{}
 for _,n:=range m.Nodes{byID[n.ID]=n}
 for _,n:=range m.Nodes{
  p,e:=s.Get(ctx,n.PR)
  if e!=nil{return fmt.Errorf("%s: %w",n.ID,e)}
  if p.Number!=n.PR||p.Head.SHA!=n.Head||!p.Draft||p.State!="open"||p.MergedAt!=nil{
   return fmt.Errorf("%s: mutable, closed, merged or incorrect PR head",n.ID)
  }
  if n.Parent!=""{
   parent:=byID[n.Parent]
   if p.Base.SHA!=parent.Head{
    return fmt.Errorf("%s: current live base %s does not match pinned parent %s",n.ID,p.Base.SHA,parent.Head)
   }
  }
  if p.Base.SHA==p.Head.SHA{return fmt.Errorf("%s: head equals base, no differential source",n.ID)}
  fmt.Printf("R27_E15_GITHUB_PR_%d_HEAD_BASE_ATTESTED=PASS\n",p.Number)
 }
 return nil
}
func main(){
 if len(os.Args)!=2{fmt.Fprintln(os.Stderr,"usage: live.go inventory.json");os.Exit(2)}
 raw,e:=os.ReadFile(os.Args[1]);if e!=nil{panic(e)}
 var m Manifest;if e=json.Unmarshal(raw,&m);e!=nil{panic(e)}
 token:=os.Getenv("GH_TOKEN")
 if token==""{fmt.Fprintln(os.Stderr,"GH_TOKEN required; no unauthenticated adoption");os.Exit(1)}
 ctx,cancel:=context.WithTimeout(context.Background(),60*time.Second);defer cancel()
 client:=Source{Endpoint:"https://api.github.com",Token:token,HTTP:&http.Client{Timeout:15*time.Second}}
 if e=verify(ctx,client,m);e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}
 fmt.Printf("R27_E15_LIVE_DRAFT_PR_ANCESTRY=PASS count=%d\n",len(m.Nodes))
 fmt.Println("R27_E15_GIT_MERGE_BASE_VERIFIED=NOT_TESTED")
 fmt.Println("R27_E15_ONE_HEAD_RC=NOT_TESTED")
 fmt.Println("R27_E15_RELEASE_ADMISSION=BLOCKED")
}
