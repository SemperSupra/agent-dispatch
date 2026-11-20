package main

import(
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net/http"
 "strconv"
 "strings"
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
