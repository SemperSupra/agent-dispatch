package main

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net/http"
 "os"
 "regexp"
 "strconv"
 "strings"
 "time"
)

type Evidence struct {
 Cell string `json:"cell"`
 PR int `json:"pr"`
 SourceSHA string `json:"source_sha"`
 RunID int64 `json:"run_id"`
 JobID int64 `json:"job_id"`
 Conclusion string `json:"conclusion"`
 Disposition string `json:"disposition"`
 Assertion string `json:"assertion"`
}
type Inventory struct{
 Repository string `json:"repository"`
 Proofs []Evidence `json:"proofs"`
}
type ref struct {SHA string `json:"sha"`}
type pr struct {Number int `json:"number"`; Head ref `json:"head"`}
type run struct {ID int64 `json:"id"`;HeadSHA string `json:"head_sha"`;Status string `json:"status"`;Conclusion string `json:"conclusion"`;Event string `json:"event"`;PullRequests []struct{Number int `json:"number"`;Head ref `json:"head"`} `json:"pull_requests"`}
type job struct {ID int64 `json:"id"`;RunID int64 `json:"run_id"`;Status string `json:"status"`;Conclusion string `json:"conclusion"`}
var fullSHA=regexp.MustCompile(`^[0-9a-f]{40}$`)
var fullMarker=regexp.MustCompile(`^[A-Z][A-Z0-9_]*=(PASS|REPRODUCED)$`)
func valid(i Inventory)error{
 if i.Repository!="SemperSupra/agent-dispatch"||len(i.Proofs)==0{return errors.New("invalid repo or empty proof inventory")}
 seen:=map[string]bool{}
 for _,p:=range i.Proofs{
  if p.Cell==""||seen[p.Cell]||p.PR<=0||!fullSHA.MatchString(p.SourceSHA)||p.RunID<=0||p.JobID<=0||
   p.Conclusion!="success"||!fullMarker.MatchString(p.Assertion){return fmt.Errorf("invalid identity for %s",p.Cell)}
  seen[p.Cell]=true
  if !strings.HasPrefix(p.Assertion,strings.ToUpper(strings.ReplaceAll(p.Cell,"-",""))+"_"){return fmt.Errorf("cross-cell assertion %s",p.Cell)}
  switch p.Disposition{
  case "PASS":
   if !strings.HasSuffix(p.Assertion,"=PASS"){return fmt.Errorf("forged positive %s",p.Cell)}
  case "RED":
   if !strings.HasSuffix(p.Assertion,"=REPRODUCED"){return fmt.Errorf("forged red %s",p.Cell)}
  default:return fmt.Errorf("unsupported verdict %s",p.Disposition)
  }
 }
 return nil
}
type Client struct{Base string;Token string;HTTP *http.Client}
func(c Client)get(ctx context.Context,path string,v any)error{
 req,err:=http.NewRequestWithContext(ctx,"GET",strings.TrimSuffix(c.Base,"/")+path,nil)
 if err!=nil{return err}
 req.Header.Set("Accept","application/vnd.github+json")
 req.Header.Set("X-GitHub-Api-Version","2022-11-28")
 if c.Token!=""{req.Header.Set("Authorization","Bearer "+c.Token)}
 res,err:=c.HTTP.Do(req);if err!=nil{return err};defer res.Body.Close()
 if res.StatusCode!=200{return fmt.Errorf("GitHub %s: HTTP %d",path,res.StatusCode)}
 return json.NewDecoder(io.LimitReader(res.Body,4<<20)).Decode(v)
}
func(c Client)logs(ctx context.Context,path string)(string,error){
 req,err:=http.NewRequestWithContext(ctx,"GET",strings.TrimSuffix(c.Base,"/")+path,nil);if err!=nil{return "",err}
 req.Header.Set("Accept","application/vnd.github+json")
 if c.Token!=""{req.Header.Set("Authorization","Bearer "+c.Token)}
 res,err:=c.HTTP.Do(req);if err!=nil{return "",err};defer res.Body.Close()
 if res.StatusCode!=200{return "",fmt.Errorf("GitHub log HTTP %d",res.StatusCode)}
 raw,err:=io.ReadAll(io.LimitReader(res.Body,8<<20));if err!=nil{return "",err}
 return string(raw),nil
}
func markerInLog(log,assertion string)bool{
 for _,line:=range strings.Split(log,"\n"){
  for _,field:=range strings.Fields(line){
   if strings.TrimSpace(field)==assertion{return true}
  }
 }
 return false
}
func verify(ctx context.Context,c Client,i Inventory)error{
 if err:=valid(i);err!=nil{return err}
 for _,p:=range i.Proofs{
  base:="/repos/"+i.Repository
  var pbody pr
  if err:=c.get(ctx,base+"/pulls/"+strconv.Itoa(p.PR),&pbody);err!=nil{return err}
  if pbody.Number!=p.PR||pbody.Head.SHA!=p.SourceSHA{return fmt.Errorf("%s PR head source mismatch",p.Cell)}
  var r run
  if err:=c.get(ctx,base+"/actions/runs/"+strconv.FormatInt(p.RunID,10),&r);err!=nil{return err}
  if r.ID!=p.RunID||r.Status!="completed"||r.Conclusion!="success"{return fmt.Errorf("%s run incomplete or not green",p.Cell)}
  linked:=r.HeadSHA==p.SourceSHA
  for _,q:=range r.PullRequests{
   if q.Number==p.PR && (q.Head.SHA==p.SourceSHA || r.HeadSHA==p.SourceSHA){linked=true}
  }
  if !linked{return fmt.Errorf("%s run not linked to immutable PR head",p.Cell)}
  var j job
  if err:=c.get(ctx,base+"/actions/jobs/"+strconv.FormatInt(p.JobID,10),&j);err!=nil{return err}
  if j.ID!=p.JobID||j.RunID!=p.RunID||j.Status!="completed"||j.Conclusion!=p.Conclusion{return fmt.Errorf("%s job/source mismatch",p.Cell)}
  log,err:=c.logs(ctx,base+"/actions/jobs/"+strconv.FormatInt(p.JobID,10)+"/logs")
  if err!=nil{return err}
  if !markerInLog(log,p.Assertion){return fmt.Errorf("%s claimed assertion missing from authenticated job logs",p.Cell)}
  fmt.Printf("R27_E10_LIVE_GITHUB_%s_%s_VERIFIED=PASS run=%d job=%d\n",p.Cell,p.Disposition,p.RunID,p.JobID)
 }
 return nil
}
func main(){
 if len(os.Args)!=2{fmt.Fprintln(os.Stderr,"usage: liveverify evidence.json");os.Exit(2)}
 raw,err:=os.ReadFile(os.Args[1]);if err!=nil{panic(err)}
 var inv Inventory
 if err=json.Unmarshal(raw,&inv);err!=nil{panic(err)}
 token:=os.Getenv("GH_TOKEN")
 if token==""{fmt.Fprintln(os.Stderr,"GH_TOKEN is mandatory for API/log corroboration");os.Exit(1)}
 ctx,cancel:=context.WithTimeout(context.Background(),60*time.Second);defer cancel()
 c:=Client{Base:"https://api.github.com",Token:token,HTTP:&http.Client{Timeout:20*time.Second}}
 if err=verify(ctx,c,inv);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
 fmt.Println("R27_E10_GITHUB_LIVE_EVIDENCE=PASS; RELEASE_NOT_ADMITTED")
}
