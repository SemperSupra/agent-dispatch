// Stage R only: bounded live retrieval; no concept reasoning or policy decisions.
// Stage P and CPE comparison remain with their private owning authorities.
package main

import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/url"
 "os"
 "regexp"
 "sort"
 "strings"
 "time"
)

const schema = "mcp-gha-stage-r/v1"
const maxPlanBytes = 32768
const maxProviderBytes = 1048576
const maxQueries = 24
const maxHits = 10
const maxQueryChars = 240

type Query struct {
 Language string `json:"language"`
 Text string `json:"text"`
 Role string `json:"role"`
}
type Projection struct {
 Schema string `json:"schema"`
 AuthorityRef string `json:"authority_ref"`
 Queries []Query `json:"queries"`
}
type Plan struct {
 Schema string `json:"schema"`
 ID string `json:"id"`
 DataClass string `json:"data_class"`
 IntentRef string `json:"intent_ref"`
 Reference []Query `json:"reference_queries"`
 CPEProjectionSHA256 string `json:"cpe_projection_sha256"`
 Languages []string `json:"languages"`
 ImageDigest string `json:"searxng_image_digest"`
 ConfigSHA256 string `json:"searxng_config_sha256"`
}
type Hit struct {
 EvidenceID string `json:"evidence_id"`
 URL string `json:"url"`
 Title string `json:"title"`
 Snippet string `json:"snippet"`
 DerivedHash string `json:"derived_hash"`
 Engine string `json:"engine"`
}
type Attempt struct {
 Track string `json:"track"`
 Language string `json:"language"`
 Role string `json:"role"`
 QuerySHA256 string `json:"query_sha256"`
 ElapsedMs int64 `json:"elapsed_ms"`
 State string `json:"state"`
 HTTPStatus int `json:"http_status,omitempty"`
 Hits []Hit `json:"retrieved_evidence"`
 UnresponsiveEngines []string `json:"unresponsive_engines,omitempty"`
}
type Result struct {
 Schema string `json:"schema"`
 PlanID string `json:"plan_id"`
 PlanSHA256 string `json:"plan_sha256"`
 ProjectionSHA256 string `json:"projection_sha256"`
 CPEAuthorityRef string `json:"cpe_authority_ref"`
 AuthorityStatus string `json:"authority_status"`
 SearxngImage string `json:"searxng_image_digest"`
 ConfigSHA256 string `json:"searxng_config_sha256"`
 RuntimeUTC string `json:"runtime_utc"`
 State string `json:"terminal_state"`
 Planned int `json:"planned_requests"`
 Attempted int `json:"attempted_network"`
 Succeeded int `json:"succeeded_provider"`
 Failed int `json:"failed_provider"`
 Attempts []Attempt `json:"attempts"`
}
var identRE=regexp.MustCompile(`^[a-z][a-z0-9-]{2,79}$`)
var langRE=regexp.MustCompile(`^[a-z]{2,3}(-[A-Za-z0-9]{2,8}){0,3}$`)
var hex64=regexp.MustCompile(`^[a-f0-9]{64}$`)
var imageRE=regexp.MustCompile(`^ghcr.io/searxng/searxng:[a-zA-Z0-9.-]+@sha256:[a-f0-9]{64}$`)

func digest(b []byte) string { s:=sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func decodeStrict(b []byte, dst any) error {
 d:=json.NewDecoder(bytes.NewReader(b));d.DisallowUnknownFields()
 if err:=d.Decode(dst);err!=nil{return err}
 var extra any
 if err:=d.Decode(&extra);err!=io.EOF{return errors.New("extra JSON data")}
 return nil
}
func readJSON(path string,dst any) ([]byte,error) {
 f,e:=os.Open(path);if e!=nil{return nil,e};defer f.Close()
 b,e:=io.ReadAll(io.LimitReader(f,maxPlanBytes+1));if e!=nil{return nil,e}
 if len(b)>maxPlanBytes{return nil,errors.New("plan too large")}
 return b,decodeStrict(b,dst)
}
func validateQueries(q []Query, allowed map[string]bool) error {
 if len(q)==0||len(q)>maxQueries{return errors.New("query count out of bounds")}
 seen:=map[string]bool{}
 for _,x:=range q {
  if !allowed[x.Language]||!langRE.MatchString(x.Language){return errors.New("unapproved query language")}
  // The current pinned SearXNG profile qualifies general web only;
  // never mislabel a general web result as a dictionary/ontology observation.
  if x.Role!="web"{return errors.New("source role not qualified by SearXNG profile")}
  if len([]rune(x.Text))<2||len([]rune(x.Text))>maxQueryChars||strings.ContainsAny(x.Text,"\r\n"){return errors.New("query text outside bounds")}
  k:=x.Language+"\x00"+x.Role+"\x00"+x.Text
  if seen[k]{return errors.New("duplicate query")};seen[k]=true
 }
 return nil
}
func validate(p Plan,projection Projection,projectionBytes []byte) error {
 if p.Schema!=schema||p.DataClass!="public-reviewed"||!identRE.MatchString(p.ID)||p.IntentRef==""{return errors.New("invalid public-safe Stage-R plan")}
 if !imageRE.MatchString(p.ImageDigest)||!hex64.MatchString(p.ConfigSHA256){return errors.New("unpinned SearXNG runtime/config")}
 if !hex64.MatchString(p.CPEProjectionSHA256)||digest(projectionBytes)!=p.CPEProjectionSHA256{return errors.New("CPE projection missing or digest mismatch")}
 if projection.Schema!="cpe-search-projection/v1"||projection.AuthorityRef==""{return errors.New("missing CPE projection provenance")}
 if len(p.Languages)<3||len(p.Languages)>20{return errors.New("insufficient global language coverage")}
 allowed:=map[string]bool{}
 for _,lang:=range p.Languages{if !langRE.MatchString(lang)||allowed[lang]{return errors.New("bad language list")};allowed[lang]=true}
 if err:=validateQueries(p.Reference,allowed);err!=nil{return fmt.Errorf("reference: %w",err)}
 if err:=validateQueries(projection.Queries,allowed);err!=nil{return fmt.Errorf("CPE: %w",err)}
 return nil
}
func endpointOK(base string) error {
 u,e:=url.Parse(base);if e!=nil||u.Scheme!="http"||u.User!=nil||u.RawQuery!=""||u.Fragment!=""||u.Path!=""{return errors.New("SearXNG must be loopback HTTP origin")}
 host,_,e:=net.SplitHostPort(u.Host);if e!=nil{return errors.New("explicit loopback port required")}
 ip:=net.ParseIP(host);if ip==nil||!ip.IsLoopback(){return errors.New("external search endpoint denied")}
 return nil
}
type searxReply struct {
 Results []struct{ URL string `json:"url"`;Title string `json:"title"`;Content string `json:"content"`;Engine string `json:"engine"`} `json:"results"`
 Unresponsive [][]any `json:"unresponsive_engines"`
}
func search(ctx context.Context,client *http.Client,endpoint string,track string,i int,q Query) Attempt {
 a:=Attempt{Track:track,Language:q.Language,Role:q.Role,QuerySHA256:digest([]byte(q.Text)),State:"ATTEMPTED_NETWORK",Hits:[]Hit{}}
 u,_:=url.Parse(endpoint+"/search");v:=url.Values{"q":{q.Text},"format":{"json"},"language":{q.Language},"categories":{"general"}}
 u.RawQuery=v.Encode()
 req,e:=http.NewRequestWithContext(ctx,"GET",u.String(),nil)
 if e!=nil{a.State="FAILED_PROVIDER";return a}
 resp,e:=client.Do(req)
 if e!=nil{a.State="FAILED_PROVIDER";return a}
 defer resp.Body.Close();a.HTTPStatus=resp.StatusCode
 if resp.StatusCode!=200{a.State="FAILED_PROVIDER";return a}
 data,e:=io.ReadAll(io.LimitReader(resp.Body,maxProviderBytes+1))
 if e!=nil||len(data)>maxProviderBytes{a.State="FAILED_PROVIDER";return a}
 var parsed searxReply
 if e:=decodeStrictSearx(data,&parsed);e!=nil||parsed.Results==nil{a.State="FAILED_PROVIDER";return a}
 a.State="SUCCEEDED_PROVIDER"
 for n,entry:=range parsed.Results {
  if n==maxHits{break}
  target,e:=url.Parse(entry.URL)
  if e!=nil||!(target.Scheme=="https"||target.Scheme=="http")||target.Host==""{continue}
  // Plain source fields are written ONLY to the local result, later age sealed.
  urlStr:=entry.URL
  title:=truncate(entry.Title,320)
  snippet:=truncate(entry.Content,600)
  a.Hits=append(a.Hits,Hit{EvidenceID:fmt.Sprintf("%s:%03d:%02d",track,i,n),URL:urlStr,Title:title,Snippet:snippet,DerivedHash:digest([]byte(urlStr+":"+title+":"+snippet)),Engine:truncate(entry.Engine,80)})
 }
 for _,x:=range parsed.Unresponsive {if len(x)>0{if s,ok:=x[0].(string);ok {a.UnresponsiveEngines=append(a.UnresponsiveEngines,truncate(s,80))}}}
 sort.Strings(a.UnresponsiveEngines)
 return a
}
func truncate(s string,n int) string {x:=[]rune(s);if len(x)>n{return string(x[:n])};return s}
func decodeStrictSearx(b []byte,out *searxReply) error {
 // SearXNG may append harmless additional response fields; decode documented fields.
 return json.Unmarshal(b,out)
}
func run(ctx context.Context,p Plan,projection Projection,planBytes,projBytes []byte,endpoint string,client *http.Client) (Result,error) {
 if err:=validate(p,projection,projBytes);err!=nil{return Result{},err}
 if err:=endpointOK(endpoint);err!=nil{return Result{},err}
 r:=Result{Schema:schema,PlanID:p.ID,PlanSHA256:digest(planBytes),ProjectionSHA256:digest(projBytes),CPEAuthorityRef:projection.AuthorityRef,AuthorityStatus:"PROJECTION_DIGEST_MATCH_ONLY_NOT_AUTHORITY_VERIFIED",SearxngImage:p.ImageDigest,ConfigSHA256:p.ConfigSHA256,RuntimeUTC:time.Now().UTC().Format(time.RFC3339),State:"TREATMENT_PATH_DEFECT",Attempts:[]Attempt{}}
 for _,t:=range []struct{name string;queries []Query}{{"reference",p.Reference},{"cpe",projection.Queries}} {
  for i,q:=range t.queries {
   r.Planned++
   began:=time.Now()
   attempt:=search(ctx,client,endpoint,t.name,i,q)
   attempt.ElapsedMs=time.Since(began).Milliseconds()
   r.Attempts=append(r.Attempts,attempt);r.Attempted++
   if attempt.State=="SUCCEEDED_PROVIDER"{r.Succeeded++}else{r.Failed++}
  }
 }
 if r.Failed==0 {r.State="RETRIEVAL_PASS"} else if r.Succeeded==0 {r.State="SOURCE_EXECUTOR_GAP"}else{r.State="PARTIAL"}
 return r,nil
}
func main(){
 armPlanPath:=flag.String("arm-plan","","exactly one independently frozen public-safe arm manifest")
 planPath:=flag.String("plan","","approved public-safe plan JSON")
 projectionPath:=flag.String("projection","","separately pinned minimized CPE projection JSON")
 endpoint:=flag.String("endpoint","http://127.0.0.1:18888","loopback SearXNG JSON API")
 out:=flag.String("out","","local plaintext output (caller MUST seal before upload)")
 flag.Parse()
 if *armPlanPath!="" {
  if *planPath!=""||*projectionPath!=""||*out=="" {fmt.Fprintln(os.Stderr,"arm mode requires arm-plan/out only");os.Exit(2)}
  result,e:=runArmFile(context.Background(),*armPlanPath,*endpoint,&http.Client{Timeout:12*time.Second})
  if e!=nil{fmt.Fprintln(os.Stderr,"BLOCKED_SINGLE_ARM_INPUT_OR_PROVIDER_BOUNDARY");os.Exit(2)}
  data,e:=marshalArm(result);if e!=nil{os.Exit(2)}
  if e:=os.WriteFile(*out,append(data,'\n'),0600);e!=nil{os.Exit(2)}
  fmt.Printf("ARM_STAGE_R_%s attempted=%d succeeded=%d failed=%d\n",result.TerminalState,result.Attempted,result.Succeeded,result.Failed)
  if result.TerminalState=="SOURCE_EXECUTOR_GAP"{os.Exit(3)}
  return
 }
 if *planPath==""||*projectionPath==""||*out==""{fmt.Fprintln(os.Stderr,"required plan/projection/out");os.Exit(2)}
 var p Plan;planBytes,e:=readJSON(*planPath,&p);if e!=nil{fmt.Fprintln(os.Stderr,"BLOCKED_PLAN");os.Exit(2)}
 var projection Projection;projectionBytes,e:=readJSON(*projectionPath,&projection);if e!=nil{fmt.Fprintln(os.Stderr,"BLOCKED_CPE_PROJECTION");os.Exit(2)}
 client:=&http.Client{Timeout:12*time.Second}
 result,e:=run(context.Background(),p,projection,planBytes,projectionBytes,*endpoint,client)
 if e!=nil{fmt.Fprintln(os.Stderr,"BLOCKED_INPUT_OR_SOURCE_BOUNDARY");os.Exit(2)}
 data,e:=json.MarshalIndent(result,"","  ");if e!=nil{os.Exit(2)}
 if e:=os.WriteFile(*out,append(data,'\n'),0600);e!=nil{os.Exit(2)}
 // Never print queries or source URLs. Provider failure is NOT a live success.
 fmt.Printf("STAGE_R_%s attempted=%d succeeded=%d failed=%d\n",result.State,result.Attempted,result.Succeeded,result.Failed)
 if result.State=="SOURCE_EXECUTOR_GAP" {os.Exit(3)}
}
