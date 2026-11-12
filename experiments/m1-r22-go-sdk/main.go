// Real official Go MCP SDK client, public-safe synthetic tool-belt qualification.
// No model inference, account OAuth, native private workset or production tokens.
package main

import (
  "context"
  "encoding/json"
  "fmt"
  "net/http"
  "os"
  "path/filepath"
  "sort"
  "strings"
  "time"

  "github.com/modelcontextprotocol/go-sdk/mcp"
)

type bearerTransport struct {
  base http.RoundTripper
  token string
}
func (t bearerTransport) RoundTrip(r *http.Request) (*http.Response,error) {
  c:=r.Clone(r.Context())
  c.Header.Set("Authorization","Bearer "+t.token)
  return t.base.RoundTrip(c)
}
type check struct { Name string `json:"name"`; Passed bool `json:"passed"` }
type receipt struct {
  Schema string `json:"schema"`
  Phase string `json:"phase"`
  Checks []check `json:"checks"`
  Passed bool `json:"passed"`
  Error string `json:"error,omitempty"`
  Scope string `json:"scope"`
  Limitations []string `json:"limitations"`
}
func toolText(result *mcp.CallToolResult) string {
 if result==nil{return ""}
 b,_:=json.Marshal(result.Content)
 return string(b)
}
func qualify(ctx context.Context, phase,profile,belt string, stale bool, rec *receipt) error {
  filename:=filepath.Join("runtime-receipts",profile+"-"+belt+".jwt")
  secret,err:=os.ReadFile(filename)
  if err!=nil{return fmt.Errorf("token fixture missing: %w",err)}
  token:=strings.TrimSpace(string(secret))
  httpClient:=&http.Client{Timeout:12*time.Second,
    Transport:bearerTransport{base:http.DefaultTransport,token:token}}
  client:=mcp.NewClient(&mcp.Implementation{Name:"m1-r22-official-go-sdk",Version:"1"},nil)
  session,err:=client.Connect(ctx,&mcp.StreamableClientTransport{
    Endpoint:"http://127.0.0.1:39200/mcp",HTTPClient:httpClient},nil)
  if err!=nil{return fmt.Errorf("sdk session connect %s/%s: %w",profile,belt,err)}
  defer session.Close()
  tools,err:=session.ListTools(ctx,&mcp.ListToolsParams{})
  if err!=nil{return fmt.Errorf("sdk ListTools: %w",err)}
  names:=[]string{}
  for _,t:=range tools.Tools {names=append(names,t.Name)}
  sort.Strings(names)
  expected:="alpha_echo"
  other:="beta_echo"
  expectedSource:="alpha:"
  otherSource:="beta:"
  if (profile=="old"&&belt=="engineering")||(profile=="new"&&belt=="research") {
    expected,other=other,expected
    expectedSource,otherSource=otherSource,expectedSource
  }
  want:=[]string{expected}
  if stale {want=[]string{}}
  rec.Checks=append(rec.Checks,check{fmt.Sprintf("%s-%s-sdk-discovery",profile,belt),strings.Join(names,",")==strings.Join(want,",")})
  if !stale {
    got,err:=session.CallTool(ctx,&mcp.CallToolParams{
      Name:expected,Arguments:map[string]any{"text":"real-go-sdk"}})
    ok:=err==nil&&got!=nil&&!got.IsError&&strings.Contains(toolText(got),expectedSource+"real-go-sdk")
    rec.Checks=append(rec.Checks,check{fmt.Sprintf("%s-%s-sdk-own-invocation",profile,belt),ok})
  }
  crossResult,crossErr:=session.CallTool(ctx,&mcp.CallToolParams{
    Name:other,Arguments:map[string]any{"text":"must-deny"}})
  crossDenied:=crossErr!=nil||crossResult==nil||crossResult.IsError||!strings.Contains(toolText(crossResult),otherSource+"must-deny")
  rec.Checks=append(rec.Checks,check{fmt.Sprintf("%s-%s-sdk-direct-unselected-denied",profile,belt),crossDenied})
  if stale {
    oldTool:="alpha_echo"
    if belt=="engineering"{oldTool="beta_echo"}
    oldRes,oldErr:=session.CallTool(ctx,&mcp.CallToolParams{
      Name:oldTool,Arguments:map[string]any{"text":"stale-must-deny"}})
    oldDenied:=oldErr!=nil||oldRes==nil||oldRes.IsError||!strings.Contains(toolText(oldRes),"stale-must-deny")
    rec.Checks=append(rec.Checks,check{fmt.Sprintf("%s-%s-stale-signed-jwt-denied",profile,belt),oldDenied})
  }
  return nil
}
func main(){
 phase:="old"
 if len(os.Args)!=2 || (os.Args[1]!="old"&&os.Args[1]!="new"){
  fmt.Fprintln(os.Stderr,"usage: official-sdk old|new");os.Exit(2)
 }
 phase=os.Args[1]
 out:=receipt{Schema:"m1-r22-official-go-sdk-g4-c2-v1",Phase:phase,
  Scope:"Real official modelcontextprotocol/go-sdk v1.8.0; actual synthetic signed-JWT Agentgateway transport, discovery and tool invocation.",
  Limitations:[]string{"No LLM/model run; client SDK is not an AI agent",
    "Synthetic issuer and MCP upstreams, not real OAuth or native workset",
    "Only legacy negotiated transport against this gateway tested; no assertion that negotiated 2026-07-28",
    "No ChatGPT Secure MCP Tunnel or Gemini provider identity",
    "Ephemeral free hosted GHA, not deployment acceptance"}}
 ctx,cancel:=context.WithTimeout(context.Background(),40*time.Second)
 defer cancel()
 for _,belt:=range []string{"research","engineering"} {
  if err:=qualify(ctx,phase,phase,belt,false,&out);err!=nil {out.Error=err.Error();break}
 }
 if phase=="new"&&out.Error=="" {
  for _,belt:=range []string{"research","engineering"} {
   if err:=qualify(ctx,phase,"old",belt,true,&out);err!=nil {
    // A hard rejection of an obsolete signed session during connect is still a correct stale-token denial.
    msg:=strings.ToLower(err.Error())
    acceptedDeny:=strings.Contains(msg,"401")||strings.Contains(msg,"403")||strings.Contains(msg,"unauthorized")||strings.Contains(msg,"forbidden")
    out.Checks=append(out.Checks,check{"old-"+belt+"-sdk-stale-connection-rejected",acceptedDeny})
   }
  }
 }
 out.Passed=out.Error==""&&len(out.Checks)>0
 for _,item:=range out.Checks{out.Passed=out.Passed&&item.Passed}
 os.MkdirAll("runtime-receipts",0700)
 data,_:=json.MarshalIndent(out,"","  ")
 os.WriteFile(filepath.Join("runtime-receipts","official-sdk-"+phase+".json"),append(data,byte(10)),0600)
 fmt.Println(string(data))
 if !out.Passed {os.Exit(1)}
}
