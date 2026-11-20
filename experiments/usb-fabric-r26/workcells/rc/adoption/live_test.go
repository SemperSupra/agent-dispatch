package main

import(
 "context"
 "encoding/json"
 "fmt"
 "net/http"
 "net/http/httptest"
 "strconv"
 "strings"
 "testing"
)
func fixture(t *testing.T)Manifest{return sample(t)}
func fakeGithub(t *testing.T,m Manifest,mode string)*httptest.Server{
 t.Helper()
 return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.Header.Get("Authorization")!="Bearer fixture"{t.Error("missing read-only auth")}
  raw:=strings.TrimPrefix(r.URL.Path,"/repos/SemperSupra/agent-dispatch/pulls/")
  id,e:=strconv.Atoi(raw);if e!=nil{http.Error(w,"bad id",400);return}
  var node Node
  found:=false
  for _,n:=range m.Nodes{if n.PR==id{node=n;found=true;break}}
  if !found{http.Error(w,"not found",404);return}
  base:=strings.Repeat("e",40)
  if node.Parent!=""{for _,n:=range m.Nodes{if n.ID==node.Parent{base=n.Head}}}
  head:=node.Head
  merged:=any(nil)
  state:="open"
  draft:=true
  switch mode{
  case "wrong-head":if id==937{head=strings.Repeat("f",40)}
  case "wrong-parent":if id==937{base=strings.Repeat("a",40)}
  case "merged":if id==937{merged="2026-11-20T12:00:00Z"}
  case "closed":if id==937{state="closed"}
  case "not-draft":if id==937{draft=false}
  }
  body:=map[string]any{"number":id,"head":map[string]any{"sha":head},"base":map[string]any{"sha":base},"draft":draft,"state":state,"merged_at":merged}
  _=json.NewEncoder(w).Encode(body)
 }))
}
func TestAuthenticatedCurrentSixPRDAG(t *testing.T){
 m:=fixture(t);s:=fakeGithub(t,m,"");defer s.Close()
 if e:=verify(context.Background(),Source{Endpoint:s.URL,Token:"fixture",HTTP:s.Client()},m);e!=nil{t.Fatal(e)}
}
func TestRejectStaleOrMergedLivePR(t *testing.T){
 for _,mode:=range []string{"wrong-head","wrong-parent","merged","closed","not-draft"}{
  t.Run(mode,func(t *testing.T){m:=fixture(t);s:=fakeGithub(t,m,mode);defer s.Close()
   if e:=verify(context.Background(),Source{Endpoint:s.URL,Token:"fixture",HTTP:s.Client()},m);e==nil{t.Fatal("stale or merged PR authenticated")}
  })
 }
}
func TestNoTokenIsNotVerification(t *testing.T){
 m:=fixture(t);s:=fakeGithub(t,m,"");defer s.Close()
 if e:=verify(context.Background(),Source{Endpoint:s.URL,HTTP:s.Client()},m);e==nil{t.Fatal("anonymous API accepted")}
}
func TestNoInventedReleaseAuthority(t *testing.T){
 m:=fixture(t);m.ReleaseReady=true
 s:=fakeGithub(t,m,"");defer s.Close()
 if e:=verify(context.Background(),Source{Endpoint:s.URL,Token:"fixture",HTTP:s.Client()},m);e==nil{t.Fatal("release authority forged")}
}
func TestHTTPErrorFailClosed(t *testing.T){
 m:=fixture(t);s:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){fmt.Fprint(w,"denied");w.WriteHeader(403)}));defer s.Close()
 if e:=verify(context.Background(),Source{Endpoint:s.URL,Token:"fixture",HTTP:s.Client()},m);e==nil{t.Fatal("API errors accepted")}
}
