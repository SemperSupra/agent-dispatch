package main

// Isolated synthetic HTTP harness around Casbin's Go library.
// Not an Agent Dispatch connector or production authentication service.
import (
 "encoding/json"
 "log"
 "net/http"
 "sync"
 "time"
 "github.com/casbin/casbin/v3"
 "github.com/casbin/casbin/v3/model"
)

type query struct {
 Principal string `json:"principal"`
 Resource string `json:"resource"`
 Action string `json:"action"`
}
type decision struct { Result bool `json:"result"` }
const spec = `[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p_eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act`

func main() {
 m, err := model.NewModelFromString(spec)
 if err != nil { log.Fatal(err) }
 e, err := casbin.NewEnforcer(m)
 if err != nil { log.Fatal(err) }
 if _, err = e.AddPolicy("worker-a","workset-a","observe"); err != nil { log.Fatal(err) }
 var mu sync.RWMutex
 mux:=http.NewServeMux()
 mux.HandleFunc("/healthz", func(w http.ResponseWriter,r *http.Request){ if r.Method!=http.MethodGet {http.Error(w,"method",405); return}; w.Write([]byte("ok")) })
 mux.HandleFunc("/v1/check", func(w http.ResponseWriter,r *http.Request){
  if r.Method!=http.MethodPost {http.Error(w,"method",405); return}
  r.Body=http.MaxBytesReader(w,r.Body,4096)
  defer r.Body.Close()
  var q query
  if err:=json.NewDecoder(r.Body).Decode(&q); err!=nil {http.Error(w,"invalid request",400);return}
  mu.RLock()
  ok,err:=e.Enforce(q.Principal,q.Resource,q.Action)
  mu.RUnlock()
  if err!=nil {http.Error(w,"evaluation failed",500);return}
  w.Header().Set("Content-Type","application/json")
  json.NewEncoder(w).Encode(decision{Result:ok})
 })
 mux.HandleFunc("/v1/revoke", func(w http.ResponseWriter,r *http.Request){
  if r.Method!=http.MethodPost {http.Error(w,"method",405); return}
  mu.Lock()
  _,err:=e.RemovePolicy("worker-a","workset-a","observe")
  mu.Unlock()
  if err!=nil {http.Error(w,"revoke failed",500);return}
  w.WriteHeader(http.StatusNoContent)
 })
 s:=&http.Server{Addr:":8090",Handler:mux,ReadHeaderTimeout:3*time.Second}
 log.Fatal(s.ListenAndServe())
}
