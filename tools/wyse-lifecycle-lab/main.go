// Command wyse-lifecycle-lab is a public-synthetic-only fleet lifecycle
// simulator. It has NO firmware, disk, power, GARM, TrueNAS or TPM actuator.
package main

import (
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "crypto/subtle"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "log"
 "net"
 "net/http"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "time"
)

const scope = "PUBLIC_SYNTHETIC_ONLY"
const enrollDomain = "WYSE-LAB-ENROLL-v1\x00"
const rotateDomain = "WYSE-LAB-ROTATE-v1\x00"

type Device struct {
 ID string `json:"id"`
 Key string `json:"public_key"`
 State string `json:"state"`
 Revision int64 `json:"revision"`
 Verified bool `json:"hardware_verified"`
}
type Event struct {
 Seq int64 `json:"seq"`
 DeviceID string `json:"device_id"`
 Action string `json:"action"`
 Actor string `json:"actor"`
 Revision int64 `json:"revision"`
}
type Pending struct {
 Key string `json:"key"`
 Challenge string `json:"challenge"`
 Witness string `json:"witness"`
 Deadline time.Time `json:"deadline"`
}
type Snapshot struct {
 Nodes map[string]Device `json:"nodes"`
 Pending map[string]Pending `json:"pending"`
 Events []Event `json:"events"`
 Idempotency map[string]string `json:"idempotency"`
 Rotation map[string]Pending `json:"rotation"`
}
type Service struct {
 mu sync.Mutex
 file string
 secret []byte
 state Snapshot
 now func() time.Time
}
type request struct {
 ID string `json:"id"`
 PublicKey string `json:"public_key"`
 Witness string `json:"witness"`
 Signature string `json:"signature"`
 OldSignature string `json:"old_signature"`
 NewSignature string `json:"new_signature"`
 Action string `json:"action"`
 ExpectedRevision int64 `json:"expected_revision"`
}
func newService(file string, secret []byte) (*Service,error) {
 if len(secret)<32 {return nil,errors.New("bearer token must be at least 32 bytes")}
 s:=&Service{file:file,secret:append([]byte(nil),secret...),now:time.Now}
 s.state=Snapshot{Nodes:map[string]Device{},Pending:map[string]Pending{},Rotation:map[string]Pending{},Idempotency:map[string]string{}}
 b,err:=os.ReadFile(file)
 if err!=nil && !errors.Is(err,os.ErrNotExist) {return nil,err}
 if err==nil {
  if err=json.Unmarshal(b,&s.state);err!=nil{return nil,fmt.Errorf("state corrupted, fail closed: %w",err)}
  if s.state.Nodes==nil||s.state.Pending==nil||s.state.Rotation==nil||s.state.Idempotency==nil{return nil,errors.New("missing state collections")}
 }
 return s,nil
}
func randomHex(n int) (string,error) {
 b:=make([]byte,n)
 if _,err:=rand.Read(b);err!=nil{return "",err}
 return hex.EncodeToString(b),nil
}
func parseKey(raw string) (ed25519.PublicKey,error) {
 b,err:=base64.StdEncoding.DecodeString(raw)
 if err!=nil||len(b)!=ed25519.PublicKeySize{return nil,errors.New("invalid Ed25519 key")}
 return ed25519.PublicKey(b),nil
}
func validID(id string) bool {
 if len(id)<3||len(id)>48{return false}
 for _,c:=range id {if !(c>='a'&&c<='z'||c>='0'&&c<='9'||c=='-'){return false}}
 return true
}
func checkSignature(pub string,sig string,msg string) bool {
 pk,err:=parseKey(pub);if err!=nil{return false}
 b,err:=base64.StdEncoding.DecodeString(sig)
 return err==nil&&ed25519.Verify(pk,[]byte(msg),b)
}
func (s *Service) save() error {
 b,err:=json.MarshalIndent(s.state,"","  ");if err!=nil{return err}
 dir:=filepath.Dir(s.file)
 if err=os.MkdirAll(dir,0700);err!=nil{return err}
 f,err:=os.CreateTemp(dir,".wyse-state-*");if err!=nil{return err}
 defer os.Remove(f.Name())
 if err=f.Chmod(0600);err!=nil{f.Close();return err}
 if _,err=f.Write(b);err!=nil{f.Close();return err}
 if err=f.Sync();err!=nil{f.Close();return err}
 if err=f.Close();err!=nil{return err}
 if err=os.Rename(f.Name(),s.file);err!=nil{return err}
 d,err:=os.Open(dir);if err==nil{_ = d.Sync();_ = d.Close()}
 return nil
}
func (s *Service) record(id,action,actor string,rev int64) {
 s.state.Events=append(s.state.Events,Event{Seq:int64(len(s.state.Events)+1),DeviceID:id,Action:action,Actor:actor,Revision:rev})
}
func response(w http.ResponseWriter,code int,value any) {
 w.Header().Set("Content-Type","application/json")
 w.WriteHeader(code)
 _=json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter,code int,msg string){response(w,code,map[string]string{"error":msg})}
func decode(w http.ResponseWriter,r *http.Request)(request,bool) {
 var x request
 if r.Header.Get("Content-Type")!="application/json"{fail(w,415,"application/json required");return x,false}
 d:=json.NewDecoder(io.LimitReader(r.Body,8193));d.DisallowUnknownFields()
 if err:=d.Decode(&x);err!=nil{fail(w,400,"invalid JSON");return x,false}
 var extra any
 if d.Decode(&extra)!=io.EOF{fail(w,400,"trailing or oversized JSON");return x,false}
 return x,true
}
func actor(r *http.Request) string {
 a:=r.Header.Get("X-Actor")
 if a=="human"||a=="automation"||a=="agent"{return a}
 return "unknown"
}
func (s *Service) Handler() http.Handler {
 mux:=http.NewServeMux()
 mux.HandleFunc("GET /healthz",func(w http.ResponseWriter,r *http.Request){_,_=w.Write([]byte("ok\n"))})
 mux.HandleFunc("GET /",func(w http.ResponseWriter,r *http.Request){
  if r.URL.Path!="/"{http.NotFound(w,r);return}
  w.Header().Set("Content-Type","text/html; charset=utf-8")
  w.Header().Set("Content-Security-Policy","default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
  _,_=w.Write([]byte(htmlUI))
 })
 mux.HandleFunc("GET /app.js",func(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Type","text/javascript; charset=utf-8");_,_=w.Write([]byte(jsUI))})
 mux.HandleFunc("GET /style.css",func(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Type","text/css; charset=utf-8");_,_=w.Write([]byte(cssUI))})
 mux.HandleFunc("GET /api/v1/lab/schema",func(w http.ResponseWriter,r *http.Request){
  response(w,200,map[string]any{"schema":"wyse-lifecycle-lab/v1","scope":scope,"hardware_verified":false,"real_garm_admission":false,"physical_mutation":false,
   "audiences":[]string{"human","automation","agent"},"states":[]string{"PENDING","ENROLLED","COMMISSIONED","READY","DRAINED","QUARANTINED","RETIRED"},"auth":"Bearer token; X-Actor is descriptive and NOT authorization",
   "enroll_proof":enrollDomain+"<id>\\x00<server-challenge>","rotate_proof":rotateDomain+"<id>\\x00<server-challenge>"})
 })
 protected:=func(w http.ResponseWriter,r *http.Request) bool {
  const prefix="Bearer "
  a:=r.Header.Get("Authorization")
  if !strings.HasPrefix(a,prefix)||subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(a,prefix)),s.secret)!=1 {
   w.Header().Set("WWW-Authenticate",`Bearer realm="wyse-lab"`)
   fail(w,401,"unauthorized");return false
  }
  return true
 }
 mux.HandleFunc("GET /api/v1/lab/nodes",func(w http.ResponseWriter,r *http.Request){
  if !protected(w,r){return}
  s.mu.Lock();defer s.mu.Unlock()
  nodes:=make([]Device,0,len(s.state.Nodes))
  for _,n:=range s.state.Nodes{nodes=append(nodes,n)}
  response(w,200,map[string]any{"scope":scope,"nodes":nodes})
 })
 mux.HandleFunc("GET /api/v1/lab/events",func(w http.ResponseWriter,r *http.Request){
  if !protected(w,r){return}
  s.mu.Lock();defer s.mu.Unlock()
  response(w,200,map[string]any{"scope":scope,"events":s.state.Events})
 })
 mux.HandleFunc("POST /api/v1/lab/enrollments",func(w http.ResponseWriter,r *http.Request){
  if !protected(w,r){return}
  x,ok:=decode(w,r);if !ok{return}
  if !validID(x.ID){fail(w,400,"invalid device ID");return}
  if _,err:=parseKey(x.PublicKey);err!=nil{fail(w,400,"invalid key");return}
  idem:=r.Header.Get("Idempotency-Key")
  if len(idem)<8||len(idem)>96{fail(w,400,"idempotency key required");return}
  s.mu.Lock();defer s.mu.Unlock()
  sum:=sha256.Sum256([]byte(x.ID+"|"+x.PublicKey))
  fingerprint:=hex.EncodeToString(sum[:])
  if old,ok:=s.state.Idempotency[idem];ok {
   if old!=fingerprint{fail(w,409,"idempotency conflict");return}
   if p,ok:=s.state.Pending[x.ID];ok{response(w,200,map[string]any{"id":x.ID,"challenge":p.Challenge,"witness":p.Witness,"state":"PENDING"});return}
   fail(w,409,"request already consumed");return
  }
  if _,ok:=s.state.Nodes[x.ID];ok{fail(w,409,"device ID already assigned");return}
  if _,ok:=s.state.Pending[x.ID];ok{fail(w,409,"pending device exists");return}
  for id,d:=range s.state.Nodes{if id!=x.ID&&d.Key==x.PublicKey{fail(w,409,"public key already enrolled");return}}
  challenge,err:=randomHex(24);if err!=nil{fail(w,500,"entropy unavailable");return}
  witness,err:=randomHex(4);if err!=nil{fail(w,500,"entropy unavailable");return}
  s.state.Pending[x.ID]=Pending{Key:x.PublicKey,Challenge:challenge,Witness:witness,Deadline:s.now().Add(10*time.Minute)}
  s.state.Idempotency[idem]=fingerprint
  if err=s.save();err!=nil{fail(w,500,"persistence failure");return}
  response(w,201,map[string]any{"id":x.ID,"challenge":challenge,"witness":witness,"expires_in_seconds":600,"scope":scope,"hardware_verified":false})
 })
 mux.HandleFunc("POST /api/v1/lab/enrollments/{id}/confirm",func(w http.ResponseWriter,r *http.Request){
  if !protected(w,r){return}
  x,ok:=decode(w,r);if !ok{return}
  id:=r.PathValue("id");s.mu.Lock();defer s.mu.Unlock()
  p,ok:=s.state.Pending[id];if !ok{fail(w,404,"pending enrollment missing");return}
  if !s.now().Before(p.Deadline){fail(w,409,"challenge expired");return}
  if subtle.ConstantTimeCompare([]byte(x.Witness),[]byte(p.Witness))!=1{fail(w,403,"witness mismatch");return}
  if !checkSignature(p.Key,x.Signature,enrollDomain+id+"\x00"+p.Challenge){fail(w,403,"device key proof invalid");return}
  n:=Device{ID:id,Key:p.Key,State:"ENROLLED",Revision:1,Verified:false}
  s.state.Nodes[id]=n;delete(s.state.Pending,id)
  s.record(id,"ENROLL",actor(r),1)
  if err:=s.save();err!=nil{fail(w,500,"persistence failure");return}
  response(w,200,n)
 })
 mux.HandleFunc("POST /api/v1/lab/nodes/{id}/actions",func(w http.ResponseWriter,r *http.Request){
  if !protected(w,r){return}
  x,ok:=decode(w,r);if !ok{return}
  id:=r.PathValue("id");s.mu.Lock();defer s.mu.Unlock()
  n,ok:=s.state.Nodes[id];if !ok{fail(w,404,"device absent");return}
  if x.ExpectedRevision!=n.Revision{fail(w,409,"revision conflict");return}
  next:=""
  switch x.Action {
  case "commission":if n.State=="ENROLLED"{next="COMMISSIONED"}
  case "qualify":if n.State=="COMMISSIONED"{next="READY"}
  case "drain":if n.State=="READY"{next="DRAINED"}
  case "resume":if n.State=="DRAINED"{next="READY"}
  case "quarantine":if n.State!="RETIRED"&&n.State!="QUARANTINED"{next="QUARANTINED"}
  case "repair":if n.State=="QUARANTINED"{next="ENROLLED"}
  case "retire":if n.State=="DRAINED"||n.State=="QUARANTINED"{next="RETIRED"}
  }
  if next==""{fail(w,409,"transition forbidden");return}
  n.State=next;n.Revision++;s.state.Nodes[id]=n
  s.record(id,strings.ToUpper(x.Action),actor(r),n.Revision)
  if err:=s.save();err!=nil{fail(w,500,"persistence failure");return}
  response(w,200,n)
 })
 mux.HandleFunc("POST /api/v1/lab/nodes/{id}/rotation-challenge",func(w http.ResponseWriter,r *http.Request){
  if !protected(w,r){return}
  id:=r.PathValue("id");s.mu.Lock();defer s.mu.Unlock()
  n,ok:=s.state.Nodes[id]
  if !ok||n.State=="RETIRED"{fail(w,409,"rotation forbidden");return}
  challenge,err:=randomHex(24);if err!=nil{fail(w,500,"entropy unavailable");return}
  s.state.Rotation[id]=Pending{Challenge:challenge,Deadline:s.now().Add(10*time.Minute)}
  if err=s.save();err!=nil{fail(w,500,"persistence failure");return}
  response(w,200,map[string]any{"challenge":challenge,"expires_in_seconds":600})
 })
 mux.HandleFunc("POST /api/v1/lab/nodes/{id}/rotate-key",func(w http.ResponseWriter,r *http.Request){
  if !protected(w,r){return}
  x,ok:=decode(w,r);if !ok{return}
  id:=r.PathValue("id");s.mu.Lock();defer s.mu.Unlock()
  n,ok:=s.state.Nodes[id];if !ok||n.State=="RETIRED"{fail(w,409,"rotation forbidden");return}
  p,ok:=s.state.Rotation[id];if !ok||!s.now().Before(p.Deadline){fail(w,409,"rotation challenge missing or expired");return}
  if x.ExpectedRevision!=n.Revision{fail(w,409,"revision conflict");return}
  if _,err:=parseKey(x.PublicKey);err!=nil{fail(w,400,"invalid new key");return}
  if x.PublicKey==n.Key{fail(w,409,"same key");return}
  for other,d:=range s.state.Nodes{if other!=id&&d.Key==x.PublicKey{fail(w,409,"key belongs to different node");return}}
  msg:=rotateDomain+id+"\x00"+p.Challenge
  if !checkSignature(n.Key,x.OldSignature,msg)||!checkSignature(x.PublicKey,x.NewSignature,msg){fail(w,403,"dual key proof invalid");return}
  n.Key=x.PublicKey;n.Revision++;s.state.Nodes[id]=n;delete(s.state.Rotation,id)
  s.record(id,"ROTATE_KEY",actor(r),n.Revision)
  if err:=s.save();err!=nil{fail(w,500,"persistence failure");return}
  response(w,200,n)
 })
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Cache-Control","no-store")
  w.Header().Set("X-Content-Type-Options","nosniff")
  w.Header().Set("Referrer-Policy","no-referrer")
  w.Header().Set("X-Frame-Options","DENY")
  mux.ServeHTTP(w,r)
 })
}
func main() {
 bind:=flag.String("bind","127.0.0.1:18085","lab loopback listen address")
 state:=flag.String("state","./wyse-lab-state.json","synthetic state path")
 tokenFile:=flag.String("token-file","","file containing >=32-byte synthetic token")
 flag.Parse()
 host,_,err:=net.SplitHostPort(*bind)
 if err!=nil||net.ParseIP(host)==nil||!net.ParseIP(host).IsLoopback(){log.Fatal("lab refuses non-loopback network bind")}
 if *tokenFile==""{log.Fatal("token-file required")}
 b,err:=os.ReadFile(*tokenFile);if err!=nil{log.Fatal(err)}
 s,err:=newService(*state,[]byte(strings.TrimSpace(string(b))));if err!=nil{log.Fatal(err)}
 log.Printf("PUBLIC SYNTHETIC Wyse lifecycle lab, no physical actions, loopback %s",*bind)
 srv:=&http.Server{Addr:*bind,Handler:s.Handler(),ReadHeaderTimeout:5*time.Second,ReadTimeout:10*time.Second,WriteTimeout:10*time.Second,IdleTimeout:15*time.Second}
 log.Fatal(srv.ListenAndServe())
}

const htmlUI=`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Wyse lifecycle LAB — synthetic only</title><link rel="stylesheet" href="/style.css"></head><body><main><h1>Wyse fleet lifecycle lab</h1><p><strong>PUBLIC SYNTHETIC ONLY.</strong> No physical devices, firmware, disks, TPM, power, TrueNAS or GitHub runners are controlled.</p><label>Lab bearer token <input id="token" type="password" autocomplete="off"></label><button id="refresh">Refresh inventory and audit</button><section aria-label="Enrollment"><h2>Simulated enrollment</h2><label>Device ID <input id="device" value="synthetic-ui-01" pattern="[a-z0-9-]{3,48}"></label><button id="enroll">Generate simulated device key and enroll</button><p>Key lives in this browser tab only; the console witness is simulated, not physical attestation.</p></section><section aria-label="Lifecycle actions"><h2>Lifecycle and rotation</h2><label>Device <select id="node"></select></label><label>Action <select id="action"><option>commission</option><option>qualify</option><option>drain</option><option>resume</option><option>quarantine</option><option>repair</option><option>retire</option></select></label><button id="apply">Apply simulated transition</button><button id="rotate">Rotate simulated key</button></section><p id="result" role="status" aria-live="polite"></p><section><h2>Device inventory</h2><pre id="nodes" aria-live="polite"></pre></section><section><h2>Durable lifecycle receipts</h2><pre id="events" aria-live="polite"></pre></section><p>Automation and agents operate through the <a href="/api/v1/lab/schema">same machine-readable lifecycle contract</a>. Physical mutations remain disabled.</p></main><script src="/app.js"></script></body></html>`
const cssUI=`body{font:16px system-ui,sans-serif;max-width:68rem;margin:2rem auto;padding:0 1rem;line-height:1.5}button,input,select{padding:.5rem;margin:.3rem;border-radius:.25rem}button{cursor:pointer}label{display:inline-flex;align-items:center;gap:.4rem}pre{white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid #888;padding:1rem;border-radius:.5rem}section{margin:1rem 0;padding:.75rem;border:1px solid #999;border-radius:.5rem}#result{min-height:1.3rem;font-weight:600}@media(prefers-color-scheme:dark){body{background:#111;color:#eee}a{color:#8cf}input,select{background:#222;color:#eee}}`
const jsUI=`'use strict';
const el = (id) => document.getElementById(id);
const keypairs = new Map();
let inventory = [];
const result = (message) => { el('result').textContent = message; };
const base64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));
async function api(path, method = 'GET', body = undefined, idem = '') {
  const headers = { 'Authorization': 'Bearer ' + el('token').value, 'X-Actor': 'human' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (idem) headers['Idempotency-Key'] = idem;
  const response = await fetch('/api/v1/lab/' + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const data = await response.json();
  if (!response.ok) throw Error(data.error || ('HTTP ' + response.status));
  return data;
}
async function refresh() {
  const nodes = await api('nodes');
  const events = await api('events');
  inventory = nodes.nodes;
  el('nodes').textContent = JSON.stringify(nodes, null, 2);
  el('events').textContent = JSON.stringify(events, null, 2);
  const selected = el('node').value;
  el('node').replaceChildren(...inventory.map((n) => new Option(n.id + ' / ' + n.state + ' / r' + n.revision, n.id)));
  if (inventory.some((n) => n.id === selected)) el('node').value = selected;
}
async function run(fn) {
  try { await fn(); } catch (error) { result('Failed safely: ' + error.message); }
}
el('refresh').addEventListener('click', () => run(async () => { await refresh(); result('Inventory and events refreshed'); }));
el('enroll').addEventListener('click', () => run(async () => {
  const id = el('device').value.trim();
  if (!/^[a-z0-9-]{3,48}$/.test(id)) throw Error('Invalid synthetic device ID');
  const keys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pub = base64(await crypto.subtle.exportKey('raw', keys.publicKey));
  const claim = await api('enrollments', 'POST', { id, public_key: pub }, crypto.randomUUID());
  const bytes = new TextEncoder().encode('WYSE-LAB-ENROLL-v1\x00' + id + '\x00' + claim.challenge);
  const signature = base64(await crypto.subtle.sign('Ed25519', keys.privateKey, bytes));
  const confirmation = await api('enrollments/' + encodeURIComponent(id) + '/confirm', 'POST', { witness: claim.witness, signature });
  keypairs.set(id, keys);
  await refresh();
  el('node').value = id;
  result('Simulated enrollment accepted: ' + confirmation.id + ' (NOT hardware verified)');
}));
el('apply').addEventListener('click', () => run(async () => {
  const id = el('node').value;
  const node = inventory.find((n) => n.id === id);
  if (!node) throw Error('Select a device');
  const transition = el('action').value;
  const state = await api('nodes/' + encodeURIComponent(id) + '/actions', 'POST', { action: transition, expected_revision: node.revision });
  await refresh();el('node').value = id;
  result('Transition ' + transition + ' → ' + state.state + ' (simulated)');
}));
el('rotate').addEventListener('click', () => run(async () => {
  const id = el('node').value;
  const node = inventory.find((n) => n.id === id);
  if (!node || !keypairs.has(id)) throw Error('This browser tab does not possess the prior synthetic key');
  const challenge = await api('nodes/' + encodeURIComponent(id) + '/rotation-challenge', 'POST');
  const keysNew = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const bytes = new TextEncoder().encode('WYSE-LAB-ROTATE-v1\x00' + id + '\x00' + challenge.challenge);
  const oldSignature = base64(await crypto.subtle.sign('Ed25519', keypairs.get(id).privateKey, bytes));
  const newSignature = base64(await crypto.subtle.sign('Ed25519', keysNew.privateKey, bytes));
  await api('nodes/' + encodeURIComponent(id) + '/rotate-key', 'POST', { public_key: base64(await crypto.subtle.exportKey('raw', keysNew.publicKey)), old_signature: oldSignature, new_signature: newSignature, expected_revision: node.revision });
  keypairs.set(id, keysNew);
  await refresh();el('node').value = id;
  result('Synthetic key rotated with both old/new signatures (NOT TPM attested)');
}));`
