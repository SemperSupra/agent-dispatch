// Public synthetic R11 broker/client/issuer fixture.
// This exercises independently enforced *mock* external effects in an ephemeral
// runner. It is not a production issuer, host security proof, or credential store.
package main

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "sync"
 "time"
)

var allowedMode="unset"
const sock="/ipc/broker.sock"
const trust="/trust"
const state="/state"
const grants="/grants"

type Grant struct {
 Actor string `json:"actor"`
 Sandbox string `json:"sandbox"`
 Mission string `json:"mission"`
 Nonce string `json:"nonce"`
 Epoch uint64 `json:"epoch"`
 Issued int64 `json:"issued"`
 Expires int64 `json:"expires"`
 Capabilities []string `json:"capabilities"`
}
type Token struct {
 Grant Grant `json:"grant"`
 IssuerSignature []byte `json:"issuer_signature"`
 OwnerSignature []byte `json:"owner_signature,omitempty"`
}
type Action struct {
 Token Token `json:"token"`
 Actor string `json:"actor"`
 Sandbox string `json:"sandbox"`
 Mission string `json:"mission"`
 Capability string `json:"capability"`
}
type Ledger struct { Seen map[string]bool `json:"seen"` }
func die(err error) {fmt.Fprintln(os.Stderr, "R11_FIXTURE_ERROR:",err); os.Exit(1)}
func mustWrite(path string,b []byte) error{return os.WriteFile(path,b,0600)}
func serialize(g Grant) []byte {b,_:=json.Marshal(g);return b}
func read(path string)([]byte,error){return os.ReadFile(path)}
func newKey(prefix string)error {
 seed:=make([]byte,ed25519.SeedSize)
 if _,err:=rand.Read(seed);err!=nil{return err}
 sk:=ed25519.NewKeyFromSeed(seed)
 if err:=mustWrite(filepath.Join(trust,prefix+".seed"),seed);err!=nil{return err}
 return mustWrite(filepath.Join(trust,prefix+".pub"),sk.Public().(ed25519.PublicKey))
}
func issuer(args []string)error{
 if len(args)==0{return errors.New("issuer keygen|mint")}
 switch args[0]{
 case "keygen":
  if len(args)!=1{return errors.New("keygen takes no arguments")}
  if err:=newKey("issuer");err!=nil{return err}
  if err:=newKey("owner");err!=nil{return err}
  fmt.Println("R11_SYNTHETIC_SIGNER_KEYS_CREATED_IN_EPHEMERAL_CELL=PASS")
  return nil
 case "mint":
  if len(args)!=6 {return errors.New("mint nonce capability approve epoch file")}
  nonce,cap,approve,sEpoch,file:=args[1],args[2],args[3],args[4],args[5]
  if !strings.HasPrefix(file,"token-")||strings.Contains(file,"/"){return errors.New("token file is not scoped")}
  epoch,err:=strconv.ParseUint(sEpoch,10,64);if err!=nil{return err}
  seed,err:=read(filepath.Join(trust,"issuer.seed"));if err!=nil{return err}
  now:=time.Now().Unix()
  g:=Grant{Actor:"agent-unknown",Sandbox:"ephemeral-r11",Mission:"mock-only",
   Nonce:nonce,Epoch:epoch,Issued:now-60,Expires:now+600,Capabilities:[]string{cap}}
  sk:=ed25519.NewKeyFromSeed(seed)
  token:=Token{Grant:g,IssuerSignature:ed25519.Sign(sk,serialize(g))}
  if approve=="yes"{
   ownerSeed,e:=read(filepath.Join(trust,"owner.seed"));if e!=nil{return e}
   ownerKey:=ed25519.NewKeyFromSeed(ownerSeed)
   token.OwnerSignature=ed25519.Sign(ownerKey,append(serialize(g),[]byte("
owner-approval:"+cap)...))
  } else if approve!="no" {return errors.New("approval must be yes|no")}
  data,_:=json.Marshal(token)
  return mustWrite(filepath.Join(grants,file),data)
 }
 return errors.New("unknown issuer command")
}
func loadPublic(name string)(ed25519.PublicKey,error){
 b,e:=read(filepath.Join(trust,name+".pub"))
 if e!=nil || len(b)!=ed25519.PublicKeySize{return nil,errors.New("invalid synthetic public key")}
 return ed25519.PublicKey(b),nil
}
func check(action Action,issuerKey,ownerKey ed25519.PublicKey)(string,bool){
 g:=action.Token.Grant
 if g.Actor!="agent-unknown"||g.Sandbox!="ephemeral-r11"||g.Mission!="mock-only"||
    action.Actor!=g.Actor||action.Sandbox!=g.Sandbox||action.Mission!=g.Mission||
    g.Nonce==""||g.Expires<=g.Issued||time.Now().Unix()<g.Issued||
    time.Now().Unix()>=g.Expires||len(g.Capabilities)!=1||
    !ed25519.Verify(issuerKey,serialize(g),action.Token.IssuerSignature){return "scope_or_signature",false}
 if g.Capabilities[0]!=action.Capability{return "out_of_scope",false}
 minData,e:=read(filepath.Join(state,"epoch_min"))
 if e!=nil{return "revocation_state_unavailable",false}
 min,e:=strconv.ParseUint(strings.TrimSpace(string(minData)),10,64)
 if e!=nil || g.Epoch<min{return "revoked",false}
 switch action.Capability{
 case "guest.tools","guest.root":
  return "allowed_mock_guest",true
 case "external.synthetic_effect":
  approval:=append(serialize(g),[]byte("
owner-approval:"+action.Capability)...)
  if len(action.Token.OwnerSignature)==0 || !ed25519.Verify(ownerKey,approval,action.Token.OwnerSignature){
   return "owner_approval_required",false
  }
  return "allowed_mock_external",true
 default:
  return "unknown_or_real_resource",false
 }
}
var lock sync.Mutex
func serve()error{
 issuerKey,e:=loadPublic("issuer");if e!=nil{return e}
 ownerKey,e:=loadPublic("owner");if e!=nil{return e}
 if err:=os.Remove(sock);err!=nil && !os.IsNotExist(err){return err}
 listener,e:=net.Listen("unix",sock);if e!=nil{return e}
 if err:=os.Chmod(sock,0666);err!=nil{return err}
 defer listener.Close()
 mux:=http.NewServeMux()
 mux.HandleFunc("/act",func(w http.ResponseWriter,r *http.Request){
  if r.Method!="POST"{http.Error(w,"method",405);return}
  data,e:=io.ReadAll(io.LimitReader(r.Body,16384))
  if e!=nil{http.Error(w,"invalid",400);return}
  var req Action
  if json.Unmarshal(data,&req)!=nil{http.Error(w,"invalid",400);return}
  lock.Lock();defer lock.Unlock()
  why,allowed:=check(req,issuerKey,ownerKey)
  if !allowed{w.WriteHeader(http.StatusForbidden);fmt.Fprint(w,"DENY:"+why);return}
  ledgerFile:=filepath.Join(state,"ledger.json")
  led:=Ledger{Seen:make(map[string]bool)}
  if b,e:=read(ledgerFile);e==nil{
   if json.Unmarshal(b,&led)!=nil||led.Seen==nil{w.WriteHeader(503);fmt.Fprint(w,"DENY:ledger_corrupt");return}
  }else if !os.IsNotExist(e){w.WriteHeader(503);fmt.Fprint(w,"DENY:ledger_missing");return}
  unique:=req.Token.Grant.Actor+"/"+req.Token.Grant.Sandbox+"/"+req.Token.Grant.Nonce
  if led.Seen[unique]{w.WriteHeader(http.StatusForbidden);fmt.Fprint(w,"DENY:replay");return}
  led.Seen[unique]=true
  newData,_:=json.Marshal(led)
  newFile:=ledgerFile+".new"
  if mustWrite(newFile,newData)!=nil || os.Rename(newFile,ledgerFile)!=nil{
   w.WriteHeader(503);fmt.Fprint(w,"DENY:ledger_io");return
  }
  if req.Capability=="external.synthetic_effect" {
   out,e:=os.OpenFile(filepath.Join(state,"effects.log"),os.O_CREATE|os.O_APPEND|os.O_WRONLY,0600)
   if e!=nil{w.WriteHeader(503);fmt.Fprint(w,"DENY:effect_io");return}
   _,e=fmt.Fprintln(out,"SYNTHETIC_ONLY:"+req.Token.Grant.Nonce)
   closeErr:=out.Close()
   if e!=nil || closeErr!=nil {w.WriteHeader(503);fmt.Fprint(w,"DENY:effect_write");return}
  }
  fmt.Fprint(w,"ALLOW:"+why)
 })
 fmt.Println("R11_BROKER_SOCKET_READY=PASS")
 return http.Serve(listener,mux)
}
func client(args []string)error{
 if len(args)<3{return errors.New("client TOKENFILE CAPABILITY EXPECT [tamper|wrong_actor]")}
 file,cap,expected:=args[0],args[1],args[2]
 if !strings.HasPrefix(file,"token-")||strings.Contains(file,"/"){return errors.New("invalid grant ref")}
 b,e:=read(filepath.Join(grants,file));if e!=nil{return e}
 var t Token
 if e=json.Unmarshal(b,&t);e!=nil{return e}
 a:=Action{Token:t,Actor:"agent-unknown",Sandbox:"ephemeral-r11",Mission:"mock-only",Capability:cap}
 if len(args)>3 {
  switch args[3]{
  case "tamper":a.Token.Grant.Nonce="modified-by-guest"
  case "wrong_actor":a.Actor="other-agent"
  default:return errors.New("unexpected negative probe")
  }
 }
 transport:=&http.Transport{DialContext:func(_ context.Context,_,_ string)(net.Conn,error){
  return net.DialTimeout("unix",sock,3*time.Second)
 }}
 hc:=&http.Client{Transport:transport,Timeout:5*time.Second}
 body,_:=json.Marshal(a)
 resp,e:=hc.Post("http://synthetic-broker/act","application/json",strings.NewReader(string(body)))
 if e!=nil{return e}
 defer resp.Body.Close()
 response,e:=io.ReadAll(io.LimitReader(resp.Body,256))
 if e!=nil{return e}
 got:="DENY";if resp.StatusCode==200{got="ALLOW"}
 if got!=expected{return fmt.Errorf("R11_EXPECTED_%s_GOT_%s: %s",expected,got,string(response))}
 fmt.Printf("R11_INDEPENDENT_BROKER_%s=PASS CAP=%s
",got,cap)
 return nil
}
func main(){
 if len(os.Args)<2{die(errors.New("need keygen|mint|serve|client"))}
 mode:=os.Args[1]
 if mode=="keygen"||mode=="mint"{if allowedMode!="issuer"{die(errors.New("issuer denied"))};if e:=issuer(os.Args[1:]);e!=nil{die(e)};return}
 if mode=="serve"{if allowedMode!="broker"{die(errors.New("broker denied"))};if e:=serve();e!=nil{die(e)};return}
 if mode=="client"{if allowedMode!="client"{die(errors.New("client denied"))};if e:=client(os.Args[2:]);e!=nil{die(e)};return}
 die(errors.New("unknown mode"))
}
