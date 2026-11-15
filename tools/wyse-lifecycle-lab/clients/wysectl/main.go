// wysectl is a synthetic-only, external API client for independently testing
// the same enrollment lifecycle as the human browser. Never use with real nodes.
package main
import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "net/http"
 "net/url"
 "os"
 "strings"
 "time"
)
type client struct {base,token,actor string; http *http.Client}
func (c client) call(method,path string,body any,idem string)(map[string]any,error){
 var b io.Reader
 if body!=nil {buf,err:=json.Marshal(body);if err!=nil{return nil,err};b=bytes.NewReader(buf)}
 req,err:=http.NewRequest(method,c.base+"/api/v1/lab/"+path,b);if err!=nil{return nil,err}
 req.Header.Set("X-Actor",c.actor)
 req.Header.Set("Authorization","Bearer "+c.token)
 if body!=nil{req.Header.Set("Content-Type","application/json")}
 if idem!=""{req.Header.Set("Idempotency-Key",idem)}
 resp,err:=c.http.Do(req);if err!=nil{return nil,err}
 defer resp.Body.Close()
 var payload map[string]any
 err=json.NewDecoder(io.LimitReader(resp.Body,16384)).Decode(&payload)
 if err!=nil{return nil,err}
 if resp.StatusCode<200||resp.StatusCode>=300{return nil,fmt.Errorf("%s %s: HTTP %d: %v",method,path,resp.StatusCode,payload["error"])}
 return payload,nil
}
func str(m map[string]any,k string)string {s,_:=m[k].(string);return s}
func rev(m map[string]any)int64 {f,_:=m["revision"].(float64);return int64(f)}
func sig(priv ed25519.PrivateKey,msg string)string {return base64.StdEncoding.EncodeToString(ed25519.Sign(priv,[]byte(msg)))}
func run(c client,id string)error {
 schema,err:=c.call("GET","schema",nil,"");if err!=nil{return err}
 if schema["hardware_verified"]!=false||schema["real_garm_admission"]!=false||schema["physical_mutation"]!=false{return errors.New("lab hardware safety flags not false")}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{return err}
 nonce:=make([]byte,16);if _,err=rand.Read(nonce);err!=nil{return err}
 first,err:=c.call("POST","enrollments",map[string]any{"id":id,"public_key":base64.StdEncoding.EncodeToString(pub)},hex.EncodeToString(nonce));if err!=nil{return err}
 challenge,witness:=str(first,"challenge"),str(first,"witness")
 confirm,err:=c.call("POST","enrollments/"+id+"/confirm",map[string]any{"witness":witness,"signature":sig(priv,"WYSE-LAB-ENROLL-v1\x00"+id+"\x00"+challenge)},"");if err!=nil{return err}
 if str(confirm,"state")!="ENROLLED"||rev(confirm)!=1{return errors.New("enrollment oracle failed")}
 steps:=[]struct{action,state string}{
  {"commission","COMMISSIONED"},{"qualify","READY"},
  {"drain","DRAINED"},{"resume","READY"},
  {"quarantine","QUARANTINED"},{"repair","ENROLLED"},
  {"commission","COMMISSIONED"},{"qualify","READY"},
  {"drain","DRAINED"},{"retire","RETIRED"},
 }
 current:=confirm
 for i,step:=range steps {
  if i==2 {
   rotation,err:=c.call("POST","nodes/"+id+"/rotation-challenge",nil,"");if err!=nil{return err}
   newPub,newPriv,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{return e}
   msg:="WYSE-LAB-ROTATE-v1\x00"+id+"\x00"+str(rotation,"challenge")
   changed,e:=c.call("POST","nodes/"+id+"/rotate-key",map[string]any{
     "public_key":base64.StdEncoding.EncodeToString(newPub),
     "old_signature":sig(priv,msg),"new_signature":sig(newPriv,msg),
     "expected_revision":rev(current),
   },"");if e!=nil{return e}
   current=changed;priv=newPriv
  }
  updated,e:=c.call("POST","nodes/"+id+"/actions",map[string]any{"action":step.action,"expected_revision":rev(current)},"")
  if e!=nil{return e}
  if str(updated,"state")!=step.state{return fmt.Errorf("expected %s actual %s",step.state,str(updated,"state"))}
  current=updated
 }
 nodes,err:=c.call("GET","nodes",nil,"");if err!=nil{return err}
 found:=false
 for _,entry:=range nodes["nodes"].([]any){n:=entry.(map[string]any);if str(n,"id")==id&&str(n,"state")=="RETIRED"&&n["hardware_verified"]==false{found=true}}
 if !found{return errors.New("final inventory oracle failed")}
 ev,err:=c.call("GET","events",nil,"");if err!=nil{return err}
 count:=0
 for _,entry:=range ev["events"].([]any){e:=entry.(map[string]any);if str(e,"device_id")==id&&str(e,"actor")==c.actor{count++}}
 if count<12{return fmt.Errorf("audit receipts missing: %d",count)}
 fmt.Printf("EXTERNAL_%s_ENROLL_SIGN_ROTATE_ALL_TRANSITIONS_RETIRE=PASS\n",strings.ToUpper(c.actor))
 fmt.Printf("EXTERNAL_%s_AGENT_API_DURABLE_EVENTS=PASS\n",strings.ToUpper(c.actor))
 return nil
}
func main(){
 base:=flag.String("url","http://127.0.0.1:18085","loopback-only lab URL")
 tokenPath:=flag.String("token-file","","ephemeral lab bearer token file")
 actor:=flag.String("actor","automation","automation or agent")
 id:=flag.String("id","synthetic-api-01","synthetic device identifier")
 flag.Parse()
 parsed,err:=url.Parse(*base)
 if err!=nil||parsed.Scheme!="http"||parsed.Hostname()!="127.0.0.1"{fmt.Fprintln(os.Stderr,"refuse non-loopback lab target");os.Exit(2)}
 if *actor!="automation"&&*actor!="agent"{fmt.Fprintln(os.Stderr,"use automation or agent");os.Exit(2)}
 if *tokenPath==""{fmt.Fprintln(os.Stderr,"token file required");os.Exit(2)}
 secret,err:=os.ReadFile(*tokenPath);if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(2)}
 c:=client{base:strings.TrimSuffix(*base,"/"),token:strings.TrimSpace(string(secret)),actor:*actor,http:&http.Client{Timeout:8*time.Second}}
 if err=run(c,*id);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
}
