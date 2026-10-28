package main
import(
 "crypto/hmac"
 "crypto/sha256"
 "encoding/hex"
 "fmt"
 "strings"
 "testing"
)
const webhookRepository="synthetic-public/fixture"
const webhookWorkflow=".github/workflows/public-test.yml"
const webhookDelivery="a10f60d4-9e87-42af-80ff-001122334455"
const webhookSecret="synthetic-qualification-secret-long-enough"
func makeWebhook()([]byte,string){
 body:=[]byte(fmt.Sprintf(`{"action":"completed","repository":{"full_name":"%s"},"workflow_run":{"id":10001,"path":"%s","event":"pull_request","run_attempt":1,"head_sha":"%s","conclusion":"failure"}}`,webhookRepository,webhookWorkflow,sampleSHA))
 mac:=hmac.New(sha256.New,[]byte(webhookSecret));_,_=mac.Write(body)
 return body,"sha256="+hex.EncodeToString(mac.Sum(nil))
}
func TestWebhookAuthenticatedObservation(t *testing.T){
 b,s:=makeWebhook();g:=new(WebhookGate)
 r,e:=g.Observe([]byte(webhookSecret),webhookRepository,webhookWorkflow,"pull_request","workflow_run",webhookDelivery,s,b)
 if e!=nil{t.Fatal(e)};if r.Schema!="gha-webhook-observation/v1"||r.Workflow!=webhookWorkflow||r.RunID!=10001||r.Attempt!=1||r.Conclusion!="failure"{t.Fatal(r)}
 if _,e=g.Observe([]byte(webhookSecret),webhookRepository,webhookWorkflow,"pull_request","workflow_run",webhookDelivery,s,b);e==nil{t.Fatal("duplicate event accepted")}
}
func TestWebhookRejectsBadSignatureRepoAndBody(t *testing.T){
 b,s:=makeWebhook()
 cases:=[]struct{name,repo,event,id,sig string;body []byte;secret string}{
  {"wrong-secret",webhookRepository,"workflow_run",webhookDelivery,s,b,"not-the-same-synthetic-secret"},
  {"wrong-repo","other-public/fixture","workflow_run",webhookDelivery,s,b,webhookSecret},
  {"wrong-event",webhookRepository,"issue_comment",webhookDelivery,s,b,webhookSecret},
  {"bad-id",webhookRepository,"workflow_run","123",s,b,webhookSecret},
  {"bad-signature",webhookRepository,"workflow_run",webhookDelivery,"sha256="+strings.Repeat("0",64),b,webhookSecret},
  {"too-large",webhookRepository,"workflow_run",webhookDelivery,s,[]byte(strings.Repeat("z",65537)),webhookSecret},
  {"unsupported-action",webhookRepository,"workflow_run",webhookDelivery,s,[]byte(strings.Replace(string(b),"completed","queued",1)),webhookSecret},
  {"wrong-sha",webhookRepository,"workflow_run",webhookDelivery,s,[]byte(strings.Replace(string(b),sampleSHA,"",1)),webhookSecret},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  g:=new(WebhookGate)
  if _,e:=g.Observe([]byte(tc.secret),tc.repo,webhookWorkflow,"pull_request",tc.event,tc.id,tc.sig,tc.body);e==nil{t.Fatal("unauthorized event accepted")}
 })}
}
func TestWebhookRejectsAuthenticatedUnsupportedAction(t *testing.T){
 b,_:=makeWebhook();b=[]byte(strings.Replace(string(b),`"completed"`,`"queued"`,1))
 mac:=hmac.New(sha256.New,[]byte(webhookSecret));_,_=mac.Write(b)
 s:="sha256="+hex.EncodeToString(mac.Sum(nil))
 if _,e:=new(WebhookGate).Observe([]byte(webhookSecret),webhookRepository,webhookWorkflow,"pull_request","workflow_run",webhookDelivery,s,b);e==nil{t.Fatal("queued event accepted")}
}

func TestWebhookDenyWrongWorkflowAndDuplicateAttempt(t *testing.T){
 b,s:=makeWebhook()
 g:=new(WebhookGate)
 if _,e:=g.Observe([]byte(webhookSecret),webhookRepository,
  "other-public-workflow.yml","pull_request","workflow_run",webhookDelivery,s,b);e==nil{
  t.Fatal("signed unrelated workflow accepted")
 }
 if _,e:=g.Observe([]byte(webhookSecret),webhookRepository,
  webhookWorkflow,"workflow_dispatch","workflow_run",webhookDelivery,s,b);e==nil{
  t.Fatal("unadmitted triggering event accepted")
 }
 if _,e:=g.Observe([]byte(webhookSecret),webhookRepository,
  webhookWorkflow,"pull_request","workflow_run",webhookDelivery,s,b);e!=nil{t.Fatal(e)}
 differentDelivery:="b10f60d4-9e87-42af-80ff-001122334455"
 if _,e:=g.Observe([]byte(webhookSecret),webhookRepository,
  webhookWorkflow,"pull_request","workflow_run",differentDelivery,s,b);e==nil{
  t.Fatal("duplicate run/attempt via new delivery ID accepted")
 }
}

// Even with a correct HMAC, a duplicate-key payload must not be parsed by
// conflicting first-value/last-value consumers.
func TestWebhookRejectsAuthenticatedDuplicateJSONKeys(t *testing.T) {
 original,_:=makeWebhook()
 cases:=[]struct{name,needle,replacement string}{
  {"outer-action",`"action":`,`"action":"queued","action":`},
  {"outer-action-alias",`"action":`,`"action":"queued","Action":`},
  {"nested-run-id",`"id":10001`,`"id":-9,"id":10001`},
  {"nested-run-id-alias",`"id":10001`,`"id":-9,"ID":10001`},
  {"nested-origin",`"full_name":`,`"full_name":"synthetic-other/fixture","full_name":`},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  changed:=strings.Replace(string(original),tc.needle,tc.replacement,1)
  if changed==string(original){t.Fatal("fixture anchor absent")}
  raw:=[]byte(changed)
  mac:=hmac.New(sha256.New,[]byte(webhookSecret))
  _,_=mac.Write(raw)
  signature:="sha256="+hex.EncodeToString(mac.Sum(nil))
  if _,e:=new(WebhookGate).Observe([]byte(webhookSecret),webhookRepository,webhookWorkflow,
   "pull_request","workflow_run",webhookDelivery,signature,raw);e==nil{
   t.Fatal("authenticated ambiguous duplicate-key webhook accepted")
  }
 })}
}
