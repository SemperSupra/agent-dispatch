package main

// Transport-only webhook authenticating a GitHub workflow_run completed event.
// No runner dispatch or declassification, no network listener, no credential logs.
import (
 "crypto/hmac"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "io"
 "bytes"
 "regexp"
 "sync"
)
type WebhookObservation struct{
 Schema string "json:\"schema\""
 DeliveryID string "json:\"delivery_id\""
 RunID int64 "json:\"run_id\""
 Attempt int64 "json:\"attempt\""
 HeadSHA string "json:\"head_sha\""
 Conclusion string "json:\"conclusion\""
}
type webhookPayload struct{
 Action string "json:\"action\""
 WorkflowRun struct{
  ID int64 "json:\"id\""
  RunAttempt int64 "json:\"run_attempt\""
  HeadSHA string "json:\"head_sha\""
  Conclusion string "json:\"conclusion\""
 } "json:\"workflow_run\""
}
type WebhookGate struct{ mu sync.Mutex; seen map[string]struct{} }
var deliveryIDOK=regexp.MustCompile("^[a-fA-F0-9-]{30,40}$")
func (g *WebhookGate)Observe(secret []byte, event,deliveryID,signature string,payload []byte)(WebhookObservation,error){
 fail:=func() (WebhookObservation,error){return WebhookObservation{},errors.New("unauthorized or malformed webhook")}
 if len(secret)<24||len(payload)==0||len(payload)>65536||event!="workflow_run"||
  !deliveryIDOK.MatchString(deliveryID)||len(signature)!=71||signature[:7]!="sha256="{return fail()}
 provided,e:=hex.DecodeString(signature[7:]);if e!=nil||len(provided)!=sha256.Size{return fail()}
 mac:=hmac.New(sha256.New,secret);_,_=mac.Write(payload)
 if !hmac.Equal(mac.Sum(nil),provided){return fail()}
 var p webhookPayload
 d:=json.NewDecoder(bytes.NewReader(payload))
 if e:=d.Decode(&p);e!=nil{return fail()}
 var v any;if d.Decode(&v)!=io.EOF{return fail()}
 if p.Action!="completed"||p.WorkflowRun.ID<=0||p.WorkflowRun.RunAttempt<=0||
  !shaOK.MatchString(p.WorkflowRun.HeadSHA)||
  (p.WorkflowRun.Conclusion!="success"&&p.WorkflowRun.Conclusion!="failure"&&p.WorkflowRun.Conclusion!="cancelled"){
  return fail()
 }
 g.mu.Lock();defer g.mu.Unlock()
 if g.seen==nil{g.seen=map[string]struct{}{}}
 if _,exists:=g.seen[deliveryID];exists{return WebhookObservation{},errors.New("duplicate delivery")}
 g.seen[deliveryID]=struct{}{}
 return WebhookObservation{Schema:"gha-webhook-observation/v1",DeliveryID:deliveryID,RunID:p.WorkflowRun.ID,
  Attempt:p.WorkflowRun.RunAttempt,HeadSHA:p.WorkflowRun.HeadSHA,Conclusion:p.WorkflowRun.Conclusion},nil
}
