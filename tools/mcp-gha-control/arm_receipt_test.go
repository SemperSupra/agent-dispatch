package main

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func armFixture(t *testing.T) (string, string, Receipt) {
 t.Helper()
 dir:=t.TempDir()
 cipher:=filepath.Join(dir,"result.age")
 payload:=[]byte("age ciphertext structure is not inspected by hash-only verifier")
 if e:=os.WriteFile(cipher,payload,0600);e!=nil{t.Fatal(e)}
 hash:=sha256.Sum256(payload)
 zero:=int64(0)
 truth:=true
 r:=Receipt{
  Schema:"mcp-gha-sealed-arm-receipt/v1",
  Arm:"reference",
  ResearchStatus:"SYNTHETIC_TRANSPORT_ONLY_NOT_BLIND_RESEARCH",
  SourceSHA:strings.Repeat("a",40),
  RunID:"40506152579",
  RunAttempt:"1",
  PlanSHA256:strings.Repeat("b",64),
  ProviderImageDigest:"ghcr.io/searxng/searxng:2026.10.23-629368e40@sha256:"+strings.Repeat("c",64),
  ConfigSHA256:strings.Repeat("d",64),
  TerminalState:"RETRIEVAL_PASS",
  Attempted:3,Succeeded:3,Failed:0,
  ImagePullMS:&zero,ProviderReadyMS:&zero,GoBuildMS:&zero,PrewarmedImageVerifyMS:&zero,
  RunnerPreparedOnce:&truth,
  CiphertextSHA256:hex.EncodeToString(hash[:]),
  CiphertextBytes:int64(len(payload)),
 }
 receipt:=filepath.Join(dir,"receipt.json")
 saveReceipt(t,receipt,r)
 return receipt,cipher,r
}
func saveReceipt(t *testing.T,path string,receipt Receipt){
 t.Helper()
 data,e:=json.Marshal(receipt)
 if e!=nil{t.Fatal(e)}
 if e:=os.WriteFile(path,data,0600);e!=nil{t.Fatal(e)}
}
func TestPerArmMailboxIsVerifiableWithoutClaimingCPEAuthority(t *testing.T){
 receipt,cipher,r:=armFixture(t)
 v,e:=verifyBound(receipt,cipher,r.RunID,r.Arm)
 if e!=nil{t.Fatal(e)}
 if !v.CiphertextVerified||v.Arm!="reference"||v.RunID!=r.RunID||
 v.ReceiptTrust!="SELF_REPORTED_UNAUTHENTICATED_NEEDS_NATIVE_RUN_AND_PRIVATE_INGEST"||
 v.ArtifactState!="CIPHERTEXT_DIGEST_MATCH_ONLY_NOT_DECRYPTED"||
 v.ScienceState!="SYNTHETIC_ONLY_NO_CPE_AUTHORITY_OR_ADJUDICATION"{t.Fatalf("unsupported authority: %+v",v)}
}
func TestPerArmMailboxNegativeBoundaries(t *testing.T){
 originalReceipt,cipher,original:=armFixture(t)
 for _,test:=range []struct{name string;edit func(*Receipt)}{
  {"arm-swapped",func(r *Receipt){r.Arm="cpe"}},
  {"run-swapped",func(r *Receipt){r.RunID="40506152580"}},
  {"run-attempt-invalid",func(r *Receipt){r.RunAttempt="0"}},
  {"unknown-arm",func(r *Receipt){r.Arm="both"}},
  {"research-promoted",func(r *Receipt){r.ResearchStatus="VALIDATED_CPE"}},
  {"wrong-image",func(r *Receipt){r.ProviderImageDigest="not-a-pinned-image"}},
  {"provider-missing",func(r *Receipt){r.ProviderReadyMS=nil}},
  {"metrics-negative",func(r *Receipt){v:=int64(-1);r.GoBuildMS=&v}},
  {"success-lie",func(r *Receipt){r.Failed=1;r.Succeeded=2}},
  {"bad-cipher-digest",func(r *Receipt){r.CiphertextSHA256=strings.Repeat("e",64)}},
  {"invalid-sha",func(r *Receipt){r.SourceSHA="invalid"}},
  {"extra-requests",func(r *Receipt){r.Attempted=4;r.Succeeded=4}},
  {"unknown-schema",func(r *Receipt){r.Schema="mcp-gha-sealed-arm-receipt/v2"}},
  {"false-science",func(r *Receipt){r.ScienceValid=true}},
 }{
  t.Run(test.name,func(t *testing.T){
   receipt:=filepath.Join(t.TempDir(),"receipt.json")
   current:=original
   test.edit(&current)
   saveReceipt(t,receipt,current)
   if _,e:=verifyBound(receipt,cipher,original.RunID,original.Arm);e==nil{
    t.Fatalf("accepted incorrect mailbox: %+v",current)
   }
  })
 }
 if _,e:=verifyBound(originalReceipt,cipher,"40506152580","reference");e==nil{t.Fatal("expected run ID not enforced")}
 if _,e:=verifyBound(originalReceipt,cipher,original.RunID,"cpe");e==nil{t.Fatal("expected arm not enforced")}
}
