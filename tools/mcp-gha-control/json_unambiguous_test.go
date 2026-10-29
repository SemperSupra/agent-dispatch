package main

import (
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestPairManifestRejectsRecursiveDuplicateAndCaseAlias(t *testing.T) {
 manifest,_,_:=pairedFixture(t)
 original,err:=os.ReadFile(manifest);if err!=nil{t.Fatal(err)}
 good:=string(original)
 if _,err=readPairPlan(manifest);err!=nil{t.Fatalf("valid fixture rejected: %v",err)}
 for _,tc:=range []struct{name string;old string;rewrite string}{
  {"duplicate-schema",`"schema":`,`"schema":"mcp-gha-private-pair-preflight/v2","schema":`},
  {"case-alias-schema",`"schema":`,`"Schema":"mcp-gha-private-pair-preflight/v2","schema":`},
  {"unicode-escaped-alias",`"schema":`,`"sch\u0065ma":"mcp-gha-private-pair-preflight/v2","schema":`},
  {"nested-job-alias",`"job_id":`,`"Job_ID":"123","job_id":`},
  {"nested-plan-duplicate",`"plan_sha256":`,`"plan_sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","plan_sha256":`},
  {"nested-arm-alias",`"arm":`,`"Arm":"cpe","arm":`},
 }{
  t.Run(tc.name,func(t *testing.T){
   if !strings.Contains(good,tc.old){t.Fatalf("fixture missing %q",tc.old)}
   bad:=strings.Replace(good,tc.old,tc.rewrite,1)
   path:=filepath.Join(t.TempDir(),"ambiguous.json")
   if err:=os.WriteFile(path,[]byte(bad),0600);err!=nil{t.Fatal(err)}
   if _,err:=readPairPlan(path);err==nil{t.Fatal("ambiguous manifest accepted")}
  })
 }
}
func TestPairManifestRejectsDeepAndTrailingJSON(t *testing.T){
 examples:=[]string{
  strings.Repeat("[",33)+"0"+strings.Repeat("]",33),
  `{"schema":"x"}{"schema":"y"}`,
  `{"schema":"x",}`,
 }
 for _,raw:=range examples{
  if err:=rejectAmbiguousPairJSON([]byte(raw));err==nil{t.Fatalf("unsafe JSON accepted: %.40s",raw)}
 }
}
func TestPairManifestAcceptsNormalNestedStructure(t *testing.T){
 valid:=`{"arms":[{"arm":"reference","metadata":{"author":"x","ids":[1,2,3]}},{"arm":"cpe","metadata":{}}],"count":2}`
 if err:=rejectAmbiguousPairJSON([]byte(valid));err!=nil{t.Fatal(err)}
}

func TestPairManifestUnicodeSimpleFoldDifferential(t *testing.T){
 // Standard Go typed JSON accepts long-s as equivalent to ASCII s in
 // a struct field name. ToLower alone does not detect this alias.
 raw:=[]byte(`{"schema":"safe","ſchema":"swapped"}`)
 if strings.ToLower("schema")==strings.ToLower("ſchema"){
  t.Fatal("test would not discriminate lowercasing from EqualFold")
 }
 if !strings.EqualFold("schema","ſchema"){
  t.Fatal("Go unicode folding precondition changed")
 }
 var ordinary struct{Schema string `json:"schema"`}
 if err:=json.Unmarshal(raw,&ordinary);err!=nil||ordinary.Schema!="swapped"{
  t.Fatalf("typed decoder not vulnerable to alias in test environment: %+v %v",ordinary,err)
 }
 if err:=rejectAmbiguousPairJSON(raw);err==nil{t.Fatal("Unicode simple-fold duplicate accepted")}
}

func TestPairManifestRejectsExcessObjectKeys(t *testing.T){
 parts:=make([]string,0,65)
 for i:=0;i<65;i++{parts=append(parts,fmt.Sprintf(`"k%d":%d`,i,i))}
 raw:="{"+strings.Join(parts,",")+"}"
 if err:=rejectAmbiguousPairJSON([]byte(raw));err==nil{t.Fatal("oversized JSON object key count accepted")}
}
