package main
import (
 "context"
 "encoding/json"
 "os"
 "testing"
 "time"
 "net/http"
)
func TestAuthenticatedLiveGithubDraftAncestry(t *testing.T){
 if os.Getenv("R27_E15_REQUIRE_LIVE")!="1"{t.Skip("explicit GitHub API qualification job only")}
 token:=os.Getenv("GH_TOKEN")
 if token==""{t.Fatal("GitHub token required for live provenance qualification")}
 dir:=os.Getenv("R27_E15_INVENTORY")
 if dir==""{t.Fatal("source-pinned inventory file missing")}
 raw,err:=os.ReadFile(dir);if err!=nil{t.Fatal(err)}
 var m Manifest;if err=json.Unmarshal(raw,&m);err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithTimeout(context.Background(),60*time.Second);defer cancel()
 source:=Source{Endpoint:"https://api.github.com",Token:token,HTTP:&http.Client{Timeout:15*time.Second}}
 if err=verify(ctx,source,m);err!=nil{t.Fatal(err)}
 t.Logf("R27_E15_LIVE_DRAFT_PR_ANCESTRY=PASS count=%d",len(m.Nodes))
 t.Log("R27_E15_ACTUAL_GIT_MERGE_BASE=NOT_TESTED")
 t.Log("R27_E15_RELEASE_ADMISSION=BLOCKED")
}
