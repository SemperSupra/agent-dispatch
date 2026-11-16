package red

import (
 "encoding/json"
 "os"
 "testing"
)

type Case struct {
 ID string `json:"id"`
 Priority string `json:"priority"`
 Boundary string `json:"boundary"`
 Expected string `json:"expected"`
 Oracle string `json:"oracle"`
 ImplementationStatus string `json:"implementation_status"`
}
type Corpus struct {
 Schema int `json:"schema"`
 Scope string `json:"scope"`
 Cases []Case `json:"cases"`
}
func TestAdversarialCorpusIntegrity(t *testing.T) {
 b,e:=os.ReadFile("attack-cases.json");if e!=nil{t.Fatal(e)}
 var c Corpus
 if e=json.Unmarshal(b,&c);e!=nil{t.Fatal(e)}
 if c.Schema!=1 || len(c.Cases)<15 {t.Fatal("insufficient corpus or incompatible schema")}
 seen:=map[string]bool{}
 byBoundary:=map[string]bool{}
 for _,a:=range c.Cases{
  if a.ID==""||a.Oracle==""||a.Boundary==""||seen[a.ID]{t.Fatalf("missing/duplicate case %+v",a)}
  seen[a.ID]=true;byBoundary[a.Boundary]=true
  if a.Priority!="P0"&&a.Priority!="P1"{t.Fatalf("invalid risk priority %s",a.ID)}
  switch a.Expected{case "deny","hold","quarantine":default:t.Fatalf("invalid expected result %s",a.ID)}
  if a.ImplementationStatus!="fixture_only"{t.Fatalf("unsupported exploit claim %s",a.ID)}
 }
 for _,b:=range []string{"api","control","lease","recovery","discovery","capture","lifecycle","transport","storage","topology","policy"}{
  if !byBoundary[b]{t.Fatalf("missing trust boundary %s",b)}
 }
 t.Logf("R26_RED_CORPUS_VALIDATED=%d (NOT target-system security qualification)",len(c.Cases))
}
