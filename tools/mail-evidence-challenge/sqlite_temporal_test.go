package evidence

import (
    "encoding/json"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "testing"
)

type sqliteTemporalReceipt struct {
    Schema string `json:"schema"`
    Classification string `json:"classification"`
    SQLiteVersion string `json:"sqlite_version"`
    QualifiedCases int `json:"qualified_cases"`
    SourceOccurrences int `json:"source_occurrences"`
    ClaimObservations int `json:"claim_observations"`
    UniqueSourceLineages int `json:"unique_source_lineages"`
    AssessmentHistoryRows int `json:"assessment_history_rows"`
    FourValuedVerdicts []string `json:"four_valued_verdicts"`
    RetrospectiveQueryVerified bool `json:"retrospective_query_verified"`
    ConflictPreserved bool `json:"conflict_preserved"`
    HistoricalReplayVerified bool `json:"historical_replay_verified"`
    ReacquisitionNotIndependentVote bool `json:"reacquisition_not_independent_vote"`
    ImmutableSourceGuard bool `json:"immutable_source_guard"`
    IndexUsed bool `json:"index_used"`
    ModelInference bool `json:"model_inference"`
    NativePSTQualified bool `json:"native_pst_qualified"`
    SourceFixtureSHA256 string `json:"source_fixture_sha256"`
    PolicySHA256 string `json:"policy_sha256"`
}

// This executes the system's real embedded SQLite engine, via Python's
// standard-library sqlite3 binding, NOT a simulated SQL or Go state machine.
// Both interpreter and database are disposable; no network or personal mail.
func TestNativeSQLiteBitemporalProjection(t *testing.T) {
    if _, err := exec.LookPath("python3"); err != nil {
        t.Fatal("required standard python3/sqlite3 runner unavailable:", err)
    }
    root := t.TempDir()
    script := filepath.Join("temporal_sqlite", "qualify.py")
    if _, err := os.Stat(script); err != nil { t.Fatal(err) }
    command := exec.Command("python3", "-B", script)
    command.Dir = "."
    command.Env = []string{
        "PATH=/usr/local/bin:/usr/bin:/bin", "PYTHONNOUSERSITE=1",
        "PYTHONHASHSEED=0", "HOME=" + root, "LANG=C.UTF-8",
    }
    out, err := command.CombinedOutput()
    if err != nil { t.Fatalf("native SQLite witness failed (%v): %s",err,out) }
    if len(out)>8192 { t.Fatal("unexpected output length") }
    var result sqliteTemporalReceipt
    if err := json.Unmarshal(out,&result); err != nil { t.Fatal("invalid native receipt",err) }
    if result.Schema!="mail-temporal-sqlite-public-r1" ||
        result.Classification!="SQLITE_NATIVE_BITEMPORAL_PROJECTION_ONLY" ||
        result.QualifiedCases!=8 || result.SourceOccurrences!=6 ||
        result.ClaimObservations!=6 || result.UniqueSourceLineages!=5 ||
        result.AssessmentHistoryRows!=2 ||
        !result.RetrospectiveQueryVerified || !result.ConflictPreserved ||
        !result.HistoricalReplayVerified || !result.ReacquisitionNotIndependentVote ||
        !result.ImmutableSourceGuard || !result.IndexUsed ||
        result.ModelInference || result.NativePSTQualified ||
        len(result.SourceFixtureSHA256)!=64 || len(result.PolicySHA256)!=64 {
        t.Fatalf("native SQL oracle drift: %+v",result)
    }
    for _,status:=range []string{"BOTH","NEITHER","REFUTED","SUPPORTED"}{
        if !strings.Contains(strings.Join(result.FourValuedVerdicts,","),status) {
            t.Fatalf("four-valued state %s absent from test scenarios",status)
        }
    }
}
