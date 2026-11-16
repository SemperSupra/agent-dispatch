package evidence

import (
    "encoding/json"
    "math/rand"
    "os"
    "path/filepath"
    "reflect"
    "strings"
    "testing"
)

func cloneFixture(t *testing.T) Ledger {
    t.Helper()
    raw,err:=json.Marshal(Fixture())
    if err!=nil{t.Fatal(err)}
    var result Ledger
    if err:=json.Unmarshal(raw,&result);err!=nil{t.Fatal(err)}
    return result
}

func TestMetamorphicOriginalSourceOrderingDoesNotChangeGroundTruth(t *testing.T) {
    baseline:=Fixture()
    if err:=baseline.Validate();err!=nil{t.Fatal(err)}
    gold,err:=ReadGold("testdata/gold.json")
    if err!=nil{t.Fatal(err)}
    expected:=make([]Answer,len(gold))
    for index,card:=range gold {
        expected[index],err=baseline.Answer(card.Question)
        if err!=nil{t.Fatal(err)}
    }
    for seed:=int64(1);seed<=32;seed++ {
        copy:=cloneFixture(t)
        rand.New(rand.NewSource(seed)).Shuffle(len(copy.Observations),func(i,j int){
            copy.Observations[i],copy.Observations[j]=copy.Observations[j],copy.Observations[i]
        })
        if err:=copy.Validate();err!=nil{t.Fatalf("seed %d: %v",seed,err)}
        if copy.Digest()!=baseline.Digest(){t.Fatalf("seed %d changed corpus digest",seed)}
        for i,card:=range gold {
            answer,err:=copy.Answer(card.Question)
            if err!=nil{t.Fatalf("seed %d case %d: %v",seed,i,err)}
            if !reflect.DeepEqual(answer,expected[i]) {
                t.Fatalf("source order changed answer for %s seed %d: %+v vs %+v",
                    card.Question.ID,seed,answer,expected[i])
            }
        }
    }
}

func TestSourceInvariantsRejectEightIndependentCorruptionClasses(t *testing.T) {
    tests:=[]struct{
        name string
        reason string
        mutate func(*Ledger)
    }{
        {"native-locator-aliased", "DUPLICATE_NATIVE_SOURCE_LOCATOR",func(l *Ledger){
            l.Observations[1].Archive=l.Observations[0].Archive
            l.Observations[1].Locator=l.Observations[0].Locator
        }},
        {"capture-time-invalid","CAPTURE_TIMESTAMP_INVALID",func(l *Ledger){
            l.Observations[0].CapturedAt="not-a-timestamp"
        }},
        {"cyclic-thread-parent","CYCLIC_THREAD_PARENT",func(l *Ledger){
            l.Observations[0].ParentID="a-3"
        }},
        {"cross-tenant-parent","CROSS_TENANT_THREAD",func(l *Ledger){
            l.Observations[7].ParentID="a-1"
        }},
        {"missing-parent","PARENT_ABSENT",func(l *Ledger){
            l.Observations[4].ParentID="ghost"
        }},
        {"changed-source-bytes","SOURCE_DIGEST_MISMATCH",func(l *Ledger){
            l.Observations[0].Raw="source changed without source digest"
        }},
        {"changed-attachment-bytes","ATTACHMENT_ID_OR_DIGEST",func(l *Ledger){
            l.Observations[0].Attachments[0].Content="malicious edited attachment"
        }},
        {"duplicate-attachment-id","ATTACHMENT_ID_OR_DIGEST",func(l *Ledger){
            l.Observations[0].Attachments[1].ID=l.Observations[0].Attachments[0].ID
        }},
        {"unsupported-claim","CLAIM_NOT_ANCHORED",func(l *Ledger){
            l.Observations[0].Claims[0].Quote="No source supports this invented quote"
        }},
        {"invalid-claim-time","CLAIM_TIME_INVALID",func(l *Ledger){
            l.Observations[0].Claims[0].ValidAt="not-a-date"
        }},
    }
    for _,tc:=range tests {
        t.Run(tc.name,func(t *testing.T){
            l:=cloneFixture(t)
            tc.mutate(&l)
            err:=l.Validate()
            if err==nil || !strings.Contains(err.Error(),tc.reason) {
                t.Fatalf("expected %s, got %v",tc.reason,err)
            }
        })
    }
}

func TestRecoveredSnapshotRejectsUnknownFieldsAndConcatenatedPayload(t *testing.T) {
    l:=Fixture()
    root:=t.TempDir()
    path:=filepath.Join(root,"observations.json")
    if err:=l.Persist(path);err!=nil{t.Fatal(err)}
    original,err:=os.ReadFile(path)
    if err!=nil{t.Fatal(err)}
    if _,err:=Recover(path);err!=nil{t.Fatal(err)}
    var document map[string]any
    if err:=json.Unmarshal(original,&document);err!=nil{t.Fatal(err)}
    document["UnsupportedUserState"]="must never silently drop field"
    unknown,err:=json.Marshal(document)
    if err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(path,unknown,0600);err!=nil{t.Fatal(err)}
    if _,err:=Recover(path);err==nil {t.Fatal("unknown persisted source field accepted")}
    concatenated:=append(append([]byte(nil),original...),[]byte(" true")...)
    if err:=os.WriteFile(path,concatenated,0600);err!=nil{t.Fatal(err)}
    if _,err:=Recover(path);err==nil ||
        !strings.Contains(err.Error(),"SOURCE_SNAPSHOT_TRAILING_CONTENT") {
        t.Fatalf("appended JSON fragment accepted or wrong error: %v",err)
    }
}

func TestIndependentGoldRejectsAppendedAdditionalJSON(t *testing.T) {
    root:=t.TempDir()
    original,err:=os.ReadFile("testdata/gold.json")
    if err!=nil{t.Fatal(err)}
    path:=filepath.Join(root,"poisoned-gold.json")
    if err:=os.WriteFile(path,append(append([]byte(nil),original...),[]byte(" false")...),0600);err!=nil{
        t.Fatal(err)
    }
    if _,err:=ReadGold(path);err==nil ||
        !strings.Contains(err.Error(),"GOLD_TRAILING_CONTENT") {
        t.Fatalf("gold corpus with trailing data accepted: %v",err)
    }
}
