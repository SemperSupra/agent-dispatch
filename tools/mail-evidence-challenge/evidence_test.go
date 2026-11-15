package evidence

import (
    "os"
    "path/filepath"
    "slices"
    "strings"
    "testing"
)

func TestIndependentGoldAndRestart(t *testing.T) {
    result,err:=Evaluate("testdata/gold.json")
    if err!=nil{t.Fatal(err)}
    if result.SourceOccurrences!=8 || result.AttachmentOccurrences!=5 || result.QuestionCount!=21 ||
       result.VerifiedQuestions!=21 || result.FalseMergeCount!=0 || result.CrossTenantLeaks!=0 ||
       !result.PersistenceRecovery || !result.IndependentGold || result.ModelInference {
        t.Fatalf("unexpected bounded evaluation: %+v",result)
    }
    if result.NativePSTConformance!="NOT_TESTED" || len(result.CorpusSHA256)!=64 {
        t.Fatal("unsupported conformance claim",result)
    }
}
func TestIdenticalMessageIDMustNotMergeSourceOccurrences(t *testing.T) {
    l:=Fixture()
    if err:=l.Validate();err!=nil{t.Fatal(err)}
    got,err:=l.Answer(Question{ID:"collision",Tenant:"alpha",Mode:"message-id-collisions",Key:"<collision@invalid.test>"})
    if err!=nil{t.Fatal(err)}
    want:=[]string{"a-1","a-2","b-1","c-1"}
    if !slices.Equal(got.IDs,want)||len(got.Citations)!=4 {t.Fatalf("lost occurrence: %+v",got)}
    a,_:=l.byID("a-1"); c,_:=l.byID("c-1")
    if a.SHA256!=c.SHA256 || a.ID==c.ID {t.Fatal("repeated original incorrectly equated")}
}
func TestSameNameAttachmentsStayDistinct(t *testing.T) {
    l:=Fixture()
    got,err:=l.Answer(Question{ID:"same-filename",Tenant:"alpha",Mode:"attachment-by-filename",OccurrenceID:"a-1",Filename:"report.txt"})
    if err!=nil{t.Fatal(err)}
    if !slices.Equal(got.IDs,[]string{"a-1/0","a-1/1"})||len(got.AttachmentRefs)!=2||
       got.AttachmentRefs[0].SHA256==got.AttachmentRefs[1].SHA256 {
        t.Fatal("attachment occurrence loss",got)
    }
}
func TestBytesAndTenantsGateCitations(t *testing.T) {
    l:=Fixture()
    answer,err:=l.Answer(Question{ID:"thai",Tenant:"alpha",Mode:"fact-asof",Group:"coast",Key:"approval",AsOf:"2026-05-05T09:00:00Z"})
    if err!=nil{t.Fatal(err)}
    if len(answer.Citations)!=1 || answer.Citations[0].Quote!="อนุมัติแล้ว" {
        t.Fatal("Thai claim lacks a byte-anchored source",answer)
    }
    if err:=validateProvenance(l,Question{Tenant:"alpha"},answer);err!=nil{t.Fatal(err)}
    answer.Citations[0].Start++
    if err:=validateProvenance(l,Question{Tenant:"alpha"},answer);err==nil{t.Fatal("accepted forged source byte range")}
    answer,err=l.Answer(Question{ID:"denied",Tenant:"alpha",Mode:"source-by-id",OccurrenceID:"beta-1"})
    if err!=nil||answer.Classification!="ABSTAIN"||len(answer.IDs)!=0{t.Fatalf("tenant leak %+v %v",answer,err)}
}
func TestNoSnapshotAbsenceEqualsDeletion(t *testing.T) {
    l:=Fixture()
    pending,err:=l.Answer(Question{ID:"no-delete",Tenant:"alpha",Mode:"fact-asof",Group:"release",Key:"status",AsOf:"2026-05-30T00:00:00Z"})
    if err!=nil||pending.Value!="pending"||!slices.Equal(pending.IDs,[]string{"a-5"}) {
        t.Fatalf("incomplete snapshot inferred deletion: %+v, %v",pending,err)
    }
    unknown,err:=l.Answer(Question{ID:"no-evidence",Tenant:"alpha",Mode:"fact-asof",Group:"release",Key:"revoked",AsOf:"2026-05-30T00:00:00Z"})
    if err!=nil||unknown.Classification!="ABSTAIN" {t.Fatal("invented claim",unknown,err)}
}
func TestTamperAndCollisionRejectedOnRecover(t *testing.T) {
    l:=Fixture()
    tmp:=t.TempDir()
    path:=filepath.Join(tmp,"snapshot.json")
    if err:=l.Persist(path);err!=nil{t.Fatal(err)}
    restored,err:=Recover(path)
    if err!=nil||restored.Digest()!=l.Digest(){t.Fatal("failed clean restart",err)}
    corrupted:=l
    corrupted.Observations=slices.Clone(l.Observations)
    corrupted.Observations[0].Raw+="TAMPER"
    if err:=corrupted.Validate();err==nil{t.Fatal("accepted raw source corruption")}
    dup:=l
    dup.Observations=slices.Clone(l.Observations)
    dup.Observations[1].ID=dup.Observations[0].ID
    if err:=dup.Validate();err==nil{t.Fatal("accepted duplicate native occurrence identity")}
    gold,err:=os.ReadFile("testdata/gold.json");if err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(filepath.Join(tmp,"gold.json"),[]byte(strings.Replace(string(gold),
        "budget-prior","budget-prior-mutated",1)),0600);err!=nil{t.Fatal(err)}
    // A name-only change is not an automatic label leak; a changed expected
    // source identity must be rejected independently by the oracle.
    poisoned:=strings.Replace(string(gold),"\"ExpectedValue\": \"120\"","\"ExpectedValue\": \"999\"",1)
    if err:=os.WriteFile(filepath.Join(tmp,"poisoned.json"),[]byte(poisoned),0600);err!=nil{t.Fatal(err)}
    if _,err:=Evaluate(filepath.Join(tmp,"poisoned.json"));err==nil{t.Fatal("accepted altered independent ground truth")}
}
