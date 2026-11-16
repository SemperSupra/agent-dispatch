package evidence

import (
    "bytes"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "slices"
)

type GoldCard struct {
    Question Question
    ExpectedClassification string
    ExpectedValue string
    ExpectedIDs []string
    ExpectedCitationCount int
    ExpectedAttachmentCount int
}

func ReadGold(path string) ([]GoldCard, error) {
    data,err:=os.ReadFile(path);if err!=nil{return nil,err}
    if len(data)>32_768 {return nil,errors.New("GOLD_TOO_LARGE")}
    d:=json.NewDecoder(bytes.NewReader(data));d.DisallowUnknownFields()
    var gold []GoldCard
    if err=d.Decode(&gold);err!=nil{return nil,err}
    var extra any
    if err:=d.Decode(&extra);err!=io.EOF {
        return nil,errors.New("GOLD_TRAILING_CONTENT")
    }
    if len(gold)<20 || len(gold)>30 {return nil,errors.New("GOLD_CASE_COUNT")}
    seen:=map[string]bool{}
    for _,c:=range gold {
        if c.Question.ID=="" || seen[c.Question.ID] || c.Question.Question=="" ||
           c.Question.Language=="" || c.ExpectedClassification=="" {
            return nil,errors.New("GOLD_CARD_INVALID")
        }
        seen[c.Question.ID]=true
    }
    return gold,nil
}

func validateProvenance(l Ledger,q Question,a Answer) error {
    for _,c:=range a.Citations {
        o,ok:=l.byID(c.OccurrenceID)
        if !ok || o.Tenant!=q.Tenant {return errors.New("CITATION_TENANT_OR_OCCURRENCE_VIOLATION")}
        if c.SourceSHA256!=o.SHA256 || c.Start<0 || c.End>len([]byte(o.Raw)) ||
           c.Start>=c.End || string([]byte(o.Raw)[c.Start:c.End])!=c.Quote {
            return errors.New("CITATION_BYTE_SPAN_INVALID")
        }
    }
    for _,ref:=range a.AttachmentRefs {
        o,ok:=l.byID(ref.SourceOccurrenceID)
        if !ok || o.Tenant!=q.Tenant {return errors.New("ATTACHMENT_CROSS_TENANT")}
        found:=false
        for _,f:=range o.Attachments {
            if f.ID==ref.AttachmentID && f.Filename==ref.Filename &&
               f.SHA256==ref.SHA256 && hash(f.Content)==ref.SHA256 {found=true}
        }
        if !found {return errors.New("ATTACHMENT_SOURCE_OR_BYTES_MISMATCH")}
    }
    return nil
}

func Evaluate(goldPath string) (Evaluation,error) {
    l:=Fixture()
    if err:=l.Validate();err!=nil{return Evaluation{},err}
    gold,err:=ReadGold(goldPath)
    if err!=nil{return Evaluation{},err}
    stats:=Evaluation{
        Schema:Schema,Classification:"SYNTHETIC_TYPED_EVIDENCE_ONLY",
        SourceOccurrences:len(l.Observations),QuestionCount:len(gold),
        IndependentGold:true,ModelInference:false,
        NativePSTConformance:"NOT_TESTED",CorpusSHA256:l.Digest(),
    }
    unique:=map[string]bool{}
    for _,o:=range l.Observations {
        if unique[o.ID] {stats.FalseMergeCount++}
        unique[o.ID]=true
        stats.AttachmentOccurrences+=len(o.Attachments)
    }
    for _,card:=range gold {
        answer,err:=l.Answer(card.Question)
        if err!=nil{return stats,fmt.Errorf("ANSWER_RUNTIME_%s: %w",card.Question.ID,err)}
        if answer.Classification!=card.ExpectedClassification ||
           answer.Value!=card.ExpectedValue ||
           !slices.Equal(answer.IDs,card.ExpectedIDs) ||
           len(answer.Citations)!=card.ExpectedCitationCount ||
           len(answer.AttachmentRefs)!=card.ExpectedAttachmentCount {
            return stats,fmt.Errorf("GOLD_MISMATCH_%s",card.Question.ID)
        }
        if err:=validateProvenance(l,card.Question,answer);err!=nil{
            stats.CrossTenantLeaks++
            return stats,fmt.Errorf("PROVENANCE_%s: %w",card.Question.ID,err)
        }
        stats.VerifiedQuestions++
    }
    // Persistent state is a versioned copy; native source bytes are never
    // rewritten or deleted. Check a clean process-like reopen and corruption.
    root,err:=os.MkdirTemp("","mail-evidence-qualify-*")
    if err!=nil{return stats,err}
    defer os.RemoveAll(root)
    path:=filepath.Join(root,"immutable-observations.json")
    if err:=l.Persist(path);err!=nil{return stats,err}
    recovered,err:=Recover(path);if err!=nil{return stats,err}
    if recovered.Digest()!=l.Digest() || len(recovered.Observations)!=len(l.Observations){
        return stats,errors.New("RESTART_EVIDENCE_CHANGED")
    }
    raw,err:=os.ReadFile(path);if err!=nil{return stats,err}
    damaged:=bytes.Replace(raw,[]byte("Coast budget: 120 units."),
        []byte("Coast budget: 170 units."),1)
    if bytes.Equal(damaged,raw){return stats,errors.New("MISSING_CORRUPTION_NEGATIVE")}
    if err:=os.WriteFile(path,damaged,0600);err!=nil{return stats,err}
    if _,err:=Recover(path);err==nil{return stats,errors.New("CORRUPT_SOURCE_ACCEPTED")}
    stats.PersistenceRecovery=true
    return stats,nil
}
