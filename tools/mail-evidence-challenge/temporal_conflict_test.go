package evidence

import (
    "testing"
)

func TestKnowledgeAsOfCannotUseFutureAcquiredHistoricalClaim(t *testing.T) {
    ledger:=cloneFixture(t)
    future:=newObservation(
        "late-acquisition","export-future","folder:9/item:30","alpha",
        "<late@invalid.test>","legacy","","2026-05-09T00:00:00Z",
        "Historical rate was 88 units.",
        []Claim{{Key:"rate",Value:"88",Quote:"Historical rate was 88 units.",
                 ValidAt:"2026-05-01T00:00:00Z"}})
    ledger.Observations=append(ledger.Observations,future)
    if err:=ledger.Validate();err!=nil{t.Fatal(err)}
    oldQuery:=Question{ID:"historical-asof",Tenant:"alpha",Mode:"fact-asof",
        Group:"legacy",Key:"rate",AsOf:"2026-05-02T00:00:00Z"}
    before,err:=ledger.Answer(oldQuery)
    if err!=nil{t.Fatal(err)}
    if before.Classification!="ABSTAIN" || len(before.Citations)!=0 ||
        len(before.IDs)!=0 {t.Fatalf("future knowledge leaked: %+v",before)}
    oldQuery.AsOf="2026-05-10T00:00:00Z"
    after,err:=ledger.Answer(oldQuery)
    if err!=nil{t.Fatal(err)}
    if after.Classification!="SUPPORTED" || after.Value!="88" ||
        len(after.Citations)!=1 || after.Citations[0].OccurrenceID!="late-acquisition" {
        t.Fatalf("recovered historical fact not anchored: %+v",after)
    }
}

func TestSimultaneousContradictoryClaimsForceAbstention(t *testing.T) {
    ledger:=cloneFixture(t)
    rival:=newObservation(
        "rival","export-rival","folder:7/item:2","alpha",
        "<rival@invalid.test>","coast","","2026-05-03T10:00:00Z",
        "Coast budget was 151 units.",
        []Claim{{Key:"budget",Value:"151",Quote:"Coast budget was 151 units.",
                 ValidAt:"2026-05-03T09:00:00Z"}})
    ledger.Observations=append(ledger.Observations,rival)
    if err:=ledger.Validate();err!=nil{t.Fatal(err)}
    q:=Question{ID:"conflict",Tenant:"alpha",Mode:"fact-asof",
        Group:"coast",Key:"budget",AsOf:"2026-05-04T00:00:00Z"}
    answer,err:=ledger.Answer(q)
    if err!=nil{t.Fatal(err)}
    if answer.Classification!="ABSTAIN" || answer.Value!="" ||
       len(answer.Citations)!=0 || len(answer.IDs)!=0 {
        t.Fatalf("unsupported arbitrarily chosen winner: %+v",answer)
    }
    // Explicit order reversal must not change contradictory status.
    for l,r:=0,len(ledger.Observations)-1;l<r;l,r=l+1,r-1 {
        ledger.Observations[l],ledger.Observations[r]=ledger.Observations[r],ledger.Observations[l]
    }
    reversed,err:=ledger.Answer(q)
    if err!=nil||reversed.Classification!="ABSTAIN" {
        t.Fatalf("source ordering bypassed abstention: %+v %v",reversed,err)
    }
}

func TestLateContradictionDoesNotRewriteEarlierKnowledge(t *testing.T) {
    ledger:=cloneFixture(t)
    late:=newObservation(
        "late-rival","export-late","folder:8/item:3","alpha",
        "<rival@invalid.test>","coast","","2026-05-07T00:00:00Z",
        "Coast budget was 151 units.",
        []Claim{{Key:"budget",Value:"151",Quote:"Coast budget was 151 units.",
                 ValidAt:"2026-05-03T09:00:00Z"}})
    ledger.Observations=append(ledger.Observations,late)
    q:=Question{ID:"old-view",Tenant:"alpha",Mode:"fact-asof",
        Group:"coast",Key:"budget",AsOf:"2026-05-04T00:00:00Z"}
    before,err:=ledger.Answer(q)
    if err!=nil{t.Fatal(err)}
    if before.Classification!="SUPPORTED" || before.Value!="150" {
        t.Fatalf("future contradiction affected past view: %+v",before)
    }
    q.AsOf="2026-05-08T00:00:00Z"
    after,err:=ledger.Answer(q)
    if err!=nil{t.Fatal(err)}
    if after.Classification!="ABSTAIN" {
        t.Fatalf("later evidence conflict not recognized: %+v",after)
    }
}

func TestExistingFrozenGoldUnaffectedByTemporalVeto(t *testing.T) {
    result,err:=Evaluate("testdata/gold.json")
    if err!=nil{t.Fatal(err)}
    if result.VerifiedQuestions!=21 || result.QuestionCount!=21 {
        t.Fatalf("regression on frozen gold: %+v",result)
    }
}
