package temporallogic

// Independent, bounded metamorphic oracle for append-only source observations.
// The claim is *what sources support*, not objective historical truth.
import (
    "fmt"
    "math/rand"
    "reflect"
    "slices"
    "testing"
)

func TestIndependentDuplicateLineagesCannotManufactureCorroboration(t *testing.T) {
    sample:=Fixture()
    original,err:=sample.Assess("alpha","2026-05-11T12:00:00Z","2026-05-11T12:00:00Z")
    if err!=nil {t.Fatal(err)}
    before:=original.Find("coast.approved")
    if before.Status!=Both || len(before.RefutingLineages)!=1 ||
       len(before.SupportingLineages)!=1 {
        t.Fatalf("invalid independent base: %+v",before)
    }
    for n:=0;n<64;n++ {
        id:=fmt.Sprintf("extra-copy-%03d",n)
        src:=source(id,"alpha","original-denial","Approval denied.",
            "2026-05-02T08:00:00Z","2026-05-10T12:00:00Z")
        sample.Sources=append(sample.Sources,src)
        sample.Claims=append(sample.Claims,claim(
            "new-claim-"+id,id,"coast.approved","actual","Approval denied.",
            "2026-05-02T00:00:00Z",Refutes))
    }
    after,err:=sample.Assess("alpha","2026-05-11T12:00:00Z","2026-05-11T12:00:00Z")
    if err!=nil {t.Fatal(err)}
    evidence:=after.Find("coast.approved")
    if evidence.Status!=Both || len(evidence.RefutingLineages)!=1 ||
        len(evidence.SupportingLineages)!=1 || len(evidence.RefutingSourceIDs)!=66 {
        t.Fatalf("copy amplification changed evidence support: %+v",evidence)
    }
    older,err:=sample.Assess("alpha","2026-05-04T12:00:00Z","2026-05-04T12:00:00Z")
    if err!=nil {t.Fatal(err)}
    if older.Find("coast.approved").Status!=Refuted ||
       !slices.Equal(older.Find("coast.approved").RefutingSourceIDs,[]string{"deny"}) {
        t.Fatalf("late copies leaked into earlier knowledge: %+v",older)
    }
    beta,err:=sample.Assess("beta","2026-05-11T12:00:00Z","2026-05-11T12:00:00Z")
    if err!=nil || beta.Find("coast.approved").Status!=Supported ||
        !slices.Equal(beta.Find("coast.approved").SupportingSourceIDs,[]string{"private"}) {
        t.Fatalf("tenant bleed through lineage copies: %+v %v",beta,err)
    }
}

func TestTemporalSourceAndRuleOrderAreMetamorphicallyInvariant(t *testing.T) {
    baseline:=Fixture()
    cutoffs:=[][2]string{
        {"2026-05-04T12:00:00Z","2026-05-04T12:00:00Z"},
        {"2026-05-08T12:00:00Z","2026-05-08T12:00:00Z"},
        {"2026-05-11T12:00:00Z","2026-05-11T12:00:00Z"},
        {"2026-05-04T12:00:00Z","2026-05-11T12:00:00Z"},
    }
    golden:=make([]Assessment,len(cutoffs))
    for i,c:=range cutoffs {
        a,err:=baseline.Assess("alpha",c[0],c[1])
        if err!=nil {t.Fatal(err)}
        golden[i]=a
    }
    for seed:=int64(1);seed<=32;seed++ {
        candidate:=Fixture()
        rng:=rand.New(rand.NewSource(seed))
        rng.Shuffle(len(candidate.Sources),func(i,j int){
            candidate.Sources[i],candidate.Sources[j]=candidate.Sources[j],candidate.Sources[i]
        })
        rng.Shuffle(len(candidate.Claims),func(i,j int){
            candidate.Claims[i],candidate.Claims[j]=candidate.Claims[j],candidate.Claims[i]
        })
        rng.Shuffle(len(candidate.Rules),func(i,j int){
            candidate.Rules[i],candidate.Rules[j]=candidate.Rules[j],candidate.Rules[i]
        })
        for i,c:=range cutoffs {
            actual,err:=candidate.Assess("alpha",c[0],c[1])
            if err!=nil {t.Fatalf("seed %d: %v",seed,err)}
            if !reflect.DeepEqual(actual,golden[i]) {
                t.Fatalf("evidence order changed answer at seed %d cutoff %d",seed,i)
            }
        }
    }
}

func TestContradictionQuarantinesDependentRuleWithoutErasingPastReceipt(t *testing.T){
    ledger:=Fixture()
    before,err:=ledger.Assess("alpha","2026-05-08T12:00:00Z","2026-05-08T12:00:00Z")
    if err!=nil {t.Fatal(err)}
    old:=before.Find("transfer.ready")
    if old.Status!=Supported || len(old.Derivations)!=1 {
        t.Fatalf("missing source-backed prior assessment %+v",old)
    }
    later,err:=ledger.Assess("alpha","2026-05-11T12:00:00Z","2026-05-11T12:00:00Z")
    if err!=nil {t.Fatal(err)}
    if later.Find("invoice.paid").Status!=Both ||
       later.Find("transfer.ready").Status!=Neither {
        t.Fatalf("contradiction did not quarantine derived belief %+v",later)
    }
    replay,err:=ledger.Assess("alpha","2026-05-08T12:00:00Z","2026-05-08T12:00:00Z")
    if err!=nil || !reflect.DeepEqual(replay,before) {
        t.Fatal("source addition retroactively rewrote prior receipt")
    }
    if got,err:=before.Explain("transfer.ready");err!=nil || got=="" {
        t.Fatalf("old assessment lost its justification %q %v",got,err)
    }
}
