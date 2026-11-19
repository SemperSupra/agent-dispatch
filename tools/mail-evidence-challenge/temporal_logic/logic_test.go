package temporallogic

import (
    "reflect"
    "slices"
    "strings"
    "testing"
)

func source(id,tenant,lineage,raw,authored,acquired string) Source {
    return Source{ID:id,Tenant:tenant,Lineage:lineage,Raw:raw,SHA256:digest(raw),
        AuthoredAt:authored,AcquiredAt:acquired}
}
func claim(id,src,predicate,modality,quote,from string,p Polarity) Claim {
    return Claim{ID:id,SourceID:src,Predicate:predicate,Modality:modality,Quote:quote,
        ValidFrom:from,Polarity:p}
}
func Fixture() Store {
    sources:=[]Source{
        source("deny","alpha","original-denial","Approval denied.","2026-05-02T08:00:00Z","2026-05-02T09:00:00Z"),
        source("copy","alpha","original-denial","Approval denied.","2026-05-02T08:00:00Z","2026-05-06T09:00:00Z"),
        source("grant","alpha","late-revision","Approval granted, effective May 3.","2026-05-03T08:00:00Z","2026-05-10T09:00:00Z"),
        source("plan","alpha","future-plan","Approval will be granted.","2026-05-01T08:00:00Z","2026-05-01T09:00:00Z"),
        source("private","beta","beta-secret","Approval granted to beta.","2026-05-01T08:00:00Z","2026-05-01T09:00:00Z"),
        source("paid","alpha","invoice-source","Invoice paid.","2026-05-05T07:00:00Z","2026-05-05T08:00:00Z"),
        source("receipt","alpha","verified-source","Receipt verified.","2026-05-06T07:00:00Z","2026-05-06T08:00:00Z"),
        source("retraction","alpha","retraction-source","Invoice was not paid.","2026-05-10T07:00:00Z","2026-05-10T08:00:00Z"),
    }
    claims:=[]Claim{
        claim("denial","deny","coast.approved","actual","Approval denied.","2026-05-02T00:00:00Z",Refutes),
        claim("copy-denial","copy","coast.approved","actual","Approval denied.","2026-05-02T00:00:00Z",Refutes),
        claim("grant-actual","grant","coast.approved","actual","Approval granted","2026-05-03T00:00:00Z",Supports),
        claim("grant-plan","plan","coast.approved","planned","Approval will be granted.","2026-05-01T00:00:00Z",Supports),
        claim("beta","private","coast.approved","actual","Approval granted","2026-05-01T00:00:00Z",Supports),
        claim("invoice-paid","paid","invoice.paid","actual","Invoice paid.","2026-05-05T00:00:00Z",Supports),
        claim("receipt-verified","receipt","receipt.verified","actual","Receipt verified.","2026-05-06T00:00:00Z",Supports),
        claim("invoice-contradiction","retraction","invoice.paid","actual","Invoice was not paid.","2026-05-09T00:00:00Z",Refutes),
    }
    policy:=digest("reviewed-public-rule-v1")
    // Intentionally reverse dependency order so execution must be topo-safe.
    rules:=[]Rule{
        {ID:"r2",Tenant:"alpha",Consequent:"transfer.ready",
            Premises:[]string{"reimburse.ready"},PolicySHA256:policy},
        {ID:"r1",Tenant:"alpha",Consequent:"reimburse.ready",
            Premises:[]string{"invoice.paid","receipt.verified"},PolicySHA256:policy},
    }
    return Store{Sources:sources,Claims:claims,Rules:rules}
}
func TestFourValuedSupportAndTemporalRetrieval(t *testing.T){
    s:=Fixture()
    old,err:=s.Assess("alpha","2026-05-04T12:00:00Z","2026-05-04T12:00:00Z")
    if err!=nil{t.Fatal(err)}
    if b:=old.Find("coast.approved");b.Status!=Refuted ||
       !slices.Equal(b.RefutingSourceIDs,[]string{"deny"}) {
        t.Fatalf("early knowledge state wrong: %+v",b)
    }
    late,err:=s.Assess("alpha","2026-05-04T12:00:00Z","2026-05-11T00:00:00Z")
    if err!=nil{t.Fatal(err)}
    b:=late.Find("coast.approved")
    if b.Status!=Both || len(b.RefutingSourceIDs)!=2 ||
       len(b.RefutingLineages)!=1 ||
       !slices.Equal(b.SupportingSourceIDs,[]string{"grant"}) {
        t.Fatalf("late acquired correction or duplicate lineage wrong: %+v",b)
    }
    beta,err:=s.Assess("beta","2026-05-04T12:00:00Z","2026-05-11T00:00:00Z")
    if err!=nil{t.Fatal(err)}
    if beta.Find("coast.approved").Status!=Supported ||
       !slices.Equal(beta.Find("coast.approved").SupportingSourceIDs,[]string{"private"}) {
        t.Fatalf("cross tenant evidence or planned claim leaked: %+v",beta)
    }
    unknown,err:=s.Assess("alpha","2026-05-01T12:00:00Z","2026-05-02T00:00:00Z")
    if err!=nil||unknown.Find("coast.approved").Status!=Neither {
        t.Fatalf("planned event converted to accomplished truth: %+v %v",unknown,err)
    }
}
func TestRuleJustificationAndLaterContradiction(t *testing.T){
    s:=Fixture()
    old,err:=s.Assess("alpha","2026-05-08T12:00:00Z","2026-05-08T12:00:00Z")
    if err!=nil{t.Fatal(err)}
    b:=old.Find("transfer.ready")
    if b.Status!=Supported || len(b.Derivations)!=1 ||
       !slices.Equal(b.Derivations[0].SourceIDs,[]string{"paid","receipt"}) ||
       len(b.Derivations[0].PolicySHA256)!=64 {
        t.Fatalf("independent DAG-derived proof missing: %+v",b)
    }
    if note,err:=old.Explain("transfer.ready");err!=nil||!strings.Contains(note,"paid") {
        t.Fatalf("missing source provenance explanation: %s %v",note,err)
    }
    late,err:=s.Assess("alpha","2026-05-11T12:00:00Z","2026-05-11T12:00:00Z")
    if err!=nil{t.Fatal(err)}
    if late.Find("invoice.paid").Status!=Both ||
       late.Find("reimburse.ready").Status!=Neither ||
       late.Find("transfer.ready").Status!=Neither {
        t.Fatalf("unreviewed contradiction failed to quarantine derivation: %+v",late)
    }
    repeated,err:=s.Assess("alpha","2026-05-08T12:00:00Z","2026-05-08T12:00:00Z")
    if err!=nil||!reflect.DeepEqual(repeated,old){
        t.Fatal("new late evidence retroactively mutated old knowledge view")
    }
}
func TestRuleOrderDoesNotChangeDerivedState(t *testing.T){
    s:=Fixture()
    a,err:=s.Assess("alpha","2026-05-08T12:00:00Z","2026-05-08T12:00:00Z")
    if err!=nil{t.Fatal(err)}
    slices.Reverse(s.Rules)
    b,err:=s.Assess("alpha","2026-05-08T12:00:00Z","2026-05-08T12:00:00Z")
    if err!=nil||!reflect.DeepEqual(a,b) {
        t.Fatalf("reasoning rule order leaked into facts: %+v %+v %v",a,b,err)
    }
}
func TestSourceTamperingAndUnknownRuleCyclesFailClosed(t *testing.T){
    tests:=[]struct{
        name string
        change func(*Store)
        reason string
    }{
        {"source-hash",func(s *Store){s.Sources[0].Raw+=" changed"},"INVALID_SOURCE_PROVENANCE"},
        {"duplicate-source-id",func(s *Store){s.Sources[1].ID="deny"},"DUPLICATE_SOURCE_OCCURRENCE"},
        {"unanchored-quote",func(s *Store){s.Claims[0].Quote="Unsupported fabricated citation"},"CLAIM_NOT_SOURCE_ANCHORED"},
        {"bad-valid-interval",func(s *Store){s.Claims[0].ValidTo="2026-05-01T00:00:00Z"},"VALID_INTERVAL_INVALID"},
        {"self-rule",func(s *Store){s.Rules[0].Premises=[]string{"transfer.ready"}},"CYCLIC_RULE"},
        {"mutual-rule-cycle",func(s *Store){s.Rules[1].Premises=[]string{"transfer.ready"}},"CYCLIC_RULE"},
        {"unknown-modality",func(s *Store){s.Claims[0].Modality="will"},"MODALITY_INVALID"},
        {"wrong-source",func(s *Store){s.Claims[0].SourceID="other"},"CLAIM_NOT_SOURCE_ANCHORED"},
        {"bad-acquired-clock",func(s *Store){s.Sources[0].AcquiredAt="yesterday"},"INVALID_SOURCE_ACQUIRED_TIME"},
    }
    for _,tc:=range tests {
        t.Run(tc.name,func(t *testing.T) {
            s:=Fixture()
            tc.change(&s)
            if err:=s.Validate();err==nil||!strings.Contains(err.Error(),tc.reason){
                t.Fatalf("expected %s, got %v",tc.reason,err)
            }
        })
    }
}
