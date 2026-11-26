package pipeline

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	evidence "sempersupra/mail-evidence-challenge"
	gate "sempersupra/mail-evidence-challenge/improvement_gate"
)

func splitFixture() Split {
	return Split{DevIDs: []string{"a-2","a-5"},
		HeldoutIDs: []string{"a-1","b-1","c-1","a-3","a-4","beta-1"}}
}
func sample(t *testing.T) *Session {
	t.Helper()
	s,err:=New(evidence.Fixture(),splitFixture())
	if err!=nil{t.Fatal(err)}
	return s
}
func task(id string,p Partition,group,key,clock,lang,question string) Task {
	return Task{ID:id,Partition:p,Tenant:"alpha",Group:group,Key:key,
		KnownAt:clock,Language:lang,Question:question}
}
func TestIntegratedIndependentEvaluation(t *testing.T) {
	s:=sample(t)
	dev:=task("D1",Dev,"release","status","2026-05-04T00:00:00Z","en","Release status?")
	held:=[]Task{
		task("H1",Heldout,"coast","budget","2026-05-04T00:00:00Z","en","Budget as of May 4?"),
		task("H2",Heldout,"coast","approval","2026-05-03T00:00:00Z","de","Freigabestatus?"),
		task("H3",Heldout,"coast","approval","2026-05-05T00:00:00Z","th","อนุมัติแล้วหรือไม่"),
		task("H4",Heldout,"starling","marker","2026-05-05T00:00:00Z","en","Marker?"),
	}
	// Fixed, separately authored expectations. Compute offsets from exact
	// fixture literals, not from the candidate's answer/citation.
	cite:=func(id,raw,quote string) []gate.Evidence {
		start:=strings.Index(raw,quote)
		if start<0{t.Fatal("broken oracle")}
		return []gate.Evidence{{SourceID:id,Begin:start,End:start+len(quote)}}
	}
	gold:=func(x Task,family,lineage,value string,allowed []gate.Evidence) gate.Case {
		return gate.Case{ID:x.ID,Tenant:x.Tenant,Language:x.Language,KnownAt:x.KnownAt,
			Family:family,Lineage:lineage,ExpectedValue:value,Allowed:allowed}
	}
	dg:=gold(dev,"release","dev-release","pending",cite("a-5","Subject: Unassigned release\nRelease status: pending.\n","Release status: pending."))
	hg:=[]gate.Case{
		gold(held[0],"coast","held-coast","150",cite("b-1","Subject: Fictional coast budget revision\nCoast budget: 150 units.\n","Coast budget: 150 units.")),
		gold(held[1],"coast","held-coast","denied",cite("a-3","Betreff: Küstenfreigabe\nBudgetfreigabe abgelehnt.\n","Budgetfreigabe abgelehnt.")),
		gold(held[2],"coast","held-coast","approved",cite("a-4","เรื่อง: อนุมัติชายฝั่ง\nอนุมัติแล้ว\n","อนุมัติแล้ว")),
		gold(held[3],"starling","held-marker",gate.Unknown,nil),
	}
	d,err:=s.AnswerFact(dev);if err!=nil{t.Fatal(err)}
	arm:=gate.Arm{Name:"typed-reference",PolicySHA256:digest([]byte("typed-reference/v1")),Dev:[]gate.Answer{d}}
	for _,q:=range held{
		a,err:=s.AnswerFact(q);if err!=nil{t.Fatal(err)}
		arm.Heldout=append(arm.Heldout,a)
	}
	// This is an explicitly synthetic negative control, not a competitive
	// natural-language model baseline or a measured improvement.
	control:=gate.Arm{Name:"abstain-control",PolicySHA256:digest([]byte("abstain-control/v1")),
		Dev:[]gate.Answer{{CaseID:dev.ID,Value:gate.Unknown}}}
	for _,q:=range held{control.Heldout=append(control.Heldout,gate.Answer{CaseID:q.ID,Value:gate.Unknown})}
	result,err:=gate.Evaluate(gate.Experiment{Sources:s.Sources(),Dev:[]gate.Case{dg},
		Heldout:hg,Arms:[]gate.Arm{control,arm},Baseline:control.Name,InferenceKind:gate.Simulated})
	if err!=nil{t.Fatal(err)}
	if result.SelectedOnDev!=arm.Name || result.Heldout[arm.Name].Exact!=4 ||
		result.Heldout[control.Name].Exact!=1 || result.PromotionStatus!="HOLD" ||
		len(result.SelectedHardVetoes)!=0 {t.Fatalf("integration oracle mismatch: %+v",result)}
}
func TestContextScopeAndDeterministicReplay(t *testing.T) {
	s:=sample(t)
	q:=task("H",Heldout,"coast","approval","2026-05-03T00:00:00Z","de","Freigabestatus?")
	ctx,err:=s.Prepare(q);if err!=nil{t.Fatal(err)}
	var ids []string
	for _,r:=range ctx.Records{ids=append(ids,r.ID)}
	if !slices.Equal(ids,[]string{"a-1","a-3"}) {t.Fatalf("foreign, future or dev context: %v",ids)}
	raw,_:=json.Marshal(ctx)
	for _,bad:=range []string{"beta-only","Ferry date","Release status","อนุมัติแล้ว","fictional report first attachment","Claims","ExpectedValue"} {
		if strings.Contains(string(raw),bad){t.Fatalf("outward context leaked %q",bad)}
	}
	if len(ctx.SHA256)!=64{t.Fatal("missing context identity")}
	l:=evidence.Fixture();slices.Reverse(l.Observations)
	sp:=splitFixture();slices.Reverse(sp.HeldoutIDs)
	restarted,err:=New(l,sp);if err!=nil{t.Fatal(err)}
	again,err:=restarted.Prepare(q)
	if err!=nil||!reflect.DeepEqual(ctx,again){t.Fatal("context not reproducible",err)}
}
func TestSourceAndPartitionImmutability(t *testing.T){
	l:=evidence.Fixture();sp:=splitFixture()
	s,err:=New(l,sp);if err!=nil{t.Fatal(err)}
	q:=task("H",Heldout,"coast","budget","2026-05-05T00:00:00Z","en","Budget?")
	before,err:=s.Prepare(q);if err!=nil{t.Fatal(err)}
	l.Observations[0].Raw="tampered";l.Observations[0].Claims[0].Value="999"
	sp.HeldoutIDs[0]="a-5"
	a,err:=s.AnswerFact(q)
	if err!=nil||a.Value!="150"{t.Fatal("original ledger alias",a,err)}
	before.Records[0].Body="caller mutation"
	again,err:=s.Prepare(q)
	if err!=nil||again.Records[0].Body=="caller mutation"{t.Fatal("context alias",err)}
}
func TestPartitionAndQueryFailClosed(t *testing.T){
	for _,tc:=range []struct{name,why string; split Split}{
		{"same-id","PARTITION_SOURCE_REUSED",Split{DevIDs:[]string{"a-1"},HeldoutIDs:[]string{"a-1"}}},
		{"same-bytes","PARTITION_CONTENT_REUSED",Split{DevIDs:[]string{"a-1"},HeldoutIDs:[]string{"c-1"}}},
		{"unknown","PARTITION_SOURCE_UNKNOWN",Split{DevIDs:[]string{"missing"},HeldoutIDs:[]string{"a-1"}}},
		{"empty","PARTITIONS_REQUIRED",Split{DevIDs:[]string{"a-1"}}},
	}{
		t.Run(tc.name,func(t *testing.T){
			_,err:=New(evidence.Fixture(),tc.split)
			if err==nil||!strings.Contains(err.Error(),tc.why){t.Fatal(err)}
		})
	}
	s:=sample(t)
	q:=task("H",Heldout,"coast","approval","not-a-clock","en","Approval?")
	if _,err:=s.Prepare(q);err==nil{t.Fatal("invalid knowledge clock")}
	q.KnownAt="2026-04-01T00:00:00Z"
	a,err:=s.AnswerFact(q)
	if err!=nil||a.Value!=gate.Unknown||a.Citation!=nil{t.Fatal("future evidence used",a,err)}
	q.KnownAt="2026-05-05T00:00:00Z";q.Partition="other"
	if _,err:=s.Prepare(q);err==nil{t.Fatal("invalid partition")}
}
