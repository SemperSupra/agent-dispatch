package pipeline

import (
	"reflect"
	"slices"
	"testing"

	inventory "sempersupra/mail-evidence-challenge/review_inventory"
	logic "sempersupra/mail-evidence-challenge/temporal_logic"
)

// The fixture creates the expected inventory on the trusted test-catalog
// side before mutation of any untrusted submissions.
func trustedInventory(t *testing.T,f reviewedFixture)(inventory.Manifest,string){
	t.Helper()
	c,err:=f.s.Prepare(f.q);if err!=nil{t.Fatal(err)}
	m:=inventory.Manifest{Schema:inventory.Schema,Scope:inventory.Scope{
		Tenant:f.q.Tenant,Partition:string(f.q.Partition),TaskID:f.q.ID,
		Group:f.q.Group,Predicate:f.q.Key,ValidAt:rev2,KnownAt:f.q.KnownAt,
		PolicySHA256:f.policy,ContextSHA256:c.SHA256}}
	known,_:=stamp(f.q.KnownAt)
	for _,x:=range f.bundle.Sources{
		a:=x.Payload
		b,err:=SourceReviewBytes(a);if err!=nil{t.Fatal(err)}
		m.Entries=append(m.Entries,inventory.Entry{Kind:"source",ID:a.SourceID,
			PayloadSHA256:digest(b),RecordedAt:a.Identity.RecordedAt})
	}
	for _,x:=range f.bundle.Revisions{
		a:=x.Payload;at,_:=stamp(a.Identity.RecordedAt)
		if at.After(known){continue}
		b,err:=RevisionReviewBytes(a);if err!=nil{t.Fatal(err)}
		m.Entries=append(m.Entries,inventory.Entry{Kind:"revision",ID:a.Revision.ID,
			PayloadSHA256:digest(b),RecordedAt:a.Identity.RecordedAt})
	}
	pin,err:=inventory.Digest(m);if err!=nil{t.Fatal(err)}
	return m,pin
}
func TestPinnedSignedTemporalAssessment(t *testing.T){
	for _,lang:=range []string{"en","de","th"}{
		t.Run(lang,func(t *testing.T){
			f:=reviewed(t,lang)
			m,pin:=trustedInventory(t,f)
			a,err:=f.s.AssessPinnedReviewedTemporal(f.q,rev2,f.policy,f.grants,f.bundle,m,pin)
			if err!=nil||a.Assessment.Assessment.Find("gate.open").Status!=logic.Refuted||
				a.Inventory.RevisionCount!=1||a.Inventory.ManifestSHA256!=pin{t.Fatal(a,err)}
			slices.Reverse(f.bundle.Sources);slices.Reverse(m.Entries)
			b,err:=f.s.AssessPinnedReviewedTemporal(f.q,rev2,f.policy,f.grants,f.bundle,m,pin)
			if err!=nil||!reflect.DeepEqual(a,b){t.Fatal("order drift",err)}
		})
	}
}
func TestPinnedGateRejectsValidSignedButOmittedCorrection(t *testing.T){
	f:=reviewed(t,"en");m,pin:=trustedInventory(t,f)
	f.bundle.Revisions=nil
	// Individual signatures cannot establish completeness.
	a,err:=f.assess()
	if err!=nil||a.Assessment.Assessment.Find("gate.open").Status!=logic.Both{t.Fatal(a,err)}
	if _,err=f.s.AssessPinnedReviewedTemporal(f.q,rev2,f.policy,f.grants,f.bundle,m,pin);err==nil{
		t.Fatal("accepted omitted signed correction")
	}
	m.Entries=m.Entries[:2]
	if _,err=f.s.AssessPinnedReviewedTemporal(f.q,rev2,f.policy,f.grants,f.bundle,m,pin);err==nil{
		t.Fatal("accepted self-consistent replacement manifest with original pin")
	}
}
func TestPinnedGateBindsTaskPredicateAndHistoricalReviewInventory(t *testing.T){
	f:=reviewed(t,"de");f.q.KnownAt=rev2
	m,pin:=trustedInventory(t,f)
	a,err:=f.s.AssessPinnedReviewedTemporal(f.q,rev2,f.policy,f.grants,f.bundle,m,pin)
	if err!=nil||a.Inventory.RevisionCount!=0||
		a.Assessment.Assessment.Find("gate.open").Status!=logic.Both{t.Fatal(a,err)}
	f.bundle.Revisions=nil
	b,err:=f.s.AssessPinnedReviewedTemporal(f.q,rev2,f.policy,f.grants,f.bundle,m,pin)
	if err!=nil||!reflect.DeepEqual(a,b){t.Fatal("future review changed historical receipt",err)}
	f.q.Key="other"
	if _,err=f.s.AssessPinnedReviewedTemporal(f.q,rev2,f.policy,f.grants,f.bundle,m,pin);err==nil{
		t.Fatal("accepted predicate scope drift")
	}
}
