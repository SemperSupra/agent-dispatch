package temporallogic

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const revStart="2026-06-01T00:00:00Z"
const revAuth="2026-06-02T00:00:00Z"
const revKnown="2026-06-05T00:00:00Z"
const revEnd="2026-06-09T00:00:00Z"

func revisionFixture() (Store,[]Revision) {
	src:=func(id,tenant,lineage,raw,authored,acquired string)Source{
		return Source{ID:id,Tenant:tenant,Lineage:lineage,Raw:raw,SHA256:digest(raw),AuthoredAt:authored,AcquiredAt:acquired}
	}
	return Store{
		Sources:[]Source{
			src("a","alpha","notice","Gate is open.",revStart,revStart),
			src("b","alpha","notice","Correction: gate is closed.",revAuth,revKnown),
			src("c","alpha","independent","Gate is open.",revStart,revStart),
			src("d","beta","notice","Correction: gate is open.",revAuth,revKnown),
			src("e","alpha","notice","Correction: gate is open again.",revKnown,revEnd),
		},
		Claims:[]Claim{
			{ID:"old",SourceID:"a",Predicate:"gate.open",Modality:"actual",Quote:"Gate is open.",ValidFrom:revStart,Polarity:Supports},
			{ID:"new",SourceID:"b",Predicate:"gate.open",Modality:"actual",Quote:"gate is closed.",ValidFrom:revAuth,ValidTo:revEnd,Polarity:Refutes},
			{ID:"other",SourceID:"c",Predicate:"gate.open",Modality:"actual",Quote:"Gate is open.",ValidFrom:revStart,Polarity:Supports},
			{ID:"foreign",SourceID:"d",Predicate:"gate.open",Modality:"actual",Quote:"gate is open.",ValidFrom:revAuth,Polarity:Supports},
			{ID:"next",SourceID:"e",Predicate:"gate.open",Modality:"actual",Quote:"gate is open again.",ValidFrom:revAuth,Polarity:Supports},
		},
	},[]Revision{{ID:"r1",PredecessorID:"old",SuccessorID:"new",Quote:"Correction: gate is closed.",RecordedAt:revKnown}}
}

func TestExplicitRevisionClockAndContradiction(t *testing.T){
	s,r:=revisionFixture()
	cases:=[]struct{label,valid,known string;want Status;support,refute []string;edges int}{
		{"before-valid",revStart,revKnown,Supported,[]string{"a","c"},nil,0},
		{"before-known",revAuth,revAuth,Supported,[]string{"a","c"},nil,0},
		{"late-known-historical",revAuth,revKnown,Both,[]string{"c"},[]string{"b"},1},
		{"exclusive-end",revEnd,revKnown,Supported,[]string{"a","c"},nil,0},
	}
	for _,c:=range cases{t.Run(c.label,func(t *testing.T){
		a,err:=s.AssessRevisions("alpha",c.valid,c.known,r)
		if err!=nil{t.Fatal(err)}
		b:=a.Assessment.Find("gate.open")
		if b.Status!=c.want||!slices.Equal(b.SupportingSourceIDs,c.support)||!slices.Equal(b.RefutingSourceIDs,c.refute)||len(a.Applied)!=c.edges{
			t.Fatalf("historical projection mismatch: %+v %+v",b,a.Applied)
		}
	})}
	// With no explicit revision edge, later contradictory evidence cannot
	// suppress the original source (both source lineages remain visible).
	unreviewed,err:=s.AssessRevisions("alpha",revAuth,revKnown,nil)
	if err!=nil||!slices.Equal(unreviewed.Assessment.Find("gate.open").SupportingSourceIDs,[]string{"a","c"}){
		t.Fatalf("automatic supersession: %+v %v",unreviewed,err)
	}
	foreign,err:=s.AssessRevisions("beta",revAuth,revKnown,r)
	if err!=nil||len(foreign.Applied)!=0||!slices.Equal(foreign.Assessment.Find("gate.open").SupportingSourceIDs,[]string{"d"}){
		t.Fatalf("revision tenant escape: %+v %v",foreign,err)
	}
}

func TestRevisionProjectionPreservesImmutableStoreAndOrder(t *testing.T){
	s,r:=revisionFixture()
	// Make the intermediate claim open-ended so all links overlap at revEnd.
	s.Claims[1].ValidTo=""
	r=append(r,Revision{ID:"r2",PredecessorID:"new",SuccessorID:"next",Quote:"Correction: gate is open again.",RecordedAt:revEnd})
	before,_:=json.Marshal(s)
	x,err:=s.AssessRevisions("alpha",revAuth,revEnd,r);if err!=nil{t.Fatal(err)}
	want:=x.Assessment.Find("gate.open")
	if want.Status!=Supported||!slices.Equal(want.SupportingSourceIDs,[]string{"c","e"})||len(x.Applied)!=2{t.Fatalf("chain %+v",x)}
	after,_:=json.Marshal(s);if string(before)!=string(after){t.Fatal("mutated source")}
	slices.Reverse(s.Sources);slices.Reverse(s.Claims);slices.Reverse(r)
	y,err:=s.AssessRevisions("alpha",revAuth,revEnd,r)
	if err!=nil||!reflect.DeepEqual(x,y){t.Fatal("order dependence",err)}
	// Revisiting earlier acquisition time after learning corrections is stable.
	early,err:=s.AssessRevisions("alpha",revAuth,revAuth,r)
	if err!=nil||early.Assessment.Find("gate.open").Status!=Supported||len(early.Applied)!=0{t.Fatal("history rewritten",early,err)}
}

func TestRevisionRejectsScopeForgeryAndCycles(t *testing.T){
	cases:=[]struct{name,want string; mutate func(*Store,*[]Revision)}{
		{"unknown","REVISION_IDENTITY_INVALID",func(s *Store,r *[]Revision){(*r)[0].PredecessorID="missing"}},
		{"foreign","REVISION_SCOPE_INVALID",func(s *Store,r *[]Revision){(*r)[0].SuccessorID="foreign"}},
		{"lineage","REVISION_SCOPE_INVALID",func(s *Store,r *[]Revision){(*r)[0].PredecessorID="other"}},
		{"predicate","REVISION_SCOPE_INVALID",func(s *Store,r *[]Revision){s.Claims[1].Predicate="other.p"}},
		{"planned","REVISION_SCOPE_INVALID",func(s *Store,r *[]Revision){s.Claims[1].Modality="planned"}},
		{"quote","REVISION_QUOTE_UNANCHORED",func(s *Store,r *[]Revision){(*r)[0].Quote="not present"}},
		{"author-order","REVISION_AUTHOR_ORDER",func(s *Store,r *[]Revision){s.Sources[1].AuthoredAt="2026-05-30T00:00:00Z"}},
		{"duplicate","REVISION_IDENTITY_INVALID",func(s *Store,r *[]Revision){*r=append(*r,(*r)[0])}},
		{"missing-recorded","REVISION_RECORDED_CLOCK_INVALID",func(s *Store,r *[]Revision){(*r)[0].RecordedAt=""}},
		{"premature-recorded","REVISION_RECORDED_BEFORE_EVIDENCE",func(s *Store,r *[]Revision){(*r)[0].RecordedAt=revAuth}},
		{"cycle","REVISION_CYCLE",func(s *Store,r *[]Revision){s.Sources[1].AuthoredAt=revStart;*r=append(*r,Revision{ID:"r2",PredecessorID:"new",SuccessorID:"old",Quote:"Gate is open.",RecordedAt:revKnown})}},
	}
	for _,c:=range cases{t.Run(c.name,func(t *testing.T){
		s,r:=revisionFixture();c.mutate(&s,&r)
		_,err:=s.AssessRevisions("alpha",revAuth,revKnown,r)
		if err==nil||!strings.Contains(err.Error(),c.want){t.Fatalf("want %s, got %v",c.want,err)}
	})}
}

func TestCorrectionReviewCannotRewriteEarlierKnowledge(t *testing.T){
	s,r:=revisionFixture()
	r[0].RecordedAt="2026-06-07T00:00:00Z"
	early,err:=s.AssessRevisions("alpha",revAuth,revKnown,r)
	if err!=nil{t.Fatal(err)}
	old:=early.Assessment.Find("gate.open")
	if old.Status!=Both||!slices.Equal(old.SupportingSourceIDs,[]string{"a","c"})||
		!slices.Equal(old.RefutingSourceIDs,[]string{"b"})||len(early.Applied)!=0{
		t.Fatalf("review leaked into historical knowledge: %+v",early)
	}
	late,err:=s.AssessRevisions("alpha",revAuth,r[0].RecordedAt,r)
	if err!=nil{t.Fatal(err)}
	newBelief:=late.Assessment.Find("gate.open")
	if newBelief.Status!=Both||!slices.Equal(newBelief.SupportingSourceIDs,[]string{"c"})||
		len(late.Applied)!=1||late.Applied[0].RecordedAt!=r[0].RecordedAt{
		t.Fatalf("recorded correction was not applied: %+v",late)
	}
}
