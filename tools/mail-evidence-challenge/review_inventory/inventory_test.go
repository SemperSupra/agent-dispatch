package reviewinventory

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)
func fixture()(Manifest,string){
	s:=Scope{Tenant:"alpha",Partition:"heldout",TaskID:"Q",Group:"gate",Predicate:"gate.open",
		ValidAt:"2026-06-02T00:00:00Z",KnownAt:"2026-06-04T00:00:00Z",
		PolicySHA256:digest([]byte("policy")),ContextSHA256:digest([]byte("context"))}
	m:=Manifest{Schema:Schema,Scope:s,Entries:[]Entry{
		{Kind:"source",ID:"old",PayloadSHA256:digest([]byte("source-old")),RecordedAt:"2026-06-01T00:00:00Z"},
		{Kind:"source",ID:"new",PayloadSHA256:digest([]byte("source-new")),RecordedAt:"2026-06-02T00:00:00Z"},
		{Kind:"revision",ID:"review-1",PayloadSHA256:digest([]byte("revision")),RecordedAt:"2026-06-03T00:00:00Z"},
	}}
	pin,err:=Digest(m);if err!=nil{panic(err)}
	return m,pin
}
func TestExactInventoryOrderAndCoverage(t *testing.T){
	m,pin:=fixture()
	observed:=slices.Clone(m.Entries)
	first,err:=Verify(m.Scope,pin,m,observed)
	if err!=nil||first.SourceCount!=2||first.RevisionCount!=1{t.Fatal(first,err)}
	slices.Reverse(m.Entries)
	got,err:=Verify(m.Scope,pin,m,observed)
	if err!=nil||!reflect.DeepEqual(first,got){t.Fatal(got,err)}
}
func TestPinnedInventoryRejectsSubstitutionAndOmission(t *testing.T){
	for _,name:=range []string{"omit-correction","omit-source","replace-source","add-review","duplicate","future","stale-manifest","wrong-context","wrong-predicate","wrong-valid-at","wrong-cutoff","wrong-policy","unknown-kind","bad-pin"}{
		t.Run(name,func(t *testing.T){
			m,pin:=fixture();scope:=m.Scope;observed:=slices.Clone(m.Entries)
			switch name{
			case "omit-correction":observed=observed[:2]
			case "omit-source":observed=observed[1:]
			case "replace-source":observed[0].PayloadSHA256=digest([]byte("old-version"))
			case "add-review":observed=append(observed,Entry{Kind:"revision",ID:"unapproved",PayloadSHA256:digest([]byte("extra")),RecordedAt:m.Scope.KnownAt})
			case "duplicate":observed=append(observed,observed[0])
			case "future":observed[2].RecordedAt="2026-06-05T00:00:00Z"
			case "stale-manifest":m.Entries=m.Entries[:2];observed=observed[:2]
			case "wrong-context":scope.ContextSHA256=digest([]byte("other"))
			case "wrong-predicate":scope.Predicate="gate.closed"
			case "wrong-valid-at":scope.ValidAt="2026-06-03T00:00:00Z"
			case "wrong-cutoff":scope.KnownAt="2026-06-03T00:00:00Z"
			case "wrong-policy":scope.PolicySHA256=digest([]byte("other"))
			case "unknown-kind":observed[2].Kind="rule"
			case "bad-pin":pin=strings.Repeat("G",64)
			}
			if _,err:=Verify(scope,pin,m,observed);err==nil{t.Fatal("accepted",name)}
		})
	}
}
func TestIndependentCatalogPinCannotBeReplacedBySelfConsistentOmission(t *testing.T){
	m,pin:=fixture()
	m.Entries=m.Entries[:2]
	forged,err:=Digest(m);if err!=nil{t.Fatal(err)}
	if forged==pin{t.Fatal("digest collision")}
	if _,err:=Verify(m.Scope,pin,m,m.Entries);err==nil{t.Fatal("accepted rewritten history")}
	// This is why the pin must be independently trusted: self-consistency
	// alone is not authenticity and cannot detect a dishonest catalog.
	if _,err:=Verify(m.Scope,forged,m,m.Entries);err!=nil{t.Fatal("self-consistency control",err)}
}
func TestHistoricalCheckpointAndEmptyInventory(t *testing.T){
	m,_:=fixture();m.Scope.KnownAt="2026-06-02T00:00:00Z";m.Entries=m.Entries[:2]
	pin,err:=Digest(m);if err!=nil{t.Fatal(err)}
	got,err:=Verify(m.Scope,pin,m,m.Entries)
	if err!=nil||got.SourceCount!=2||got.RevisionCount!=0{t.Fatal(got,err)}
	m.Entries=nil
	pin,err=Digest(m);if err!=nil{t.Fatal(err)}
	got,err=Verify(m.Scope,pin,m,[]Entry{})
	if err!=nil||got.SourceCount!=0||got.RevisionCount!=0{t.Fatal(got,err)}
}
