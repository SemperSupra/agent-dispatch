package reviewauthority

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	inventory "sempersupra/mail-evidence-challenge/review_inventory"
)
const d1="2026-06-01T00:00:00Z"
const d2="2026-06-02T00:00:00Z"
const d3="2026-06-03T00:00:00Z"
const d4="2026-06-04T00:00:00Z"
const d5="2026-06-05T00:00:00Z"
const d6="2026-06-06T00:00:00Z"
const d7="2026-06-07T00:00:00Z"
func key(label string)ed25519.PrivateKey{h:=sha256.Sum256([]byte(label));return ed25519.NewKeyFromSeed(h[:])}
type fixture struct{scope Scope;root,reviewer,other ed25519.PrivateKey;events []SignedEvent}
func (f *fixture)add(e Event){
	e.Schema=Schema;e.Scope=f.scope;e.Sequence=uint64(len(f.events)+1);e.PreviousSHA256=genesis
	if len(f.events)>0{var err error;e.PreviousSHA256,err=EventDigest(f.events[len(f.events)-1]);if err!=nil{panic(err)}}
	raw,err:=EventBytes(e);if err!=nil{panic(err)}
	f.events=append(f.events,SignedEvent{Event:e,Signature:ed25519.Sign(f.root,raw)})
}
func (f fixture)trust()Trust{
	h,err:=EventDigest(f.events[len(f.events)-1]);if err!=nil{panic(err)}
	return Trust{Scope:f.scope,RootKey:f.root.Public().(ed25519.PublicKey),HeadSHA256:h}
}
func reg(kind,id,reviewer string,sourceIDs ...string)*Registration{
	return &Registration{Kind:kind,ID:id,PayloadSHA256:hash([]byte(kind+":"+id)),
		ReviewerID:reviewer,ProducerID:"producer",SourceIDs:sourceIDs}
}
func sample()fixture{
	f:=fixture{scope:Scope{CatalogID:"synthetic-catalog",Tenant:"alpha",PolicySHA256:hash([]byte("policy"))},
		root:key("fictional-root"),reviewer:key("fictional-reviewer"),other:key("fictional-rotation")}
	f.add(Event{Kind:"grant",RecordedAt:d1,Grant:&Grant{ID:"r1",PublicKey:f.reviewer.Public().(ed25519.PublicKey),NotBefore:d1,NotAfter:d6}})
	f.add(Event{Kind:"review",RecordedAt:d2,Review:reg("source","old","r1","old")})
	f.add(Event{Kind:"review",RecordedAt:d2,Review:reg("source","new","r1","new")})
	f.add(Event{Kind:"seal",RecordedAt:d2})
	f.add(Event{Kind:"review",RecordedAt:d3,Review:reg("revision","correction","r1","old","new")})
	f.add(Event{Kind:"revoke",RecordedAt:d4,RevokedID:"r1"})
	f.add(Event{Kind:"grant",RecordedAt:d4,Grant:&Grant{ID:"r2",PublicKey:f.other.Public().(ed25519.PublicKey),NotBefore:d4,NotAfter:d7}})
	f.add(Event{Kind:"review",RecordedAt:d5,Review:reg("source","next","r2","next")})
	f.add(Event{Kind:"seal",RecordedAt:d5})
	return f
}
func scope(f fixture,known string)inventory.Scope{
	return inventory.Scope{Tenant:f.scope.Tenant,PolicySHA256:f.scope.PolicySHA256,
		Partition:"heldout",TaskID:"Q",Group:"gate",Predicate:"gate.open",ValidAt:d2,KnownAt:known,
		ContextSHA256:hash([]byte("context"))}
}
func TestReplayRotationAndHistoricalProjection(t *testing.T){
	f:=sample();trust:=f.trust()
	c,err:=Replay(trust,f.events);if err!=nil{t.Fatal(err)}
	before,err:=c.Project(scope(f,d2),[]string{"old","new"})
	if err!=nil||len(before.Admissions)!=2||len(before.Grants)!=1{t.Fatal(before,err)}
	now,err:=c.Project(scope(f,d5),[]string{"old","new","next"})
	if err!=nil||len(now.Admissions)!=4||len(now.Grants)!=2{t.Fatal(now,err)}
	if now.Grants[0].ID!="r1"||now.Grants[1].ID!="r2"{t.Fatal("lost historical grant")}
	// A real serialization/reload replay; not a claim of durable disk storage.
	raw,err:=json.Marshal(f.events);if err!=nil{t.Fatal(err)}
	var recovered []SignedEvent
	if err=json.Unmarshal(raw,&recovered);err!=nil{t.Fatal(err)}
	reopened,err:=Replay(trust,recovered);if err!=nil{t.Fatal(err)}
	again,err:=reopened.Project(scope(f,d5),[]string{"next","new","old"})
	if err!=nil||!reflect.DeepEqual(now,again){t.Fatal("replay drift",err)}
	// The derived inventory must contain the correction even if a caller omits it.
	observed:=slices.DeleteFunc(slices.Clone(now.Manifest.Entries),func(e inventory.Entry)bool{return e.Kind=="revision"})
	if _,err=inventory.Verify(now.Manifest.Scope,now.ManifestSHA256,now.Manifest,observed);err==nil{t.Fatal("omission accepted")}
	// Caller mutations must not affect the verified catalog.
	now.Grants[0].PublicKey[0]^=1
	now.Admissions[0].SourceIDs[0]="tamper"
	recovered[0].Event.Grant.PublicKey[0]^=1
	after,err:=reopened.Project(scope(f,d5),[]string{"old","new","next"})
	if err!=nil||!reflect.DeepEqual(again,after){t.Fatal("catalog alias",err)}
}
func TestHeadSealAndTamper(t *testing.T){
	f:=sample();trust:=f.trust()
	for _,name:=range []string{"truncated","reordered","tampered","foreign-root","bad-head"}{
		t.Run(name,func(t *testing.T){
			x:=sample();ts:=trust
			switch name{
			case "truncated":x.events=x.events[:4]
			case "reordered":x.events[1],x.events[2]=x.events[2],x.events[1]
			case "tampered":x.events[1].Event.Review.PayloadSHA256=hash([]byte("tamper"))
			case "foreign-root":ts.RootKey=key("foreign").Public().(ed25519.PublicKey)
			case "bad-head":ts.HeadSHA256=hash([]byte("different"))
			}
			if _,err:=Replay(ts,x.events);err==nil{t.Fatal("accepted",name)}
		})
	}
	c,err:=Replay(trust,f.events);if err!=nil{t.Fatal(err)}
	for _,v:=range []struct{known string;ids []string}{{d6,[]string{"old"}},{d1,[]string{"old"}},{d5,[]string{"old","old"}},{d5,[]string{"missing"}}}{
		if _,err=c.Project(scope(f,v.known),v.ids);err==nil{t.Fatal("accepted",v)}
	}
}
func TestRootSignedInvalidLifecycleFailsClosed(t *testing.T){
	for _,name:=range []string{"revoked","expired","backdated","reuse-id","reuse-key","root-as-reviewer","unknown-source","duplicate-review"}{
		t.Run(name,func(t *testing.T){
			f:=sample()
			var e Event;want:=""
			switch name{
			case "revoked":e=Event{Kind:"review",RecordedAt:d6,Review:reg("source","late","r1","late")};want="REVIEWER_NOT_ACTIVE"
			case "expired":e=Event{Kind:"review",RecordedAt:d7,Review:reg("source","late","r2","late")};want="REVIEWER_NOT_ACTIVE"
			case "backdated":e=Event{Kind:"review",RecordedAt:d5,Review:reg("source","late","r2","late")};want="CHAIN_OR_CLOCK"
			case "reuse-id":e=Event{Kind:"grant",RecordedAt:d6,Grant:&Grant{ID:"r1",PublicKey:key("new").Public().(ed25519.PublicKey),NotBefore:d6,NotAfter:d7}};want="GRANT_REUSE"
			case "reuse-key":e=Event{Kind:"grant",RecordedAt:d6,Grant:&Grant{ID:"r3",PublicKey:f.reviewer.Public().(ed25519.PublicKey),NotBefore:d6,NotAfter:d7}};want="GRANT_REUSE"
			case "root-as-reviewer":e=Event{Kind:"grant",RecordedAt:d6,Grant:&Grant{ID:"root",PublicKey:f.root.Public().(ed25519.PublicKey),NotBefore:d6,NotAfter:d7}};want="GRANT_REUSE"
			case "unknown-source":e=Event{Kind:"review",RecordedAt:d6,Review:reg("revision","bad","r2","old","missing")};want="REVISION_BEFORE_SOURCE"
			case "duplicate-review":e=Event{Kind:"review",RecordedAt:d6,Review:reg("source","old","r2","old")};want="REVIEW_ID_REUSED"
			}
			f.add(e);f.add(Event{Kind:"seal",RecordedAt:"2026-06-08T00:00:00Z"})
			if _,err:=Replay(f.trust(),f.events);err==nil||!strings.Contains(err.Error(),want){t.Fatalf("want %s got %v",want,err)}
		})
	}
}
