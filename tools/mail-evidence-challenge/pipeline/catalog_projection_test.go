package pipeline

import (
	"crypto/ed25519"
	"crypto/sha256"
	"reflect"
	"strings"
	"testing"

	authority "sempersupra/mail-evidence-challenge/review_authority"
	logic "sempersupra/mail-evidence-challenge/temporal_logic"
)

func catalogForReview(t *testing.T,f reviewedFixture,variant string)*authority.Catalog{
	t.Helper()
	seed:=sha256.Sum256([]byte("fictional independent catalog root/v1"))
	root:=ed25519.NewKeyFromSeed(seed[:])
	scope:=authority.Scope{CatalogID:"test-catalog",Tenant:f.q.Tenant,PolicySHA256:f.policy}
	events:=[]authority.SignedEvent{}
	head:=strings.Repeat("0",64)
	add:=func(e authority.Event){
		e.Schema=authority.Schema;e.Scope=scope;e.Sequence=uint64(len(events)+1);e.PreviousSHA256=head
		raw,err:=authority.EventBytes(e);if err!=nil{t.Fatal(err)}
		s:=authority.SignedEvent{Event:e,Signature:ed25519.Sign(root,raw)}
		events=append(events,s)
		head,err=authority.EventDigest(s);if err!=nil{t.Fatal(err)}
	}
	g:=f.grants[0]
	add(authority.Event{Kind:"grant",RecordedAt:rev1,Grant:&authority.Grant{ID:g.ID,
		PublicKey:g.PublicKey,NotBefore:g.NotBefore,NotAfter:g.NotAfter}})
	for i,signed:=range f.bundle.Sources{
		a:=signed.Payload;raw,err:=SourceReviewBytes(a);if err!=nil{t.Fatal(err)}
		r:=&authority.Registration{Kind:"source",ID:a.SourceID,PayloadSHA256:digest(raw),
			ReviewerID:a.Identity.ReviewerID,ProducerID:a.Identity.ProducerID,SourceIDs:[]string{a.SourceID}}
		if variant=="wrong-producer"&&i==0{r.ProducerID="other"}
		add(authority.Event{Kind:"review",RecordedAt:a.Identity.RecordedAt,Review:r})
	}
	add(authority.Event{Kind:"seal",RecordedAt:rev2})
	for _,signed:=range f.bundle.Revisions{
		a:=signed.Payload;raw,err:=RevisionReviewBytes(a);if err!=nil{t.Fatal(err)}
		r:=&authority.Registration{Kind:"revision",ID:a.Revision.ID,PayloadSHA256:digest(raw),
			ReviewerID:a.Identity.ReviewerID,ProducerID:a.Identity.ProducerID,SourceIDs:[]string{"old","new"}}
		if variant=="wrong-endpoints"{r.SourceIDs=[]string{"new","old"}}
		at:=a.Identity.RecordedAt;if variant=="wrong-clock"{at=rev4}
		add(authority.Event{Kind:"review",RecordedAt:at,Review:r})
	}
	// A registered earlier review survives prospective revocation.
	add(authority.Event{Kind:"revoke",RecordedAt:rev4,RevokedID:g.ID})
	add(authority.Event{Kind:"seal",RecordedAt:rev4})
	c,err:=authority.Replay(authority.Trust{Scope:scope,RootKey:root.Public().(ed25519.PublicKey),HeadSHA256:head},events)
	if err!=nil{t.Fatal(err)}
	return c
}

func TestCatalogBoundProjectionAndHistoricalReplay(t *testing.T){
	for _,lang:=range []string{"en","de","th"}{t.Run(lang,func(t *testing.T){
		f:=reviewed(t,lang);c:=catalogForReview(t,f,"")
		got,err:=f.s.PrepareCatalogReviewedProjection(f.q,rev2,f.policy,c,f.bundle)
		if err!=nil||got.Projection.Status!=logic.Refuted||got.Projection.Model==nil||
			len(got.Projection.Model.Spans)!=1||len(got.CatalogHeadSHA256)!=64{t.Fatal(got,err)}
		f.bundle.Sources[0],f.bundle.Sources[1]=f.bundle.Sources[1],f.bundle.Sources[0]
		again,err:=f.s.PrepareCatalogReviewedProjection(f.q,rev2,f.policy,c,f.bundle)
		if err!=nil||!reflect.DeepEqual(got,again){t.Fatal("replay drift",err)}
		f.q.KnownAt=rev2
		// Only registered historical payloads belong to the submitted bundle.
		if _,err=f.s.PrepareCatalogReviewedProjection(f.q,rev2,f.policy,c,f.bundle);err==nil{t.Fatal("future review submitted")}
		f.bundle.Revisions=nil
		early,err:=f.s.PrepareCatalogReviewedProjection(f.q,rev2,f.policy,c,f.bundle)
		if err!=nil||early.Projection.Status!=logic.Both||early.Projection.Model!=nil||len(early.Projection.AuditSpans)!=2{t.Fatal(early,err)}
	})}
}
func TestCatalogProjectionRefusesOmittedOrUnregisteredPayloads(t *testing.T){
	for _,variant:=range []string{"omitted-correction","mutated-payload","wrong-producer","wrong-endpoints","wrong-clock","tampered-review-signature","unsealed","nil-catalog"}{
		t.Run(variant,func(t *testing.T){
			f:=reviewed(t,"en");c:=catalogForReview(t,f,variant)
			switch variant{
			case "omitted-correction":f.bundle.Revisions=nil
			case "mutated-payload":f.bundle.Sources[0].Payload.Claims[0].Claim.ValidFrom=rev2;f.signSource(0)
			case "tampered-review-signature":f.bundle.Sources[0].Signature[0]^=1
			case "unsealed":f.q.KnownAt=rev5
			case "nil-catalog":c=nil
			}
			if _,err:=f.s.PrepareCatalogReviewedProjection(f.q,rev2,f.policy,c,f.bundle);err==nil{t.Fatal("accepted",variant)}
		})
	}
}
func TestCatalogProjectionEmptyVisibleEvidenceAbstains(t *testing.T){
	f:=reviewed(t,"th");c:=catalogForReview(t,f,"")
	f.q.KnownAt="2026-05-31T00:00:00Z"
	got,err:=f.s.PrepareCatalogReviewedProjection(f.q,rev2,f.policy,c,ReviewBundle{})
	if err!=nil||got.Projection.Status!=logic.Neither||got.Projection.Model!=nil||
		got.Projection.Receipt.Inventory.SourceCount!=0{t.Fatal(got,err)}
}
