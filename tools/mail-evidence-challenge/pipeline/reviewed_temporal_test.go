package pipeline

import (
	"crypto/ed25519"
	"crypto/sha256"
	"reflect"
	"slices"
	"strings"
	"testing"

	evidence "sempersupra/mail-evidence-challenge"
	logic "sempersupra/mail-evidence-challenge/temporal_logic"
)

const (
	rev1="2026-06-01T00:00:00Z"
	rev2="2026-06-02T00:00:00Z"
	rev3="2026-06-03T00:00:00Z"
	rev4="2026-06-04T00:00:00Z"
	rev5="2026-06-05T00:00:00Z"
)
type reviewedFixture struct{
	s *Session
	q Task
	policy string
	grants []ReviewerGrant
	bundle ReviewBundle
	key ed25519.PrivateKey
}
func (f *reviewedFixture) signSource(i int)string{
	raw,err:=SourceReviewBytes(f.bundle.Sources[i].Payload);if err!=nil{panic(err)}
	f.bundle.Sources[i].Signature=ed25519.Sign(f.key,raw)
	return digest(raw)
}
func (f *reviewedFixture) signRevision(){
	raw,err:=RevisionReviewBytes(f.bundle.Revisions[0].Payload);if err!=nil{panic(err)}
	f.bundle.Revisions[0].Signature=ed25519.Sign(f.key,raw)
}
func reviewed(t *testing.T,lang string)reviewedFixture{
	t.Helper()
	// Deterministic test key only; never admit this key in production.
	seed:=sha256.Sum256([]byte("public-fictional-review-test-key/v1"))
	key:=ed25519.NewKeyFromSeed(seed[:])
	policy:=digest([]byte("synthetic-review-policy/v1"))
	pair:=map[string][2]string{
		"en":{"Gate is open.","Correction: gate is closed."},
		"de":{"Tor ist geöffnet.","Korrektur: Tor ist geschlossen."},
		"th":{"ประตูเปิด","แก้ไข: ประตูปิด"},
	}[lang]
	obs:=[]evidence.Observation{
		{ID:"old",Archive:"a",Locator:"1",Tenant:"alpha",Raw:pair[0],CapturedAt:rev1},
		{ID:"new",Archive:"a",Locator:"2",Tenant:"alpha",Raw:pair[1],CapturedAt:rev2},
		{ID:"dev",Archive:"d",Locator:"1",Tenant:"alpha",Raw:"Separate development source.",CapturedAt:rev1},
	}
	for i:=range obs{obs[i].SHA256=digest([]byte(obs[i].Raw))}
	s,err:=New(evidence.Ledger{Schema:evidence.Schema,Observations:obs},Split{DevIDs:[]string{"dev"},HeldoutIDs:[]string{"old","new"}})
	if err!=nil{t.Fatal(err)}
	f:=reviewedFixture{s:s,q:Task{ID:"Q",Tenant:"alpha",Group:"gate",Key:"gate.open",
		Language:lang,Question:"Gate status?",KnownAt:rev4,Partition:Heldout},policy:policy,key:key,
		grants:[]ReviewerGrant{{ID:"reviewer",Tenant:"alpha",PolicySHA256:policy,
			PublicKey:key.Public().(ed25519.PublicKey),NotBefore:rev1,NotAfter:rev5}}}
	for i,o:=range obs[:2]{
		p:=logic.Supports;if i==1{p=logic.Refutes}
		c:=logic.Claim{ID:o.ID+"-claim",SourceID:o.ID,Predicate:"gate.open",Modality:"actual",
			Quote:o.Raw,ValidFrom:o.CapturedAt,Polarity:p}
		a:=SourceAnnotation{Identity:ReviewIdentity{Tenant:"alpha",PolicySHA256:policy,
			ReviewerID:"reviewer",ProducerID:"extractor",RecordedAt:rev2},SourceID:o.ID,
			SourceSHA256:o.SHA256,AcquiredAt:o.CapturedAt,AuthoredAt:o.CapturedAt,Lineage:"gate",
			Claims:[]ReviewedClaim{{Claim:c,Begin:0,End:len(o.Raw)}}}
		f.bundle.Sources=append(f.bundle.Sources,SignedSourceAnnotation{Payload:a})
	}
	old,new:=f.signSource(0),f.signSource(1)
	r:=logic.Revision{ID:"review-1",PredecessorID:"old-claim",SuccessorID:"new-claim",Quote:pair[1],RecordedAt:rev3}
	f.bundle.Revisions=[]SignedRevisionAnnotation{{Payload:RevisionAnnotation{
		Identity:ReviewIdentity{Tenant:"alpha",PolicySHA256:policy,ReviewerID:"reviewer",ProducerID:"extractor",RecordedAt:rev3},
		Revision:r,PredecessorReviewSHA256:old,SuccessorReviewSHA256:new,Begin:0,End:len(pair[1])}}}
	f.signRevision()
	return f
}
func (f reviewedFixture) assess()(ReviewReceipt,error){
	return f.s.AssessReviewedTemporal(f.q,rev2,f.policy,f.grants,f.bundle)
}
func TestSignedTemporalReviewAcrossLanguagesAndClocks(t *testing.T){
	for _,lang:=range []string{"en","de","th"}{
		t.Run(lang,func(t *testing.T){
			f:=reviewed(t,lang)
			got,err:=f.assess();if err!=nil{t.Fatal(err)}
			b:=got.Assessment.Assessment.Find("gate.open")
			if b.Status!=logic.Refuted||len(got.Assessment.Applied)!=1||
				len(got.SourceReviewSHA256)!=2||len(got.RevisionReviewSHA256)!=1||len(got.ContextSHA256)!=64{
				t.Fatalf("review assessment %+v",got)
			}
			slices.Reverse(f.bundle.Sources)
			replay,err:=f.assess();if err!=nil||!reflect.DeepEqual(got,replay){t.Fatal("order drift",err)}
			f.q.KnownAt=rev2
			early,err:=f.assess();if err!=nil{t.Fatal(err)}
			if early.Assessment.Assessment.Find("gate.open").Status!=logic.Both||
				len(early.RevisionReviewSHA256)!=0||len(early.Assessment.Applied)!=0{t.Fatal("future review leaked",early)}
		})
	}
}
func TestReviewRejectsUntrustedOrMutatedAnnotations(t *testing.T){
	tests:=[]struct{name,want string;mutate func(*reviewedFixture)}{
		{"polarity-tamper","REVIEW_SIGNATURE_INVALID",func(f *reviewedFixture){f.bundle.Sources[0].Payload.Claims[0].Claim.Polarity=logic.Refutes}},
		{"lineage-tamper","REVIEW_SIGNATURE_INVALID",func(f *reviewedFixture){f.bundle.Sources[0].Payload.Lineage="invented"}},
		{"clock-tamper","REVIEW_SIGNATURE_INVALID",func(f *reviewedFixture){f.bundle.Sources[0].Payload.Claims[0].Claim.ValidFrom=rev4}},
		{"signature-tamper","REVIEW_SIGNATURE_INVALID",func(f *reviewedFixture){f.bundle.Sources[0].Signature[0]^=1}},
		{"foreign-reviewer","REVIEW_GRANT_SCOPE_INVALID",func(f *reviewedFixture){f.grants[0].Tenant="beta"}},
		{"untrusted-key","REVIEW_SIGNATURE_INVALID",func(f *reviewedFixture){seed:=sha256.Sum256([]byte("another key"));f.grants[0].PublicKey=ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)}},
		{"expired-grant","REVIEW_GRANT_EXPIRED_OR_NOT_YET_VALID",func(f *reviewedFixture){f.grants[0].NotAfter=rev2}},
		{"self-review","REVIEW_AUTHORITY_INVALID",func(f *reviewedFixture){f.bundle.Sources[0].Payload.Identity.ProducerID="reviewer";f.signSource(0)}},
		{"wrong-source-digest","REVIEW_SOURCE_BINDING_INVALID",func(f *reviewedFixture){f.bundle.Sources[0].Payload.SourceSHA256=digest([]byte("different"));f.signSource(0)}},
		{"missing-coverage","REVIEW_SOURCE_COVERAGE_INCOMPLETE",func(f *reviewedFixture){f.bundle.Sources=f.bundle.Sources[:1]}},
		{"partial-rune","REVIEW_CLAIM_SPAN_INVALID",func(f *reviewedFixture){f.bundle.Sources[0].Payload.Claims[0].Begin=1;f.signSource(0)}},
		{"late-source-review","REVIEW_SOURCE_NOT_YET_KNOWN",func(f *reviewedFixture){f.bundle.Sources[0].Payload.Identity.RecordedAt=rev5;f.grants[0].NotAfter="2026-06-06T00:00:00Z";f.signSource(0)}},
		{"stale-revision-binding","REVIEW_REVISION_BINDING_INVALID",func(f *reviewedFixture){f.bundle.Sources[0].Payload.Claims[0].Claim.ValidFrom=rev2;f.signSource(0)}},
		{"revision-tamper","REVIEW_SIGNATURE_INVALID",func(f *reviewedFixture){f.bundle.Revisions[0].Payload.Begin=1}},
		{"premature-revision","REVIEW_REVISION_BEFORE_CLAIM_REVIEW",func(f *reviewedFixture){f.bundle.Revisions[0].Payload.Identity.RecordedAt=rev1;f.bundle.Revisions[0].Payload.Revision.RecordedAt=rev1;f.signRevision()}},
	}
	for _,tc:=range tests{t.Run(tc.name,func(t *testing.T){
		f:=reviewed(t,"th");tc.mutate(&f);_,err:=f.assess()
		if err==nil||!strings.Contains(err.Error(),tc.want){t.Fatalf("expected %s got %v",tc.want,err)}
	})}
}
func TestExplicitReviewedEmptySourceIsNotAnAssertedFact(t *testing.T){
	f:=reviewed(t,"en")
	f.bundle.Revisions=nil
	f.bundle.Sources[0].Payload.Claims=nil
	f.bundle.Sources[1].Payload.Claims=nil
	f.signSource(0);f.signSource(1)
	got,err:=f.assess()
	if err!=nil||got.Assessment.Assessment.Find("gate.open").Status!=logic.Neither{t.Fatal("empty reviewed coverage invented truth",got,err)}
}

func TestReviewCanonicalWireRejectsInvalidUTF8(t *testing.T){
	f:=reviewed(t,"en")
	bad:=string([]byte{0xff})
	f.bundle.Sources[0].Payload.Lineage=bad
	if _,err:=SourceReviewBytes(f.bundle.Sources[0].Payload);err==nil{t.Fatal("lossy source canonicalization")}
	if _,err:=f.assess();err==nil{t.Fatal("accepted lossy source")}
	f=reviewed(t,"en")
	f.bundle.Sources[0].Payload.Claims[0].Claim.Predicate=bad
	if _,err:=SourceReviewBytes(f.bundle.Sources[0].Payload);err==nil{t.Fatal("lossy predicate canonicalization")}
	f=reviewed(t,"en")
	f.bundle.Revisions[0].Payload.Identity.ProducerID=bad
	if _,err:=RevisionReviewBytes(f.bundle.Revisions[0].Payload);err==nil{t.Fatal("lossy revision canonicalization")}
}
