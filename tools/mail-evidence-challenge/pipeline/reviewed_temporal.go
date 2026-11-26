package pipeline

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"
	"unicode/utf8"

	logic "sempersupra/mail-evidence-challenge/temporal_logic"
)

const reviewSchema="mail-reviewed-temporal-annotation/v1"

// Trust is configured by the trusted caller, never parsed from model output or
// the signed envelope. This contract does not authenticate the caller or
// provision production reviewer keys.
type ReviewerGrant struct {
	ID,Tenant,PolicySHA256 string
	PublicKey ed25519.PublicKey
	NotBefore,NotAfter string
}

type ReviewIdentity struct {
	Tenant,PolicySHA256,ReviewerID,ProducerID,RecordedAt string
}

// ReviewedClaim identifies the exact half-open UTF-8 span. The reviewed
// interpretation is signed, not inferred merely because the quote occurs.
type ReviewedClaim struct {
	Claim logic.Claim
	Begin,End int
}

type SourceAnnotation struct {
	Identity ReviewIdentity
	SourceID,SourceSHA256,AcquiredAt,AuthoredAt,Lineage string
	Claims []ReviewedClaim
}

type SignedSourceAnnotation struct {
	Payload SourceAnnotation
	Signature []byte
}

type RevisionAnnotation struct {
	Identity ReviewIdentity
	Revision logic.Revision
	PredecessorReviewSHA256,SuccessorReviewSHA256 string
	Begin,End int
}

type SignedRevisionAnnotation struct {
	Payload RevisionAnnotation
	Signature []byte
}

type ReviewBundle struct {
	Sources []SignedSourceAnnotation
	Revisions []SignedRevisionAnnotation
}

type ReviewReceipt struct {
	Schema,Tenant,TaskID,ValidAt,KnownAt,PolicySHA256,ContextSHA256 string
	SourceReviewSHA256,RevisionReviewSHA256 []string
	Assessment logic.RevisionAssessment
}

// Canonical bytes use a versioned domain and Go struct JSON encoding. Strings
// are exact (no Unicode or timezone coercion). This is a v1 Go wire contract,
// not a cross-language canonicalization standard. Sign only these bytes.
func utf8Strings(values ...string)bool{
	for _,s:=range values{if !utf8.ValidString(s){return false}}
	return true
}
func validReviewIdentityText(a ReviewIdentity)bool{
	return utf8Strings(a.Tenant,a.PolicySHA256,a.ReviewerID,a.ProducerID,a.RecordedAt)
}
func SourceReviewBytes(a SourceAnnotation)([]byte,error){
	// Go JSON replaces invalid UTF-8; reject it before signing to avoid
	// two different in-memory interpretations with identical wire bytes.
	if !validReviewIdentityText(a.Identity)||!utf8Strings(a.SourceID,a.SourceSHA256,a.AcquiredAt,a.AuthoredAt,a.Lineage){
		return nil,errors.New("REVIEW_UTF8_INVALID")
	}
	for _,x:=range a.Claims{
		c:=x.Claim
		if !utf8Strings(c.ID,c.SourceID,c.Predicate,c.Modality,c.Quote,c.ValidFrom,c.ValidTo){
			return nil,errors.New("REVIEW_UTF8_INVALID")
		}
	}
	return json.Marshal(struct{Schema,Kind string;Payload SourceAnnotation}{reviewSchema,"source",a})
}
func RevisionReviewBytes(a RevisionAnnotation)([]byte,error){
	r:=a.Revision
	if !validReviewIdentityText(a.Identity)||
		!utf8Strings(r.ID,r.PredecessorID,r.SuccessorID,r.Quote,r.RecordedAt,a.PredecessorReviewSHA256,a.SuccessorReviewSHA256){
		return nil,errors.New("REVIEW_UTF8_INVALID")
	}
	return json.Marshal(struct{Schema,Kind string;Payload RevisionAnnotation}{reviewSchema,"revision",a})
}

func hexDigest(v string)bool{
	b,err:=hex.DecodeString(v)
	return err==nil&&len(b)==32&&hex.EncodeToString(b)==v
}
func stamp(v string)(time.Time,error){return time.Parse(time.RFC3339,v)}
func exactSpan(body,quote string,start,end int)bool{
	return utf8.ValidString(body)&&quote!=""&&start>=0&&end>start&&end<=len(body)&&
		utf8.RuneStart(body[start])&&(end==len(body)||utf8.RuneStart(body[end]))&&body[start:end]==quote
}

func verifyReview(id ReviewIdentity, grantMap map[string]ReviewerGrant, tenant,policy string, payload,signature []byte)(time.Time,error){
	var zero time.Time
	g,ok:=grantMap[id.ReviewerID]
	if !ok||id.Tenant!=tenant||g.Tenant!=tenant||id.PolicySHA256!=policy||
		g.PolicySHA256!=policy||id.ProducerID==""||id.ProducerID==id.ReviewerID||
		len(g.PublicKey)!=ed25519.PublicKeySize||len(signature)!=ed25519.SignatureSize{
		return zero,errors.New("REVIEW_AUTHORITY_INVALID")
	}
	at,err:=stamp(id.RecordedAt)
	if err!=nil{return zero,errors.New("REVIEW_CLOCK_INVALID")}
	from,err:=stamp(g.NotBefore)
	if err!=nil{return zero,errors.New("REVIEW_GRANT_CLOCK_INVALID")}
	to,err:=stamp(g.NotAfter)
	if err!=nil||!to.After(from)||at.Before(from)||!at.Before(to){return zero,errors.New("REVIEW_GRANT_EXPIRED_OR_NOT_YET_VALID")}
	if !ed25519.Verify(g.PublicKey,payload,signature){return zero,errors.New("REVIEW_SIGNATURE_INVALID")}
	return at,nil
}

// AssessReviewedTemporal admits only independently configured, signed,
// source-bound annotations. All visible source occurrences require reviewed
// coverage (including explicitly empty claim sets); incomplete or later-only
// source review fails closed instead of dropping inconvenient evidence.
// Revisions are individually signed and bound to both source-review digests.
// No rule injection or automatic annotation, writeback, or key provisioning.
// Signature verification proves key possession and integrity, not the semantic
// correctness, human independence or real-world authority of the interpretation.
func (s *Session) AssessReviewedTemporal(t Task,validAt,policy string,grants []ReviewerGrant,bundle ReviewBundle)(ReviewReceipt,error){
	var zero ReviewReceipt
	if !hexDigest(policy)||len(grants)==0||len(grants)>64||
		len(bundle.Sources)>MaxObservations||len(bundle.Revisions)>4096{
		return zero,errors.New("REVIEW_BOUND_OR_POLICY_INVALID")
	}
	visible,err:=s.visible(t);if err!=nil{return zero,err}
	ctx,err:=s.Prepare(t);if err!=nil{return zero,err}
	known,err:=stamp(t.KnownAt);if err!=nil{return zero,err}
	if _,err:=stamp(validAt);err!=nil{return zero,errors.New("INVALID_QUERY_VALID_TIME")}
	byID:=map[string]int{}
	for i,o:=range visible{byID[o.ID]=i}
	if len(bundle.Sources)!=len(visible){return zero,errors.New("REVIEW_SOURCE_COVERAGE_INCOMPLETE")}
	gm:=map[string]ReviewerGrant{}
	for _,g:=range grants{
		if g.ID==""||g.Tenant!=t.Tenant||g.PolicySHA256!=policy||
			len(g.PublicKey)!=ed25519.PublicKeySize{return zero,errors.New("REVIEW_GRANT_SCOPE_INVALID")}
		if _,ok:=gm[g.ID];ok{return zero,errors.New("REVIEW_GRANT_DUPLICATE")}
		gm[g.ID]=g
	}
	out:=ReviewReceipt{Schema:reviewSchema,Tenant:t.Tenant,TaskID:t.ID,ValidAt:validAt,
		KnownAt:t.KnownAt,PolicySHA256:policy,ContextSHA256:ctx.SHA256,
		SourceReviewSHA256:[]string{},RevisionReviewSHA256:[]string{}}
	store:=logic.Store{}
	type claimReview struct{digest string;at time.Time;claim logic.Claim}
	claimByID:=map[string]claimReview{}
	for _,signed:=range bundle.Sources{
		a:=signed.Payload
		i,ok:=byID[a.SourceID]
		if !ok{return zero,errors.New("REVIEW_SOURCE_SCOPE_INVALID")}
		o:=visible[i]
		if a.SourceSHA256!=o.SHA256||a.AcquiredAt!=o.CapturedAt||a.Lineage==""||
			len(a.Claims)>128||a.Identity.Tenant!=o.Tenant{
			return zero,errors.New("REVIEW_SOURCE_BINDING_INVALID")
		}
		raw,err:=SourceReviewBytes(a);if err!=nil{return zero,err}
		if len(raw)>MaxBodyBytes{return zero,errors.New("REVIEW_PAYLOAD_BOUND")}
		at,err:=verifyReview(a.Identity,gm,t.Tenant,policy,raw,signed.Signature);if err!=nil{return zero,err}
		acquired,_:=stamp(o.CapturedAt)
		authored,err:=stamp(a.AuthoredAt)
		if err!=nil||authored.After(acquired)||at.Before(acquired){return zero,errors.New("REVIEW_SOURCE_CLOCK_INVALID")}
		if at.After(known){return zero,errors.New("REVIEW_SOURCE_NOT_YET_KNOWN")}
		d:=digest(raw)
		for _,c:=range a.Claims{
			if c.Claim.ID==""||c.Claim.SourceID!=o.ID||
				!exactSpan(o.Raw,c.Claim.Quote,c.Begin,c.End){
				return zero,errors.New("REVIEW_CLAIM_SPAN_INVALID")
			}
			if _,ok:=claimByID[c.Claim.ID];ok{return zero,errors.New("REVIEW_CLAIM_ID_DUPLICATE")}
			claimByID[c.Claim.ID]=claimReview{d,at,c.Claim}
			store.Claims=append(store.Claims,c.Claim)
		}
		store.Sources=append(store.Sources,logic.Source{ID:o.ID,Tenant:o.Tenant,
			Raw:o.Raw,SHA256:o.SHA256,Lineage:a.Lineage,
			AuthoredAt:a.AuthoredAt,AcquiredAt:o.CapturedAt})
		delete(byID,o.ID)
		out.SourceReviewSHA256=append(out.SourceReviewSHA256,d)
	}
	var revisions []logic.Revision
	seenRevisions:=map[string]bool{}
	for _,signed:=range bundle.Revisions{
		a:=signed.Payload;r:=a.Revision
		old,ok1:=claimByID[r.PredecessorID];new,ok2:=claimByID[r.SuccessorID]
		if !ok1||!ok2||r.ID==""||seenRevisions[r.ID]||
			a.PredecessorReviewSHA256!=old.digest||a.SuccessorReviewSHA256!=new.digest||
			r.RecordedAt!=a.Identity.RecordedAt{return zero,errors.New("REVIEW_REVISION_BINDING_INVALID")}
		seenRevisions[r.ID]=true
		raw,err:=RevisionReviewBytes(a);if err!=nil{return zero,err}
		if len(raw)>MaxBodyBytes{return zero,errors.New("REVIEW_PAYLOAD_BOUND")}
		at,err:=verifyReview(a.Identity,gm,t.Tenant,policy,raw,signed.Signature);if err!=nil{return zero,err}
		if at.Before(old.at)||at.Before(new.at){return zero,errors.New("REVIEW_REVISION_BEFORE_CLAIM_REVIEW")}
		source,ok:=s.source[new.claim.SourceID]
		if !ok||!exactSpan(source.Raw,r.Quote,a.Begin,a.End){return zero,errors.New("REVIEW_REVISION_SPAN_INVALID")}
		// Future recorded reviews do not enter the historical assessment or its
		// receipt. They are validated for integrity but not applied.
		if at.After(known){continue}
		revisions=append(revisions,r)
		out.RevisionReviewSHA256=append(out.RevisionReviewSHA256,digest(raw))
	}
	sort.Strings(out.SourceReviewSHA256)
	sort.Strings(out.RevisionReviewSHA256)
	out.Assessment,err=s.AssessTemporal(t,validAt,store,revisions)
	if err!=nil{return zero,err}
	return out,nil
}
