package pipeline

import (
	"encoding/json"
	"errors"
	"slices"
	"sort"

	inventory "sempersupra/mail-evidence-challenge/review_inventory"
	logic "sempersupra/mail-evidence-challenge/temporal_logic"
)

// ClaimSpan is an exact original UTF-8 byte range, not a new source occurrence.
// The original body remains in the evidence ledger.
type ClaimSpan struct {
	ClaimID,SourceID,SourceSHA256,SourceReviewSHA256,Quote string
	Begin,End int
	Polarity logic.Polarity
}

type ReviewedModelContext struct {
	TaskID,Language,Question,Predicate,ValidAt,KnownAt,InventorySHA256 string
	Status logic.Status
	Spans []ClaimSpan
	SHA256 string
}

type ReviewedProjection struct {
	Receipt PinnedReviewReceipt
	Status logic.Status
	Disposition string
	AuditSpans []ClaimSpan
	Model *ReviewedModelContext // nil on unresolved conflict or unsupported predicate
}

// PrepareReviewedProjection derives exact active claim spans after both
// review and inventory verification. Source-level selection alone is not
// sufficient when one email contains several predicates or future statements.
// No complete raw message, unrelated claim, expired/future claim, superseded
// claim, gold answer, private key or review credential leaves Model.
func (s *Session) PrepareReviewedProjection(t Task,validAt,policy string,grants []ReviewerGrant,bundle ReviewBundle,manifest inventory.Manifest,trustedPin string)(ReviewedProjection,error){
	var zero ReviewedProjection
	r,err:=s.AssessPinnedReviewedTemporal(t,validAt,policy,grants,bundle,manifest,trustedPin)
	if err!=nil{return zero,err}
	return s.projectReviewed(t,validAt,bundle,r)
}

func (s *Session) projectReviewed(t Task,validAt string,bundle ReviewBundle,r PinnedReviewReceipt)(ReviewedProjection,error){
	var zero ReviewedProjection
	valid,err:=stamp(validAt);if err!=nil{return zero,err}
	belief:=r.Assessment.Assessment.Find(t.Key)
	suppressed:=map[string]bool{}
	for _,w:=range r.Assessment.Applied{suppressed[w.PredecessorID]=true}
	out:=ReviewedProjection{Receipt:r,Status:belief.Status,AuditSpans:[]ClaimSpan{}}
	pos,neg:=map[string]bool{},map[string]bool{}
	for _,signed:=range bundle.Sources{
		a:=signed.Payload
		raw,err:=SourceReviewBytes(a);if err!=nil{return zero,err}
		reviewSHA:=digest(raw)
		if !slices.Contains(r.SourceReviewSHA256,reviewSHA){return zero,errors.New("PROJECTION_REVIEW_NOT_ADMITTED")}
		for _,x:=range a.Claims{
			c:=x.Claim
			if c.Predicate!=t.Key||c.Modality!="actual"||suppressed[c.ID]{continue}
			from,err:=stamp(c.ValidFrom);if err!=nil{return zero,err}
			if from.After(valid){continue}
			if c.ValidTo!=""{
				end,err:=stamp(c.ValidTo);if err!=nil{return zero,err}
				if !valid.Before(end){continue}
			}
			if c.Polarity==logic.Supports{pos[c.SourceID]=true}else if c.Polarity==logic.Refutes{neg[c.SourceID]=true}else{return zero,errors.New("PROJECTION_POLARITY")}
			o,ok:=s.source[c.SourceID]
			if !ok||!exactSpan(o.Raw,c.Quote,x.Begin,x.End){return zero,errors.New("PROJECTION_SPAN_INVALID")}
			out.AuditSpans=append(out.AuditSpans,ClaimSpan{ClaimID:c.ID,SourceID:o.ID,
				SourceSHA256:o.SHA256,SourceReviewSHA256:reviewSHA,Quote:c.Quote,
				Begin:x.Begin,End:x.End,Polarity:c.Polarity})
		}
	}
	same:=func(ids []string,m map[string]bool)bool{
		if len(ids)!=len(m){return false};for _,id:=range ids{if !m[id]{return false}};return true
	}
	if !same(belief.SupportingSourceIDs,pos)||!same(belief.RefutingSourceIDs,neg){
		return zero,errors.New("PROJECTION_ASSESSMENT_DRIFT")
	}
	sort.Slice(out.AuditSpans,func(i,j int)bool{return out.AuditSpans[i].ClaimID<out.AuditSpans[j].ClaimID})
	switch out.Status{
	case logic.Both:out.Disposition="ABSTAIN_CONFLICT";return out,nil
	case logic.Neither:out.Disposition="ABSTAIN_UNSUPPORTED";return out,nil
	case logic.Supported,logic.Refuted:
		if len(out.AuditSpans)==0{return zero,errors.New("PROJECTION_NO_EVIDENCE")}
	default:return zero,errors.New("PROJECTION_STATUS_INVALID")
	}
	out.Disposition="TYPED_STATUS_SUPPORTED_BY_REVIEW"
	m:=ReviewedModelContext{TaskID:t.ID,Language:t.Language,Question:t.Question,Predicate:t.Key,
		ValidAt:validAt,KnownAt:t.KnownAt,InventorySHA256:r.Inventory.ManifestSHA256,
		Status:out.Status,Spans:slices.Clone(out.AuditSpans)}
	raw,err:=json.Marshal(m);if err!=nil{return zero,err}
	m.SHA256=digest(raw)
	out.Model=&m
	return out,nil
}

type CitationSelection struct{
	ClaimID,SourceID string
	Begin,End int
}
type TypedSelection struct{
	ContextSHA256 string
	Status logic.Status
	Citations []CitationSelection
}

// VerifyTypedSelection is a narrow structured realization contract, not a
// free-text entailment checker. The model may select admitted supporting
// citations but cannot change the typed status or invent an evidence span.
// The caller holds the original trusted context digest separately.
func VerifyTypedSelection(ctx ReviewedModelContext,trustedContextSHA256 string,a TypedSelection)error{
	if !hexDigest(trustedContextSHA256)||ctx.SHA256!=trustedContextSHA256||
		a.ContextSHA256!=trustedContextSHA256{return errors.New("SELECTION_CONTEXT_MISMATCH")}
	detached:=ctx;detached.SHA256=""
	raw,err:=json.Marshal(detached);if err!=nil{return err}
	if digest(raw)!=trustedContextSHA256{return errors.New("SELECTION_CONTEXT_TAMPER")}
	if (ctx.Status!=logic.Supported&&ctx.Status!=logic.Refuted)||a.Status!=ctx.Status||
		len(a.Citations)==0||len(a.Citations)>len(ctx.Spans){return errors.New("SELECTION_STATUS_OR_COUNT")}
	allowed:=map[string]ClaimSpan{}
	for _,c:=range ctx.Spans{
		if _,ok:=allowed[c.ClaimID];ok{return errors.New("SELECTION_CONTEXT_DUPLICATE")}
		allowed[c.ClaimID]=c
	}
	seen:=map[string]bool{}
	for _,x:=range a.Citations{
		c,ok:=allowed[x.ClaimID]
		if !ok||seen[x.ClaimID]||x.SourceID!=c.SourceID||x.Begin!=c.Begin||x.End!=c.End{
			return errors.New("SELECTION_CITATION_INVALID")
		}
		seen[x.ClaimID]=true
	}
	return nil
}
