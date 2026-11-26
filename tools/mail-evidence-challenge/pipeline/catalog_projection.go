package pipeline

import (
	"errors"
	"slices"

	authority "sempersupra/mail-evidence-challenge/review_authority"
	inventory "sempersupra/mail-evidence-challenge/review_inventory"
	logic "sempersupra/mail-evidence-challenge/temporal_logic"
)

// CatalogReviewedProjection composes the root-pinned journal with the existing
// signed annotations, exact derived inventory and active-span projection.
// The Catalog must originate from independently configured trust via Replay.
type CatalogReviewedProjection struct {
	CatalogHeadSHA256,SealedThrough string
	Projection ReviewedProjection
}

// PrepareCatalogReviewedProjection derives the source inventory from the
// session and the independently verified journal. The model or annotation
// producer cannot substitute a reviewer grant, inventory or admission clock.
func (s *Session) PrepareCatalogReviewedProjection(t Task,validAt,policy string,catalog *authority.Catalog,bundle ReviewBundle)(CatalogReviewedProjection,error){
	var zero CatalogReviewedProjection
	ctx,err:=s.Prepare(t);if err!=nil{return zero,err}
	scope:=inventory.Scope{Tenant:t.Tenant,Partition:string(t.Partition),TaskID:t.ID,
		Group:t.Group,Predicate:t.Key,ValidAt:validAt,KnownAt:t.KnownAt,
		PolicySHA256:policy,ContextSHA256:ctx.SHA256}
	ids:=make([]string,0,len(ctx.Records))
	for _,r:=range ctx.Records{ids=append(ids,r.ID)}
	snapshot,err:=catalog.Project(scope,ids);if err!=nil{return zero,err}
	if len(bundle.Sources)!=len(ids)||len(bundle.Sources)+len(bundle.Revisions)!=len(snapshot.Admissions){
		return zero,errors.New("CATALOG_BUNDLE_COVERAGE_MISMATCH")
	}
	type key struct{kind,id string}
	admitted:=map[key]authority.Admission{}
	for _,a:=range snapshot.Admissions{admitted[key{a.Kind,a.ID}]=a}
	match:=func(k key,identity ReviewIdentity,raw []byte,sourceIDs []string)bool{
		a,ok:=admitted[k]
		if !ok||a.PayloadSHA256!=digest(raw)||a.ReviewerID!=identity.ReviewerID||
			a.ProducerID!=identity.ProducerID||a.RecordedAt!=identity.RecordedAt||
			!slices.Equal(a.SourceIDs,sourceIDs){return false}
		delete(admitted,k);return true
	}
	claimSource:=map[string]string{}
	for _,signed:=range bundle.Sources{
		a:=signed.Payload
		raw,err:=SourceReviewBytes(a);if err!=nil{return zero,err}
		if !match(key{"source",a.SourceID},a.Identity,raw,[]string{a.SourceID}){
			return zero,errors.New("CATALOG_SOURCE_ADMISSION_MISMATCH")
		}
		for _,c:=range a.Claims{
			if _,ok:=claimSource[c.Claim.ID];ok{return zero,errors.New("CATALOG_CLAIM_ID_REUSED")}
			claimSource[c.Claim.ID]=a.SourceID
		}
	}
	for _,signed:=range bundle.Revisions{
		a:=signed.Payload;r:=a.Revision
		raw,err:=RevisionReviewBytes(a);if err!=nil{return zero,err}
		if !match(key{"revision",r.ID},a.Identity,raw,[]string{claimSource[r.PredecessorID],claimSource[r.SuccessorID]}){
			return zero,errors.New("CATALOG_REVISION_ADMISSION_MISMATCH")
		}
	}
	if len(admitted)!=0{return zero,errors.New("CATALOG_BUNDLE_COVERAGE_MISMATCH")}
	out:=CatalogReviewedProjection{CatalogHeadSHA256:snapshot.HeadSHA256,SealedThrough:snapshot.SealedThrough}
	// Empty visible evidence is an explicit typed abstention, not a grant
	// failure or a model invitation. The sealed inventory is still checked.
	if len(ids)==0{
		check,err:=inventory.Verify(scope,snapshot.ManifestSHA256,snapshot.Manifest,nil)
		if err!=nil{return zero,err}
		out.Projection=ReviewedProjection{Status:logic.Neither,Disposition:"ABSTAIN_UNSUPPORTED",
			AuditSpans:[]ClaimSpan{},Receipt:PinnedReviewReceipt{
				ReviewReceipt:ReviewReceipt{Schema:reviewSchema,Tenant:t.Tenant,TaskID:t.ID,
					ValidAt:validAt,KnownAt:t.KnownAt,PolicySHA256:policy,ContextSHA256:ctx.SHA256,
					SourceReviewSHA256:[]string{},RevisionReviewSHA256:[]string{},
					Assessment:logic.RevisionAssessment{Assessment:logic.Assessment{
						Tenant:t.Tenant,ValidAt:validAt,KnowledgeAt:t.KnownAt},Applied:[]logic.RevisionWitness{}}},
				Inventory:check}}
		return out,nil
	}
	grants:=make([]ReviewerGrant,0,len(snapshot.Grants))
	for _,g:=range snapshot.Grants{
		grants=append(grants,ReviewerGrant{ID:g.ID,Tenant:t.Tenant,PolicySHA256:policy,
			PublicKey:g.PublicKey,NotBefore:g.NotBefore,NotAfter:g.NotAfter})
	}
	out.Projection,err=s.PrepareReviewedProjection(t,validAt,policy,grants,bundle,snapshot.Manifest,snapshot.ManifestSHA256)
	if err!=nil{return zero,err}
	return out,nil
}
