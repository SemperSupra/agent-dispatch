package pipeline

import (
	"errors"
	"time"

	inventory "sempersupra/mail-evidence-challenge/review_inventory"
)

// PinnedReviewReceipt combines source/revision signature verification with
// an independently trusted, exact as-of review inventory. No network or
// storage lookup is hidden here; the caller must supply the trusted pin.
type PinnedReviewReceipt struct {
	ReviewReceipt
	Inventory inventory.Receipt
}

// AssessPinnedReviewedTemporal is the complete bounded reference gate.
// The manifest digest must come from an independently trusted catalog,
// not the untrusted annotation bundle or model. A valid signature alone
// does not prove that a producer submitted all applicable corrections.
func (s *Session) AssessPinnedReviewedTemporal(t Task,validAt,policy string,grants []ReviewerGrant,bundle ReviewBundle,manifest inventory.Manifest,trustedPin string)(PinnedReviewReceipt,error){
	var zero PinnedReviewReceipt
	// The first gate verifies actual payloads and signatures. No result is
	// returned until exact independently pinned coverage is also established.
	r,err:=s.AssessReviewedTemporal(t,validAt,policy,grants,bundle)
	if err!=nil{return zero,err}
	known,err:=stamp(t.KnownAt);if err!=nil{return zero,err}
	scope:=inventory.Scope{Tenant:t.Tenant,Partition:string(t.Partition),TaskID:t.ID,
		Group:t.Group,Predicate:t.Key,ValidAt:validAt,KnownAt:t.KnownAt,
		PolicySHA256:policy,ContextSHA256:r.ContextSHA256}
	entries:=make([]inventory.Entry,0,len(bundle.Sources)+len(bundle.Revisions))
	for _,signed:=range bundle.Sources{
		a:=signed.Payload
		raw,err:=SourceReviewBytes(a);if err!=nil{return zero,err}
		entries=append(entries,inventory.Entry{Kind:"source",ID:a.SourceID,
			PayloadSHA256:digest(raw),RecordedAt:a.Identity.RecordedAt})
	}
	for _,signed:=range bundle.Revisions{
		a:=signed.Payload
		at,err:=time.Parse(time.RFC3339,a.Identity.RecordedAt);if err!=nil{return zero,err}
		if at.After(known){continue}
		raw,err:=RevisionReviewBytes(a);if err!=nil{return zero,err}
		entries=append(entries,inventory.Entry{Kind:"revision",ID:a.Revision.ID,
			PayloadSHA256:digest(raw),RecordedAt:a.Identity.RecordedAt})
	}
	check,err:=inventory.Verify(scope,trustedPin,manifest,entries)
	if err!=nil{return zero,err}
	if check.SourceCount!=len(r.SourceReviewSHA256)||check.RevisionCount!=len(r.RevisionReviewSHA256){
		return zero,errors.New("INVENTORY_RECEIPT_COUNT_MISMATCH")
	}
	return PinnedReviewReceipt{ReviewReceipt:r,Inventory:check},nil
}
