// Package reviewauthority provides a bounded, root-pinned review journal.
// It qualifies integrity, lifecycle and as-of projection, not a deployed PKI,
// trusted timestamp service, human review process or proof of semantic truth.
package reviewauthority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	inventory "sempersupra/mail-evidence-challenge/review_inventory"
)

const Schema = "mail-review-authority/v1"
const MaxEvents = 16384
var genesis = strings.Repeat("0",64)

type Scope struct { CatalogID,Tenant,PolicySHA256 string }
type Trust struct {
	Scope Scope
	RootKey ed25519.PublicKey
	HeadSHA256 string // Independently trusted current head; never take it from a submitted journal.
}
type Grant struct {
	ID string
	PublicKey ed25519.PublicKey
	NotBefore,NotAfter string
}
type Registration struct {
	Kind,ID,PayloadSHA256,ReviewerID,ProducerID string
	SourceIDs []string // source: [ID]; revision: [predecessor source, successor source]
}
type Event struct {
	Schema string
	Scope Scope
	Sequence uint64
	PreviousSHA256,RecordedAt,Kind string
	Grant *Grant
	RevokedID string
	Review *Registration
}
type SignedEvent struct { Event Event; Signature []byte }
type admitted struct { Registration; RecordedAt string }
type Catalog struct {
	scope Scope
	head, sealedThrough string
	grants map[string]Grant
	reviews []admitted
}
type Admission struct {
	Kind,ID,PayloadSHA256,ReviewerID,ProducerID,RecordedAt string
	SourceIDs []string
}
type Snapshot struct {
	Manifest inventory.Manifest
	ManifestSHA256,HeadSHA256,SealedThrough string
	Grants []Grant
	Admissions []Admission
}

func hash(b []byte)string{h:=sha256.Sum256(b);return hex.EncodeToString(h[:])}
func isHash(s string)bool{b,e:=hex.DecodeString(s);return e==nil&&len(b)==32&&hex.EncodeToString(b)==s}
func validID(s string)bool{return strings.TrimSpace(s)==s&&s!=""&&len(s)<=256&&utf8.ValidString(s)}
func validScope(s Scope)bool{return validID(s.CatalogID)&&validID(s.Tenant)&&isHash(s.PolicySHA256)}
// Closed-second UTC clocks avoid ambiguous or lossy canonical representations.
// Actual trusted clock issuance is the root operator's responsibility.
func moment(s string)(time.Time,error){
	t,e:=time.Parse(time.RFC3339,s)
	if e!=nil||t.UTC().Format(time.RFC3339)!=s{return time.Time{},errors.New("AUTHORITY_CLOCK_NOT_CANONICAL_UTC")}
	return t,nil
}
func EventBytes(e Event)([]byte,error){
	if !validScope(e.Scope)||e.Schema!=Schema||e.Sequence==0||!isHash(e.PreviousSHA256){
		return nil,errors.New("AUTHORITY_EVENT_SCOPE")
	}
	if _,err:=moment(e.RecordedAt);err!=nil{return nil,err}
	switch e.Kind{
	case "grant":
		if e.Grant==nil||e.Review!=nil||e.RevokedID!=""||!validID(e.Grant.ID)||
			len(e.Grant.PublicKey)!=ed25519.PublicKeySize{return nil,errors.New("AUTHORITY_GRANT_SHAPE")}
		if _,err:=moment(e.Grant.NotBefore);err!=nil{return nil,err}
		if _,err:=moment(e.Grant.NotAfter);err!=nil{return nil,err}
	case "revoke":
		if e.Grant!=nil||e.Review!=nil||!validID(e.RevokedID){return nil,errors.New("AUTHORITY_REVOKE_SHAPE")}
	case "review":
		r:=e.Review
		if e.Grant!=nil||r==nil||e.RevokedID!=""||!validID(r.ID)||!validID(r.ReviewerID)||
			!validID(r.ProducerID)||r.ReviewerID==r.ProducerID||!isHash(r.PayloadSHA256){
			return nil,errors.New("AUTHORITY_REVIEW_SHAPE")
		}
		if (r.Kind=="source"&&(len(r.SourceIDs)!=1||r.SourceIDs[0]!=r.ID))||
			(r.Kind=="revision"&&(len(r.SourceIDs)!=2||r.SourceIDs[0]==r.SourceIDs[1]))||
			(r.Kind!="source"&&r.Kind!="revision"){return nil,errors.New("AUTHORITY_REVIEW_SCOPE")}
		for _,id:=range r.SourceIDs{if !validID(id){return nil,errors.New("AUTHORITY_REVIEW_SCOPE")}}
	case "seal":
		if e.Grant!=nil||e.Review!=nil||e.RevokedID!=""{return nil,errors.New("AUTHORITY_SEAL_SHAPE")}
	default:return nil,errors.New("AUTHORITY_EVENT_KIND")
	}
	return json.Marshal(e)
}
func EventDigest(s SignedEvent)(string,error){
	if _,err:=EventBytes(s.Event);err!=nil{return "",err}
	if len(s.Signature)!=ed25519.SignatureSize{return "",errors.New("AUTHORITY_SIGNATURE_SHAPE")}
	b,err:=json.Marshal(s);if err!=nil{return "",err};return hash(b),nil
}

// Replay validates every event against a pinned root and exact final head.
// Grant identities/keys cannot be reused. Revocation is prospective: previous
// registered reviews stay historically valid, new ones are refused. A seal
// closes its knowledge-time prefix; no later event can be backdated into it.
func Replay(trust Trust,events []SignedEvent)(*Catalog,error){
	if !validScope(trust.Scope)||len(trust.RootKey)!=ed25519.PublicKeySize||
		!isHash(trust.HeadSHA256)||len(events)==0||len(events)>MaxEvents{
		return nil,errors.New("AUTHORITY_TRUST_OR_BOUND")
	}
	c:=&Catalog{scope:trust.Scope,grants:map[string]Grant{}}
	revoked:=map[string]bool{}
	keys:=map[string]bool{}
	type reviewKey struct{kind,id string}
	seen:=map[reviewKey]bool{}
	prev:=genesis
	var last,closed time.Time
	for i,s:=range events{
		e:=s.Event
		raw,err:=EventBytes(e);if err!=nil{return nil,err}
		at,_:=moment(e.RecordedAt)
		if e.Scope!=trust.Scope||e.Sequence!=uint64(i+1)||e.PreviousSHA256!=prev||
			at.Before(last)||(!closed.IsZero()&&!at.After(closed)){
			return nil,errors.New("AUTHORITY_CHAIN_OR_CLOCK")
		}
		if len(s.Signature)!=ed25519.SignatureSize||!ed25519.Verify(trust.RootKey,raw,s.Signature){
			return nil,errors.New("AUTHORITY_SIGNATURE_INVALID")
		}
		switch e.Kind{
		case "grant":
			g:=*e.Grant
			start,_:=moment(g.NotBefore);end,_:=moment(g.NotAfter)
			k:=hex.EncodeToString(g.PublicKey)
			if _,ok:=c.grants[g.ID];ok||keys[k]||bytes.Equal(g.PublicKey,trust.RootKey)||
				start.Before(at)||!end.After(start){
				return nil,errors.New("AUTHORITY_GRANT_REUSE_OR_CLOCK")
			}
			g.PublicKey=slices.Clone(g.PublicKey)
			c.grants[g.ID]=g;keys[k]=true
		case "revoke":
			if _,ok:=c.grants[e.RevokedID];!ok||revoked[e.RevokedID]{return nil,errors.New("AUTHORITY_REVOKE_UNKNOWN_OR_REPEATED")}
			revoked[e.RevokedID]=true
		case "review":
			r:=*e.Review
			g,ok:=c.grants[r.ReviewerID]
			if !ok||revoked[r.ReviewerID]{return nil,errors.New("AUTHORITY_REVIEWER_NOT_ACTIVE")}
			start,_:=moment(g.NotBefore);end,_:=moment(g.NotAfter)
			if at.Before(start)||!at.Before(end){return nil,errors.New("AUTHORITY_REVIEWER_NOT_ACTIVE")}
			k:=reviewKey{r.Kind,r.ID}
			if seen[k]{return nil,errors.New("AUTHORITY_REVIEW_ID_REUSED")}
			if r.Kind=="revision"{
				for _,id:=range r.SourceIDs{if !seen[reviewKey{"source",id}]{return nil,errors.New("AUTHORITY_REVISION_BEFORE_SOURCE_REVIEW")}}
			}
			seen[k]=true
			r.SourceIDs=slices.Clone(r.SourceIDs)
			c.reviews=append(c.reviews,admitted{Registration:r,RecordedAt:e.RecordedAt})
		case "seal":
			closed=at;c.sealedThrough=e.RecordedAt
		}
		prev,err=EventDigest(s);if err!=nil{return nil,err}
		last=at
	}
	if prev!=trust.HeadSHA256||events[len(events)-1].Event.Kind!="seal"{return nil,errors.New("AUTHORITY_HEAD_OR_SEAL_MISMATCH")}
	c.head=prev
	return c,nil
}

// Project derives, rather than accepts, the inventory for visible sources
// from all registered reviews up to a sealed cutoff. Revision endpoints must
// both be visible; historical grants are retained for signature verification.
// A later compromise declaration requires a distinct quarantine policy;
// prospective revocation does not retroactively rewrite earlier knowledge.
func (c *Catalog) Project(scope inventory.Scope,visibleIDs []string)(Snapshot,error){
	var zero Snapshot
	if c==nil||scope.Tenant!=c.scope.Tenant||scope.PolicySHA256!=c.scope.PolicySHA256||
		len(visibleIDs)>256{return zero,errors.New("AUTHORITY_PROJECTION_SCOPE")}
	known,err:=moment(scope.KnownAt);if err!=nil{return zero,err}
	seal,_:=moment(c.sealedThrough)
	if known.After(seal){return zero,errors.New("AUTHORITY_CUTOFF_NOT_SEALED")}
	ids:=map[string]bool{}
	for _,id:=range visibleIDs{if !validID(id)||ids[id]{return zero,errors.New("AUTHORITY_VISIBLE_ID_INVALID")};ids[id]=true}
	out:=Snapshot{Manifest:inventory.Manifest{Schema:inventory.Schema,Scope:scope},
		HeadSHA256:c.head,SealedThrough:c.sealedThrough}
	covered:=map[string]bool{}
	reviewers:=map[string]bool{}
	for _,r:=range c.reviews{
		at,_:=moment(r.RecordedAt)
		if at.After(known){continue}
		include:=true
		for _,id:=range r.SourceIDs{if !ids[id]{include=false}}
		if !include{continue}
		if r.Kind=="source"{covered[r.ID]=true}
		out.Manifest.Entries=append(out.Manifest.Entries,inventory.Entry{Kind:r.Kind,ID:r.ID,
			PayloadSHA256:r.PayloadSHA256,RecordedAt:r.RecordedAt})
		out.Admissions=append(out.Admissions,Admission{Kind:r.Kind,ID:r.ID,PayloadSHA256:r.PayloadSHA256,
			ReviewerID:r.ReviewerID,ProducerID:r.ProducerID,RecordedAt:r.RecordedAt,SourceIDs:slices.Clone(r.SourceIDs)})
		reviewers[r.ReviewerID]=true
	}
	if len(covered)!=len(ids){return zero,errors.New("AUTHORITY_SOURCE_REVIEW_MISSING")}
	for id:=range reviewers{
		g:=c.grants[id];g.PublicKey=slices.Clone(g.PublicKey);out.Grants=append(out.Grants,g)
	}
	sort.Slice(out.Grants,func(i,j int)bool{return out.Grants[i].ID<out.Grants[j].ID})
	sort.Slice(out.Admissions,func(i,j int)bool{
		a,b:=out.Admissions[i],out.Admissions[j];if a.Kind!=b.Kind{return a.Kind<b.Kind};return a.ID<b.ID
	})
	sort.Slice(out.Manifest.Entries,func(i,j int)bool{
		a,b:=out.Manifest.Entries[i],out.Manifest.Entries[j];if a.Kind!=b.Kind{return a.Kind<b.Kind};return a.ID<b.ID
	})
	out.ManifestSHA256,err=inventory.Digest(out.Manifest)
	if err!=nil{return zero,err}
	return out,nil
}
