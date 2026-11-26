// Package reviewinventory verifies a caller-pinned, exact as-of inventory.
// This is a public synthetic completeness primitive, not a storage service,
// timestamp authority, reviewer PKI or proof of the upstream catalog's truth.
package reviewinventory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"time"
)

const Schema="mail-review-inventory/v1"
const maxEntries=8192

// Scope deliberately binds the exact task and projection, not just tenant.
// The trusted caller must get the checkpoint pin out of band; accepting a
// pin supplied by the same untrusted producer proves no completeness.
type Scope struct {
	Tenant,Partition,TaskID,Group,Predicate,ValidAt,KnownAt,PolicySHA256,ContextSHA256 string
}
type Entry struct {
	Kind,ID,PayloadSHA256,RecordedAt string
}
type Manifest struct{
	Schema string
	Scope Scope
	Entries []Entry
}
type Receipt struct{
	ManifestSHA256 string
	Scope Scope
	SourceCount,RevisionCount int
}

func digest(b []byte)string{h:=sha256.Sum256(b);return hex.EncodeToString(h[:])}
func isHash(s string)bool{b,e:=hex.DecodeString(s);return e==nil&&len(b)==32&&hex.EncodeToString(b)==s}
func instant(s string)(time.Time,error){return time.Parse(time.RFC3339,s)}
func validScope(s Scope)bool{
	if s.Tenant==""||s.TaskID==""||s.Group==""||s.Predicate==""||
		(s.Partition!="dev"&&s.Partition!="heldout")||
		!isHash(s.PolicySHA256)||!isHash(s.ContextSHA256){return false}
	_,e1:=instant(s.ValidAt);_,e2:=instant(s.KnownAt);return e1==nil&&e2==nil
}
func normalize(scope Scope,entries []Entry)([]Entry,error){
	if !validScope(scope)||len(entries)>maxEntries{return nil,errors.New("INVENTORY_SCOPE_OR_BOUND")}
	known,_:=instant(scope.KnownAt)
	out:=make([]Entry,0,len(entries))
	type key struct{kind,id string}
	seen:=map[key]bool{}
	for _,e:=range entries{
		k:=key{e.Kind,e.ID}
		at,err:=instant(e.RecordedAt)
		if (e.Kind!="source"&&e.Kind!="revision")||e.ID==""||
			!isHash(e.PayloadSHA256)||err!=nil||at.After(known)||seen[k]{
			return nil,errors.New("INVENTORY_ENTRY_INVALID")
		}
		seen[k]=true
		out=append(out,e)
	}
	sort.Slice(out,func(i,j int)bool{
		if out[i].Kind!=out[j].Kind{return out[i].Kind<out[j].Kind}
		return out[i].ID<out[j].ID
	})
	return out,nil
}

// Digest returns a deterministic versioned manifest identity. It does not
// authorize the manifest; only a separately trusted pin does that.
func Digest(m Manifest)(string,error){
	if m.Schema!=Schema{return "",errors.New("INVENTORY_SCHEMA_INVALID")}
	entries,err:=normalize(m.Scope,m.Entries);if err!=nil{return "",err}
	b,err:=json.Marshal(Manifest{Schema:Schema,Scope:m.Scope,Entries:entries})
	if err!=nil{return "",err}
	return digest(b),nil
}

// Verify rejects omission, substitution, addition, duplicate IDs, scope
// drift, future entries and stale/self-selected manifests relative to the pin.
// Callers must independently verify entry payloads, signatures and chronology.
func Verify(expected Scope,trustedPin string,m Manifest,observed []Entry)(Receipt,error){
	var zero Receipt
	if !isHash(trustedPin)||m.Scope!=expected{return zero,errors.New("INVENTORY_TRUST_OR_SCOPE_INVALID")}
	d,err:=Digest(m);if err!=nil{return zero,err}
	if d!=trustedPin{return zero,errors.New("INVENTORY_PIN_MISMATCH")}
	want,err:=normalize(expected,m.Entries);if err!=nil{return zero,err}
	got,err:=normalize(expected,observed);if err!=nil{return zero,err}
	if !slices.Equal(want,got){return zero,errors.New("INVENTORY_COVERAGE_MISMATCH")}
	out:=Receipt{ManifestSHA256:d,Scope:expected}
	for _,e:=range want{if e.Kind=="source"{out.SourceCount++}else{out.RevisionCount++}}
	return out,nil
}
