package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const MaxRelationRequestBytes = 16 << 10
const MaxSelectedBytes = 1 << 20

// RangeRelationRequest compares exactly two equally sized retained byte ranges.
// It does not assert correspondence of time, object, operation or cause.
type RangeRelationRequest struct {
	Schema string `json:"schema"`
	Left EvidenceRange `json:"left"`
	Right EvidenceRange `json:"right"`
}

type RangeRelationResult struct {
	Status string `json:"status"`
	Content string `json:"content"`
	Occurrence string `json:"occurrence_relation"`
	Dependency string `json:"dependency"`
	EvidenceCeiling string `json:"evidence_ceiling"`
	Causality string `json:"causality"`
	SelectedBytes U64 `json:"selected_bytes"`
	VerifiedSourceBytes U64 `json:"verified_source_bytes"`
	FirstDifference *U64 `json:"first_difference,omitempty"`
}

func relationResult(status string) RangeRelationResult {
	return RangeRelationResult{Status:status, Content:"unknown", Occurrence:"unknown", Dependency:"unknown", EvidenceCeiling:"selected_retained_byte_relation_only", Causality:"unknown"}
}
func sameOccurrence(a,b ArtifactRef)bool {
	return a.Scope==b.Scope && a.Occurrence==b.Occurrence
}
func ValidateRangeRelation(q RangeRelationRequest) error {
	if q.Schema!="range-relation/v1" || ValidateRange(q.Left)!=nil || ValidateRange(q.Right)!=nil {
		return errors.New("invalid range relation")
	}
	if q.Left.Length!=q.Right.Length || q.Left.Length>MaxSelectedBytes ||
		q.Left.Artifact.Size>MaxSourceBytes || q.Right.Artifact.Size>MaxSourceBytes {
		return errors.New("incompatible or over-budget ranges")
	}
	if sameOccurrence(q.Left.Artifact,q.Right.Artifact) && q.Left.Artifact!=q.Right.Artifact {
		return errors.New("contradictory declaration for one occurrence")
	}
	return nil
}
func DecodeRangeRelation(b []byte)(RangeRelationRequest,error) {
	var q RangeRelationRequest
	if len(b)>MaxRelationRequestBytes || !utf8.Valid(b) {return q,errors.New("invalid request bytes")}
	m,e:=exact(b,"schema","left","right");if e!=nil{return q,e}
	for _,name:=range []string{"left","right"} {
		x,e:=exact(m[name],"artifact","offset","length");if e!=nil{return q,e}
		if _,e=DecodeArtifactRef(x["artifact"]);e!=nil{return q,e}
	}
	if e=json.Unmarshal(b,&q);e!=nil{return RangeRelationRequest{},e}
	if e=ValidateRangeRelation(q);e!=nil{return RangeRelationRequest{},e};return q,nil
}

// selection retains only an admitted subrange while the full stream is hashed.
type selection struct { pos, begin, end uint64; data []byte }
func (s *selection) Write(p []byte)(int,error) {
	a,b:=s.pos,s.pos+uint64(len(p));s.pos=b
	if a<s.end && b>s.begin {
		lo,hi:=a,b;if lo<s.begin{lo=s.begin};if hi>s.end{hi=s.end}
		s.data=append(s.data,p[lo-a:hi-a]...)
	}
	return len(p),nil
}
func readSelection(r io.Reader,x EvidenceRange,pin *ArtifactRef)([]byte,error){
	s:=selection{begin:uint64(x.Offset),end:uint64(x.Offset+x.Length),data:make([]byte,0,int(x.Length))}
	if r==nil{return nil,errors.New("missing source stream")}
	status,e:=VerifyRetainedArtifact(io.TeeReader(r,&s),x.Artifact,pin)
	if e!=nil||status!=RetainedByteMatch||uint64(len(s.data))!=uint64(x.Length){return nil,errors.New("retained range verification failed")}
	return s.data,nil
}

// CompareRetainedRanges checks supplied pins before opening the readers. The
// caller must obtain the pins independently. Readers are trusted finite immutable
// streams. Full artifacts are hashed, but only selected bytes are retained.
// A successful comparison is not a source-independence or causality assertion.
func CompareRetainedRanges(q RangeRelationRequest,left,right io.Reader,lp,rp *ArtifactRef)(RangeRelationResult,error){
	refuse:=func(e error)(RangeRelationResult,error){return relationResult("refused"),e}
	if e:=ValidateRangeRelation(q);e!=nil{return refuse(e)}
	if lp!=nil&&*lp!=q.Left.Artifact||rp!=nil&&*rp!=q.Right.Artifact{return refuse(errors.New("independent occurrence pin mismatch"))}
	if lp==nil||rp==nil{return relationResult("unknown_no_independent_pin"),nil}
	a,e:=readSelection(left,q.Left,lp);if e!=nil{return refuse(e)}
	b,e:=readSelection(right,q.Right,rp);if e!=nil{return refuse(e)}
	r:=relationResult("range_compared")
	r.SelectedBytes=q.Left.Length
	r.VerifiedSourceBytes=q.Left.Artifact.Size+q.Right.Artifact.Size
	r.Occurrence="distinct_declared_occurrences"
	if sameOccurrence(q.Left.Artifact,q.Right.Artifact) {
		r.Occurrence="same_declared_occurrence"
		r.Dependency="shared_declared_occurrence"
	}
	r.Content="equal"
	if !bytes.Equal(a,b) {
		r.Content="different"
		for i:=range a {if a[i]!=b[i]{v:=U64(i);r.FirstDifference=&v;break}}
	}
	return r,nil
}
