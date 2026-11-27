package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

const MaxBatchRequestBytes = 256 << 10
const MaxBatchQuestions = 32
const MaxBatchArtifacts = 8
const MaxBatchSelectedBytes = 8 << 20
const MaxBatchSourceBytes = 128 << 20

type RangeQuestion struct {
	ID string `json:"id"`
	Left EvidenceRange `json:"left"`
	Right EvidenceRange `json:"right"`
}
type RangeBatch struct {
	Schema string `json:"schema"`
	Questions []RangeQuestion `json:"questions"`
}
type BatchSource struct {
	Artifact ArtifactRef `json:"artifact"`
	Path string `json:"path"`
}
type BatchSources struct {
	Schema string `json:"schema"`
	Sources []BatchSource `json:"sources"`
}
type BatchAnswer struct {
	ID string `json:"id"`
	Content string `json:"content"`
	Occurrence string `json:"occurrence_relation"`
	Dependency string `json:"dependency"`
	SelectedBytes U64 `json:"selected_bytes_per_side"`
	FirstDifference *U64 `json:"first_difference,omitempty"`
}
type BatchResult struct {
	Status string `json:"status"`
	EvidenceCeiling string `json:"evidence_ceiling"`
	Causality string `json:"causality"`
	Answers []BatchAnswer `json:"answers,omitempty"`
	LogicalSelectedBytes U64 `json:"logical_selected_bytes"`
	RetainedSelectionBytes U64 `json:"retained_selection_bytes"`
	VerifiedSourceBytes U64 `json:"verified_source_bytes"`
	SeparateQuerySourceBytes U64 `json:"separate_query_source_bytes"`
	VerifiedOccurrences int `json:"verified_occurrences"`
}
type occurrenceKey struct { Scope Scope; ID string }
func occurrenceOf(a ArtifactRef)occurrenceKey{return occurrenceKey{a.Scope,a.Occurrence}}
type rangeKey struct{ Offset,Length U64 }
func rangeOf(r EvidenceRange)rangeKey{return rangeKey{r.Offset,r.Length}}
type artifactPlan struct {
	ref ArtifactRef
	ranges map[rangeKey]*selection
	order []rangeKey
}
type batchPlan struct {
	artifacts map[occurrenceKey]*artifactPlan
	order []occurrenceKey
	logical, retained, verified, separate U64
}
func planBatch(q RangeBatch)(*batchPlan,error){
	if q.Schema!="range-relation-batch/v1"||len(q.Questions)==0||len(q.Questions)>MaxBatchQuestions{return nil,errors.New("invalid batch question count or schema")}
	p:=&batchPlan{artifacts:map[occurrenceKey]*artifactPlan{}}
	ids:=map[string]bool{}
	for _,question:=range q.Questions{
		if !validID(question.ID)||ids[question.ID]{return nil,errors.New("invalid or duplicate question ID")}
		ids[question.ID]=true
		if e:=ValidateRangeRelation(RangeRelationRequest{"range-relation/v1",question.Left,question.Right});e!=nil{return nil,e}
		for _,x:=range []EvidenceRange{question.Left,question.Right}{
			p.logical+=x.Length;p.separate+=x.Artifact.Size
			k:=occurrenceOf(x.Artifact);a:=p.artifacts[k]
			if a==nil{
				a=&artifactPlan{ref:x.Artifact,ranges:map[rangeKey]*selection{}}
				p.artifacts[k]=a;p.order=append(p.order,k);p.verified+=x.Artifact.Size
			}else if a.ref!=x.Artifact{return nil,errors.New("contradictory occurrence across questions")}
			r:=rangeOf(x)
			if _,ok:=a.ranges[r];!ok{
				a.ranges[r]=nil;a.order=append(a.order,r);p.retained+=r.Length
			}
			if len(p.order)>MaxBatchArtifacts||p.retained>MaxBatchSelectedBytes||p.verified>MaxBatchSourceBytes{return nil,errors.New("aggregate batch budget exceeded")}
		}
	}
	return p,nil
}
func DecodeRangeBatch(b []byte)(RangeBatch,error){
	var q RangeBatch
	if len(b)>MaxBatchRequestBytes||!utf8.Valid(b){return q,errors.New("invalid batch bytes")}
	m,e:=exact(b,"schema","questions");if e!=nil{return q,e}
	var rows []json.RawMessage
	if e=json.Unmarshal(m["questions"],&rows);e!=nil||len(rows)==0||len(rows)>MaxBatchQuestions{return q,errors.New("invalid batch questions")}
	for _,row:=range rows{
		f,e:=exact(row,"id","left","right");if e!=nil{return q,e}
		for _,side:=range []string{"left","right"}{
			x,e:=exact(f[side],"artifact","offset","length");if e!=nil{return q,e}
			if _,e=DecodeArtifactRef(x["artifact"]);e!=nil{return q,e}
		}
	}
	if e=json.Unmarshal(b,&q);e!=nil{return RangeBatch{},e}
	if _,e=planBatch(q);e!=nil{return RangeBatch{},e};return q,nil
}
func DecodeBatchSources(b []byte)(BatchSources,error){
	var out BatchSources
	if len(b)>MaxBatchRequestBytes||!utf8.Valid(b){return out,errors.New("invalid source manifest bytes")}
	m,e:=exact(b,"schema","sources");if e!=nil{return out,e}
	var rows []json.RawMessage
	if e=json.Unmarshal(m["sources"],&rows);e!=nil||rows==nil||len(rows)>MaxBatchArtifacts{return out,errors.New("invalid source manifest")}
	for _,row:=range rows{
		f,e:=exact(row,"artifact","path");if e!=nil{return out,e}
		if _,e=DecodeArtifactRef(f["artifact"]);e!=nil{return out,e}
	}
	if e=json.Unmarshal(b,&out);e!=nil{return BatchSources{},e}
	if out.Schema!="range-relation-sources/v1"{return BatchSources{},errors.New("invalid source manifest schema")}
	seen:=map[occurrenceKey]bool{}
	for _,s:=range out.Sources{
		k:=occurrenceOf(s.Artifact)
		if seen[k]||s.Path==""||len(s.Path)>4096||strings.ContainsAny(s.Path,"\x00\r\n")||strings.ContainsRune(s.Path,utf8.RuneError){return BatchSources{},errors.New("duplicate occurrence or invalid source path")}
		seen[k]=true
	}
	return out,nil
}
type batchSink struct{ selections []*selection }
func (s batchSink)Write(p []byte)(int,error){
	for _,x:=range s.selections{if _,e:=x.Write(p);e!=nil{return 0,e}}
	return len(p),nil
}
func batchStatus(s string)BatchResult{return BatchResult{Status:s,EvidenceCeiling:"selected_retained_byte_relation_only",Causality:"unknown"}}

// CompareRetainedBatch is all-or-nothing. The caller supplies independently
// retained pins and an opener for trusted finite immutable sources. All pins
// and aggregate budgets are checked before any open. One stream per declared
// occurrence is hashed; only requested ranges are retained, for this call only.
// No cache, pathname identity, or independent-source/causal claim is made.
func CompareRetainedBatch(q RangeBatch,pins []ArtifactRef,open func(ArtifactRef)(io.ReadCloser,error))(BatchResult,error){
	refuse:=func(e error)(BatchResult,error){return batchStatus("refused"),e}
	p,e:=planBatch(q);if e!=nil{return refuse(e)}
	seen:=map[occurrenceKey]ArtifactRef{}
	for _,pin:=range pins{
		k:=occurrenceOf(pin);a:=p.artifacts[k]
		if !validArtifact(pin)||a==nil||a.ref!=pin{return refuse(errors.New("unexpected or contradictory occurrence pin"))}
		if _,ok:=seen[k];ok{return refuse(errors.New("duplicate occurrence pin"))}
		seen[k]=pin
	}
	if len(seen)!=len(p.artifacts){return batchStatus("unknown_no_independent_pin"),nil}
	if open==nil{return refuse(errors.New("source opener required"))}
	for _,k:=range p.order{
		a:=p.artifacts[k];pin:=seen[k]
		s:=batchSink{}
		for _,r:=range a.order{
			x:=&selection{begin:uint64(r.Offset),end:uint64(r.Offset+r.Length),data:make([]byte,0,int(r.Length))}
			a.ranges[r]=x;s.selections=append(s.selections,x)
		}
		reader,e:=open(a.ref);if e!=nil{return refuse(e)}
		if reader==nil{return refuse(errors.New("nil source reader"))}
		status,verifyErr:=VerifyRetainedArtifact(io.TeeReader(reader,s),a.ref,&pin)
		closeErr:=reader.Close()
		if verifyErr!=nil||closeErr!=nil||status!=RetainedByteMatch{return refuse(errors.New("batch source verification failed"))}
		for _,r:=range a.order{if len(a.ranges[r].data)!=int(r.Length){return refuse(errors.New("incomplete selection"))}}
	}
	out:=batchStatus("batch_compared")
	out.LogicalSelectedBytes=p.logical;out.RetainedSelectionBytes=p.retained;out.VerifiedSourceBytes=p.verified;out.SeparateQuerySourceBytes=p.separate;out.VerifiedOccurrences=len(p.order)
	for _,q:=range q.Questions{
		a:=p.artifacts[occurrenceOf(q.Left.Artifact)].ranges[rangeOf(q.Left)].data
		b:=p.artifacts[occurrenceOf(q.Right.Artifact)].ranges[rangeOf(q.Right)].data
		x:=BatchAnswer{ID:q.ID,Content:"equal",Occurrence:"distinct_declared_occurrences",Dependency:"unknown",SelectedBytes:q.Left.Length}
		if sameOccurrence(q.Left.Artifact,q.Right.Artifact){x.Occurrence="same_declared_occurrence";x.Dependency="shared_declared_occurrence"}
		if !bytes.Equal(a,b){x.Content="different";for i:=range a{if a[i]!=b[i]{v:=U64(i);x.FirstDifference=&v;break}}}
		out.Answers=append(out.Answers,x)
	}
	return out,nil
}
