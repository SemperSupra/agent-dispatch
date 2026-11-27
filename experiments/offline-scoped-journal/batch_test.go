package journal

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

func TestBatchVerifyOnce(t *testing.T){
	a,b:=[]byte("0123abcXYZ"),[]byte("xxabcZZZZ")
	ar:=relRef(Scope{"r","root","file","p"},"a",a)
	br:=relRef(Scope{"r","restore","file","q"},"b",b)
	l,r:=EvidenceRange{ar,4,3},EvidenceRange{br,2,3}
	q:=RangeBatch{"range-relation-batch/v1",[]RangeQuestion{{"one",l,r},{"two",l,l},{"three",l,EvidenceRange{br,3,3}}}}
	count:=map[ArtifactRef]int{}
	open:=func(x ArtifactRef)(io.ReadCloser,error){count[x]++;v:=a;if x==br{v=b};return io.NopCloser(bytes.NewReader(v)),nil}
	got,e:=CompareRetainedBatch(q,[]ArtifactRef{ar,br},open)
	if e!=nil||got.Status!="batch_compared"||len(got.Answers)!=3||got.VerifiedSourceBytes!=19||got.SeparateQuerySourceBytes!=58||got.LogicalSelectedBytes!=18||got.RetainedSelectionBytes!=9||count[ar]!=1||count[br]!=1{t.Fatal(got,e,count)}
	if got.Answers[0].Content!="equal"||got.Answers[1].Dependency!="shared_declared_occurrence"||got.Answers[2].Content!="different"||got.Answers[2].FirstDifference==nil||*got.Answers[2].FirstDifference!=0{t.Fatal(got)}
	never:=func(ArtifactRef)(io.ReadCloser,error){t.Fatal("unexpected open");return nil,nil}
	got,e=CompareRetainedBatch(q,[]ArtifactRef{ar},never);if e!=nil||got.Status!="unknown_no_independent_pin"||len(got.Answers)!=0{t.Fatal(got,e)}
	wrong:=br;wrong.SHA256=ar.SHA256
	if _,e=CompareRetainedBatch(q,[]ArtifactRef{wrong},never);e==nil{t.Fatal("bad supplied pin")}
	if _,e=CompareRetainedBatch(q,[]ArtifactRef{ar,ar,br},never);e==nil{t.Fatal("duplicate pin")}
	got,e=CompareRetainedBatch(q,[]ArtifactRef{ar,br},func(x ArtifactRef)(io.ReadCloser,error){v:=a;if x==br{v=append([]byte(nil),b...);v[len(v)-1]^=1};return io.NopCloser(bytes.NewReader(v)),nil})
	if e==nil||len(got.Answers)!=0||got.Status!="refused"{t.Fatal("outside-range mutation",got,e)}
	// A later invocation must reopen and verify; no successful cache survives.
	got,e=CompareRetainedBatch(q,[]ArtifactRef{ar,br},open)
	if e!=nil||got.Status!="batch_compared"||count[ar]!=2||count[br]!=2{t.Fatal(got,e,count)}
	conflict:=q;conflict.Questions=append([]RangeQuestion(nil),q.Questions...);conflict.Questions[2].Right.Artifact.SHA256=ar.SHA256
	if _,e=CompareRetainedBatch(conflict,nil,never);e==nil{t.Fatal("cross-question occurrence conflict")}
	q.Questions=append(q.Questions,q.Questions[0]);if _,e=CompareRetainedBatch(q,nil,never);e==nil{t.Fatal("duplicate question")}
}
func TestBatchBudgets(t *testing.T){
	r:=relRef(Scope{"r","b","file","p"},"big",[]byte("x"));r.Size=MaxSourceBytes
	q:=RangeBatch{Schema:"range-relation-batch/v1"}
	for i:=0;i<9;i++{x:=EvidenceRange{r,U64(i)*MaxSelectedBytes,MaxSelectedBytes};q.Questions=append(q.Questions,RangeQuestion{fmt.Sprintf("q%d",i),x,x})}
	if _,e:=planBatch(q);e==nil{t.Fatal("selection budget accepted")}
	q.Questions=nil
	for i:=0;i<3;i++{a:=r;a.Occurrence=fmt.Sprintf("a%d",i);x:=EvidenceRange{a,0,1};q.Questions=append(q.Questions,RangeQuestion{fmt.Sprintf("q%d",i),x,x})}
	if _,e:=planBatch(q);e==nil{t.Fatal("source budget accepted")}
}
