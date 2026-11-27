package journal

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

func relRef(scope Scope,occ string,b []byte)ArtifactRef{
	return ArtifactRef{scope,occ,fmt.Sprintf("%x",sha256.Sum256(b)),U64(len(b))}
}
func TestRangeRelation(t *testing.T){
	a,b:=[]byte("0123abcXYZ"),[]byte("xxabcZZZZ")
	left:=relRef(Scope{"r","root","file","p"},"a",a)
	right:=relRef(Scope{"r","restored","file","q"},"b",b)
	q:=RangeRelationRequest{"range-relation/v1",EvidenceRange{left,4,3},EvidenceRange{right,2,3}}
	got,e:=CompareRetainedRanges(q,bytes.NewReader(a),bytes.NewReader(b),&left,&right)
	if e!=nil||got.Content!="equal"||got.Occurrence!="distinct_declared_occurrences"||got.Dependency!="unknown"||got.Causality!="unknown"||got.SelectedBytes!=3||got.VerifiedSourceBytes!=19||got.FirstDifference!=nil{t.Fatal(got,e)}
	q.Right.Offset=3
	got,e=CompareRetainedRanges(q,bytes.NewReader(a),bytes.NewReader(b),&left,&right)
	if e!=nil||got.Content!="different"||got.FirstDifference==nil||*got.FirstDifference!=0{t.Fatal(got,e)}
	q.Right=EvidenceRange{left,4,3}
	got,e=CompareRetainedRanges(q,bytes.NewReader(a),bytes.NewReader(a),&left,&left)
	if e!=nil||got.Content!="equal"||got.Dependency!="shared_declared_occurrence"||got.Occurrence!="same_declared_occurrence"{t.Fatal(got,e)}
	// Same bytes across different occurrence labels are not independence or identity.
	copyRef:=left;copyRef.Occurrence="copy";q.Right=EvidenceRange{copyRef,4,3}
	got,e=CompareRetainedRanges(q,bytes.NewReader(a),bytes.NewReader(a),&left,&copyRef)
	if e!=nil||got.Content!="equal"||got.Occurrence!="distinct_declared_occurrences"||got.Dependency!="unknown"{t.Fatal(got,e)}
	got,e=CompareRetainedRanges(q,noRead{t},noRead{t},nil,&copyRef)
	if e!=nil||got.Status!="unknown_no_independent_pin"||got.Content!="unknown"||got.VerifiedSourceBytes!=0{t.Fatal(got,e)}
	if _,e=CompareRetainedRanges(q,noRead{t},noRead{t},nil,&left);e==nil{t.Fatal("contradictory supplied pin hidden by absent other pin")}
	if _,e=CompareRetainedRanges(q,bytes.NewReader([]byte("bad")),bytes.NewReader(a),&left,&copyRef);e==nil{t.Fatal("tamper")}
	q.Right=EvidenceRange{left,4,3};q.Right.Artifact.SHA256=right.SHA256
	if _,e=CompareRetainedRanges(q,noRead{t},noRead{t},nil,nil);e==nil{t.Fatal("conflicting same-occurrence refs")}
	for _,x:=range []EvidenceRange{{left,9,2},{left,0,0},{left,0,2}}{
		q.Right=x;if e=ValidateRangeRelation(q);e==nil{t.Fatal("invalid selection",x)}
	}
}
func TestSelectionChunkBoundary(t *testing.T){
	s:=selection{begin:2,end:7}
	for _,p:=range [][]byte{[]byte("a"),[]byte("bc"),[]byte("def"),[]byte("ghij")}{if _,e:=s.Write(p);e!=nil{t.Fatal(e)}}
	if string(s.data)!="cdefg"||s.pos!=10{t.Fatal(string(s.data),s.pos)}
}
