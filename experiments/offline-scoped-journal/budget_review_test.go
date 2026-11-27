package journal
import("bytes";"crypto/sha256";"encoding/hex";"io";"testing")
type meter struct{ io.Reader; count int; closed bool }
func(m *meter)Read(p []byte)(int,error){n,e:=m.Reader.Read(p);m.count+=n;return n,e}
func(m *meter)Close()error{m.closed=true;return nil}
func reviewRef(id string, b []byte)ArtifactRef{h:=sha256.Sum256(b);return ArtifactRef{Scope:Scope{"r","b","file","p"},Occurrence:id,SHA256:hex.EncodeToString(h[:]),Size:U64(len(b))}}
func TestReviewBoundedContradictoryStream(t *testing.T){
 good:=[]byte("a");a:=reviewRef("a",good);b:=reviewRef("b",good);q:=RangeBatch{"range-relation-batch/v1",[]RangeQuestion{{"q",EvidenceRange{a,0,1},EvidenceRange{b,0,1}}}}
 left:=&meter{Reader:bytes.NewReader(good)};right:=&meter{Reader:bytes.NewReader(bytes.Repeat(good,4<<20))};r,e:=CompareRetainedBatch(q,[]ArtifactRef{a,b},func(x ArtifactRef)(io.ReadCloser,error){if x==a{return left,nil};return right,nil})
 if e==nil||r.Status!="refused"||len(r.Answers)!=0||!left.closed||!right.closed{t.Fatal("must refuse all answers and close",r,e)}
 if right.count>int(b.Size)+1{t.Fatalf("declared size %d, consumed %d; expected <= size+1 sentinel",b.Size,right.count)}
}
func TestReviewBoundedPositiveAndSuffix(t *testing.T){
 data:=[]byte("abc");a:=reviewRef("a",data);q:=RangeBatch{"range-relation-batch/v1",[]RangeQuestion{{"q",EvidenceRange{a,0,3},EvidenceRange{a,0,3}}}}
 for _,v:=range []struct{input []byte;pass bool}{{data,true},{[]byte("abcx"),false},{[]byte("ab"),false}}{m:=&meter{Reader:bytes.NewReader(v.input)};r,e:=CompareRetainedBatch(q,[]ArtifactRef{a},func(ArtifactRef)(io.ReadCloser,error){return m,nil});if (e==nil)!=v.pass||m.count>4||!m.closed{t.Fatal(v,r,e,m.count)};if v.pass&&(len(r.Answers)!=1||r.Answers[0].Content!="equal"){t.Fatal(r)};if !v.pass&&len(r.Answers)!=0{t.Fatal(r)}}
}
