package journal

import (
 "bytes"
 "crypto/sha256"
 "fmt"
 "math"
 "strings"
 "testing"
)

func TestArtifactLocator(t *testing.T){
 scope:=Scope{"run","root","file","observer"}
 a:=ArtifactRef{scope,"first",strings.Repeat("a",64),16}
 b:=a;b.Occurrence="second"
 if a==b{t.Fatal("equal content must not merge occurrences")}
 if e:=ValidateRange(EvidenceRange{a,8,8});e!=nil{t.Fatal(e)}
 for _,r:=range []EvidenceRange{{a,16,1},{a,0,0},{a,math.MaxUint64,2},{a,15,2}}{if ValidateRange(r)==nil{t.Fatal("accepted invalid range",r)}}
 a.Size=math.MaxUint64
 if ValidateRange(EvidenceRange{a,math.MaxUint64-1,2})==nil{t.Fatal("overflow")}
 a.Occurrence=""
 if ValidateRange(EvidenceRange{a,0,1})==nil{t.Fatal("missing occurrence")}
}

type zeros struct{}
func(zeros)Read(p []byte)(int,error){clear(p);return len(p),nil}
func TestSourceVerification(t *testing.T){
 data:=[]byte("independent original synthetic bytes")
 digest:=fmt.Sprintf("%x",sha256.Sum256(data))
 if n,e:=VerifyArtifact(bytes.NewReader(data),digest);e!=nil||n!=U64(len(data)){t.Fatal(n,e)}
 for _,bad:=range [][]byte{nil,[]byte("different"),append(append([]byte(nil),data...),0)}{if _,e:=VerifyArtifact(bytes.NewReader(bad),digest);e==nil{t.Fatal("accepted mismatching bytes")}}
 if _,e:=VerifyArtifact(zeros{},digest);e==nil||!strings.Contains(e.Error(),"limit"){t.Fatal("unbounded source",e)}
}
