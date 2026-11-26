package journal

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

type noRead struct{ t *testing.T }
func (r noRead) Read(p []byte) (int,error) {
	r.t.Fatal("unexpected source read before admission")
	return 0,io.EOF
}

func TestIndependentPin(t *testing.T) {
	data:=[]byte("original retained fixture")
	claim:=ArtifactRef{Scope{"run","root","file","observer"},"occ-1",fmt.Sprintf("%x",sha256.Sum256(data)),U64(len(data))}
	pin:=claim
	if status,err:=VerifyRetainedArtifact(bytes.NewReader(data),claim,&pin);status!=RetainedByteMatch||err!=nil { t.Fatal(status,err) }
	if status,err:=VerifyRetainedArtifact(noRead{t},claim,nil);status!=NoIndependentPin||err!=nil { t.Fatal(status,err) }
	for name,mut:=range map[string]func(*ArtifactRef){
		"run":func(p *ArtifactRef){p.Scope.Run="other"},
		"branch":func(p *ArtifactRef){p.Scope.Branch="sibling"},
		"space":func(p *ArtifactRef){p.Scope.Space="other"},
		"producer":func(p *ArtifactRef){p.Scope.Producer="other"},
		"occurrence":func(p *ArtifactRef){p.Occurrence="occ-2"},
		"size":func(p *ArtifactRef){p.Size++},
		"digest":func(p *ArtifactRef){p.SHA256=strings.Repeat("a",64)},
		"invalid":func(p *ArtifactRef){p.Occurrence=""},
	}{t.Run(name,func(t *testing.T){wrong:=pin;mut(&wrong);if status,err:=VerifyRetainedArtifact(noRead{t},claim,&wrong);status!=BindingRefused||err==nil{t.Fatal(status,err)}})}
	for _,b:=range [][]byte{nil,[]byte("modified retained fixture"),append(append([]byte(nil),data...),0)} {
		if status,err:=VerifyRetainedArtifact(bytes.NewReader(b),claim,&pin);status!=BindingRefused||err==nil {t.Fatal(status,err)}
	}
	// A substituted source and re-sealed claim can pass a claimant-only digest check.
	sibling:=[]byte("sibling")
	forged:=claim;forged.SHA256=fmt.Sprintf("%x",sha256.Sum256(sibling));forged.Size=U64(len(sibling))
	if _,err:=VerifyArtifact(bytes.NewReader(sibling),forged.SHA256);err!=nil{t.Fatal(err)}
	if status,err:=VerifyRetainedArtifact(noRead{t},forged,&pin);status!=BindingRefused||err==nil {t.Fatal(status,err)}
	// Identical bytes under a different occurrence must not match the old pin.
	copyClaim:=claim;copyClaim.Occurrence="copy"
	if status,err:=VerifyRetainedArtifact(noRead{t},copyClaim,&pin);status!=BindingRefused||err==nil {t.Fatal(status,err)}
	// Even matching claims with a wrong size or too-large declared size are refused.
	bad:=claim;bad.Size++;if status,err:=VerifyRetainedArtifact(bytes.NewReader(data),bad,&bad);status!=BindingRefused||err==nil{t.Fatal(status,err)}
	bad.Size=MaxSourceBytes+1;if status,err:=VerifyRetainedArtifact(noRead{t},bad,&bad);status!=BindingRefused||err==nil{t.Fatal(status,err)}
	if status,err:=VerifyRetainedArtifact(nil,claim,&pin);status!=BindingRefused||err==nil{t.Fatal(status,err)}
}

func TestDecodeArtifactRef(t *testing.T){
 a:=ArtifactRef{Scope{"r","b","s","p"},"occ",strings.Repeat("a",64),U64(9007199254740993)}
 b,_:=json.Marshal(a)
 if v,e:=DecodeArtifactRef(b);e!=nil||v!=a {t.Fatal(v,e)}
 s:=string(b)
 for name,x:=range map[string]string{
 "duplicate":strings.Replace(s,"\"occurrence\":\"occ\"","\"occurrence\":\"occ\",\"occurrence\":\"other\"",1),
 "nested duplicate":strings.Replace(s,"\"run\":\"r\"","\"run\":\"r\",\"run\":\"q\"",1),
 "case":strings.Replace(s,"\"size\"","\"Size\"",1),
 "missing":strings.Replace(s,"\"occurrence\":\"occ\",","",1),
 "unknown":strings.Replace(s,"\"occurrence\":","\"extra\":0,\"occurrence\":",1),
 "null":strings.Replace(s,"\"occ\"","null",1),
 "numeric":strings.Replace(s,"\"9007199254740993\"","9007199254740993",1),
 "overflow":strings.Replace(s,"\"9007199254740993\"","\"18446744073709551616\"",1),
 "trailing":s+"{}",
 }{t.Run(name,func(t *testing.T){if _,e:=DecodeArtifactRef([]byte(x));e==nil{t.Fatal("accepted invalid reference")}})}
 if _,e:=DecodeArtifactRef(append(b,255));e==nil{t.Fatal("invalid UTF8")}
 if _,e:=DecodeArtifactRef(make([]byte,4097));e==nil{t.Fatal("oversized")}
}
