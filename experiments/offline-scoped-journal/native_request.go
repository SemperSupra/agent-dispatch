package journal

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"
)

const MaxNativeRequestBytes = 16 << 10

// NativeRequest is a versioned read-only question, not an execution witness.
type NativeRequest struct {
	Schema string `json:"schema"`
	ExpectedScope Scope `json:"expected_scope"`
	Pointer EvidenceRange `json:"pointer"`
	Maps EvidenceRange `json:"maps"`
	Label string `json:"label"`
	ModulePath string `json:"module_path"`
	Image ArtifactRef `json:"image"`
}

func (r NativeRequest) Query() NativeQuery {
	return NativeQuery{ExpectedScope:r.ExpectedScope,Pointer:r.Pointer,Maps:r.Maps,Label:r.Label,ModulePath:r.ModulePath,Image:r.Image}
}

// DecodeNativeRequest validates every nested field before any source I/O.
// The resolver's no-pin preflight checks the same scope and range invariants.
func DecodeNativeRequest(b []byte)(NativeRequest,error){
	var r NativeRequest
	if len(b)>MaxNativeRequestBytes||!utf8.Valid(b){return r,errors.New("invalid request size or UTF-8")}
	m,e:=exact(b,"schema","expected_scope","pointer","maps","label","module_path","image")
	if e!=nil{return r,e}
	if _,e=exact(m["expected_scope"],"run","branch","space","producer");e!=nil{return r,e}
	for _,name:=range []string{"pointer","maps"}{
		f,e:=exact(m[name],"artifact","offset","length");if e!=nil{return r,e}
		if _,e=DecodeArtifactRef(f["artifact"]);e!=nil{return r,e}
	}
	if _,e=DecodeArtifactRef(m["image"]);e!=nil{return r,e}
	if e=json.Unmarshal(b,&r);e!=nil{return NativeRequest{},e}
	if r.Schema!="native-correspondence/v1"||strings.ContainsRune(r.ModulePath,utf8.RuneError){return NativeRequest{},errors.New("unsupported schema or path encoding")}
	if _,e=ResolveNativeELF64(r.Query(),nil,nil,nil,nil);e!=nil{return NativeRequest{},e}
	return r,nil
}
