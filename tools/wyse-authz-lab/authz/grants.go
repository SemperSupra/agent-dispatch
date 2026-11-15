package authz

import (
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "strings"
)

type grantDocument struct {
 Schema string `json:"schema"`
 Principals []struct {
  SPKI string `json:"spki_sha256"`
  Audience Audience `json:"audience"`
  Capabilities []Capability `json:"capabilities"`
  Disabled bool `json:"disabled,omitempty"`
 } `json:"principals"`
}
// LoadGrants binds each non-exportable client private key to an explicit
// approved audience and capabilities. The caller must protect this file in
// an approved secret/config store, never accept it from an HTTP request.
func LoadGrants(r io.Reader)(*Authorizer,error){
 if r==nil{return nil,errors.New("missing grants")}
 dec:=json.NewDecoder(io.LimitReader(r,65537))
 dec.DisallowUnknownFields()
 var doc grantDocument
 if err:=dec.Decode(&doc);err!=nil{return nil,err}
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF{return nil,errors.New("trailing or overlarge grants")}
 if doc.Schema!="wyse-mtls-grants/v1"{return nil,errors.New("invalid grants schema")}
 if len(doc.Principals)==0||len(doc.Principals)>256{return nil,errors.New("grant count out of range")}
 g:=make(map[[32]byte]Grant,len(doc.Principals))
 for _,p:=range doc.Principals {
  if strings.TrimSpace(p.SPKI)!=p.SPKI{return nil,errors.New("uncanonical fingerprint")}
  raw,err:=hex.DecodeString(p.SPKI)
  if err!=nil||len(raw)!=32||hex.EncodeToString(raw)!=p.SPKI{return nil,errors.New("invalid SPKI fingerprint")}
  var id [32]byte;copy(id[:],raw)
  if _,ok:=g[id];ok{return nil,fmt.Errorf("duplicate principal %x",id[:4])}
  allowed:=make(map[Capability]bool,len(p.Capabilities))
  for _,cap:=range p.Capabilities{
   if allowed[cap]{return nil,fmt.Errorf("duplicate capability %q",cap)}
   allowed[cap]=true
  }
  g[id]=Grant{Role:p.Audience,Capabilities:allowed,Disabled:p.Disabled}
 }
 return New(g)
}
