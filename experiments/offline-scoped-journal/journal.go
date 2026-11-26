// Package journal resolves bounded, producer-declared mapping windows offline.
// It does not authenticate the producer or prove sensor completeness.
package journal

import (
 "bytes"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "sort"
 "strconv"
 "unicode/utf8"
)

const MaxBytes = 1 << 20
const MaxRecords = 4096

type U64 uint64
func (v *U64) UnmarshalJSON(b []byte) error {
 var s string
 if err := json.Unmarshal(b,&s); err != nil || len(s)==0 || (len(s)>1 && s[0]=='0') { return errors.New("expected canonical decimal string") }
 for i:=range s { if s[i]<'0'||s[i]>'9' { return errors.New("expected decimal digits") } }
 n,e:=strconv.ParseUint(s,10,64); if e!=nil{return e}; *v=U64(n);return nil
}
func (v U64) MarshalJSON() ([]byte,error) {return json.Marshal(strconv.FormatUint(uint64(v),10))}
type Scope struct {
 Run string `json:"run"`
 Branch string `json:"branch"`
 Space string `json:"space"`
 Producer string `json:"producer"`
}
type Mapping struct {
 Base U64 `json:"base"`
 End U64 `json:"end"`
 Object string `json:"object"`
 Generation U64 `json:"generation"`
}
type Event struct {
 Seq U64 `json:"seq"`
 At U64 `json:"at"`
 Kind string `json:"kind"`
 Mapping Mapping `json:"mapping"`
}
type Window struct {
 Schema string `json:"schema"`
 Scope Scope `json:"scope"`
 From U64 `json:"from"`
 Until U64 `json:"until"`
 FirstSeq U64 `json:"first_seq"`
 SealNext U64 `json:"seal_next"`
 Sealed bool `json:"sealed"`
 Lost U64 `json:"lost"`
 SourceSHA string `json:"source_sha256"`
 Baseline []Mapping `json:"baseline"`
 Events []Event `json:"events"`
}
type Result struct {
 Status string `json:"status"`
 Coverage string `json:"coverage"`
 Scope Scope `json:"scope"`
 At U64 `json:"at"`
 Address U64 `json:"address"`
 SourceSHA string `json:"source_sha256,omitempty"`
 Mapping *Mapping `json:"mapping,omitempty"`
}
type Journal struct { w Window; gap bool }

func validID(s string)bool {
 if len(s)==0||len(s)>256{return false}
 for i:=range s { c:=s[i];if !(c>='a'&&c<='z'||c>='A'&&c<='Z'||c>='0'&&c<='9'||c=='.'||c=='_'||c==':'||c=='-'){return false} }
 return true
}
func validScope(s Scope)bool{return validID(s.Run)&&validID(s.Branch)&&validID(s.Space)&&validID(s.Producer)}
func validSHA(s string)bool{
 if len(s)!=64{return false}; b,e:=hex.DecodeString(s);return e==nil&&hex.EncodeToString(b)==s
}
func validMap(m Mapping)bool{return m.Base<m.End&&m.Generation>0&&validID(m.Object)}
func contains(m Mapping,a U64)bool{return m.Base<=a&&a<m.End}
func overlap(a,b Mapping)bool{return a.Base<b.End&&b.Base<a.End}

// exact rejects missing, extra, duplicate, case-variant and null fields.
func exact(b []byte, fields ...string)(map[string]json.RawMessage,error){
 d:=json.NewDecoder(bytes.NewReader(b))
 t,e:=d.Token();if e!=nil||t!=json.Delim('{'){return nil,errors.New("expected object")}
 allowed:=map[string]bool{};for _,k:=range fields{allowed[k]=true}
 out:=map[string]json.RawMessage{}
 for d.More(){
  t,e=d.Token();if e!=nil{return nil,e};k,ok:=t.(string)
  if !ok||!allowed[k]||out[k]!=nil{return nil,errors.New("unexpected or duplicate field")}
  var v json.RawMessage;if e=d.Decode(&v);e!=nil{return nil,e}
  if bytes.Equal(bytes.TrimSpace(v),[]byte("null")){return nil,errors.New("null field")}
  out[k]=v
 }
 t,e=d.Token();if e!=nil||t!=json.Delim('}')||len(out)!=len(fields){return nil,errors.New("incomplete object")}
 if _,e=d.Token();e!=io.EOF{return nil,errors.New("trailing input")};return out,nil
}
func exactMap(b []byte)error{_,e:=exact(b,"base","end","object","generation");return e}
func Decode(b []byte)(Window,error){
 var w Window
 if len(b)>MaxBytes||!utf8.Valid(b){return w,errors.New("invalid input size or UTF-8")}
 m,e:=exact(b,"schema","scope","from","until","first_seq","seal_next","sealed","lost","source_sha256","baseline","events");if e!=nil{return w,e}
 if _,e=exact(m["scope"],"run","branch","space","producer");e!=nil{return w,e}
 for _,key:=range []string{"baseline","events"}{
  var a []json.RawMessage;if e=json.Unmarshal(m[key],&a);e!=nil||a==nil||len(a)>MaxRecords{return w,errors.New("invalid bounded array")}
  for _,r:=range a{
   if key=="baseline"{if e=exactMap(r);e!=nil{return w,e}}else{
    f,err:=exact(r,"seq","at","kind","mapping");if err!=nil{return w,err};if e=exactMap(f["mapping"]);e!=nil{return w,e}
   }
  }
 }
 if e=json.Unmarshal(b,&w);e!=nil{return Window{},e};return w,nil
}

// Build copies the input. A sequence-complete window is only a producer claim;
// a missing sequence, loss indication or absent seal suppresses all resolutions.
func Build(w Window)(*Journal,error){
 if w.Schema!="scoped-journal/v1"||!validScope(w.Scope)||!validSHA(w.SourceSHA)||w.From>=w.Until||w.FirstSeq==0||w.SealNext<w.FirstSeq||len(w.Baseline)>MaxRecords||len(w.Events)>MaxRecords{return nil,errors.New("invalid window")}
 w.Baseline=append([]Mapping(nil),w.Baseline...);w.Events=append([]Event(nil),w.Events...)
 sort.Slice(w.Baseline,func(i,j int)bool{return w.Baseline[i].Base<w.Baseline[j].Base})
 for i,m:=range w.Baseline{if !validMap(m)||(i>0&&overlap(w.Baseline[i-1],m)){return nil,errors.New("invalid baseline")}}
 gap:=!w.Sealed||w.Lost!=0;next:=w.FirstSeq;lastAt:=w.From
 for _,e:=range w.Events{
  if e.Seq<next||e.Seq>=w.SealNext||e.At<=lastAt||e.At>=w.Until||!validMap(e.Mapping)||(e.Kind!="map"&&e.Kind!="unmap"){return nil,errors.New("invalid event order or fields")}
  if e.Seq!=next{gap=true};next=e.Seq+1;lastAt=e.At
 }
 if next!=w.SealNext{gap=true}
 if !gap{
  state:=append([]Mapping(nil),w.Baseline...)
  for _,e:=range w.Events{
   hit:=-1
   for i,m:=range state{if overlap(m,e.Mapping){if m!=e.Mapping||hit!=-1{return nil,errors.New("ambiguous lifecycle")};hit=i}}
   if e.Kind=="map"{if hit!=-1{return nil,errors.New("map already present")};state=append(state,e.Mapping)}else{if hit==-1{return nil,errors.New("unmap missing extent")};state=append(state[:hit],state[hit+1:]...)}
  }
 }
 return &Journal{w:w,gap:gap},nil
}
func (j *Journal) Resolve(s Scope,at,address U64)Result{
 r:=Result{Status:"unknown_scope",Coverage:"unknown",Scope:s,At:at,Address:address}
 if j==nil||s!=j.w.Scope{return r}
 r.SourceSHA=j.w.SourceSHA;r.Status="coverage_gap"
 if j.gap||at<j.w.From||at>=j.w.Until{return r}
 r.Coverage="producer_declared_contiguous";r.Status="unmapped"
 i:=sort.Search(len(j.w.Baseline),func(i int)bool{return j.w.Baseline[i].End>address})
 var m *Mapping
 if i<len(j.w.Baseline)&&contains(j.w.Baseline[i],address){x:=j.w.Baseline[i];m=&x}
 for _,e:=range j.w.Events{
  if e.At>at{break};if !contains(e.Mapping,address){continue}
  if e.Kind=="unmap"{m=nil}else{x:=e.Mapping;m=&x}
 }
 if m!=nil{r.Status="resolved";r.Mapping=m};return r
}
func ParseCoordinate(s string)(U64,error){
 if s==""{return 0,fmt.Errorf("coordinate is required")}
 base:=10;digits:=s
 if len(s)>2&&s[:2]=="0x"{base=16;digits=s[2:]}
 for i:=range digits{c:=digits[i];if !(c>='0'&&c<='9'||base==16&&(c>='a'&&c<='f'||c>='A'&&c<='F')){return 0,fmt.Errorf("invalid coordinate")}}
 n,e:=strconv.ParseUint(digits,base,64);return U64(n),e
}
