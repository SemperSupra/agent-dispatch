// Read-only cohort checker for the fixed VHE raw observation projection.
// Equivalence of observations is not causal identity or producer authentication.
package cohort

import(
 "bufio"
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "regexp"
 "sort"
 "strconv"
 "strings"
)

const Plan="37c4de04e82b2e11fb080797428641ba76510c4773a33bbec665a2f97dd9cf8c"
type Event struct {
 Schema string `json:"schema"`
 Scope string `json:"scope"`
 ProducerAuthentication string `json:"producer_authentication"`
 Vantage string `json:"vantage"`
 Occurrence string `json:"occurrence_id"`
 Archive string `json:"archive_sha256"`
 Plan string `json:"plan_sha256"`
 RawMember string `json:"raw_member"`
 RawDigest string `json:"raw_sha256"`
 Receipt string `json:"related_receipt_sha256"`
 OperationIndex int `json:"operation_index"`
 Value uint32 `json:"value"`
}
type Group struct {
 Vantage string
 Member string
 RawDigest string
 Receipt string
 Occurrences []string
}
type Report struct {
 Groups []Group
 ObservationCount int
 Equivalence string
 Causality string
 ProducerAuthentication string
}
var memberRE=regexp.MustCompile(`^(qtest|tcg-guest)/(qtest|tcg-guest)-([0-7])\.raw$`)
var digestRE=regexp.MustCompile(`^[0-9a-f]{64}$`)
var oracle=map[int]uint32{1:0,3:0,5:3,7:256,8:0}
var fields=map[string]bool{"schema":true,"scope":true,"producer_authentication":true,"vantage":true,"occurrence_id":true,"archive_sha256":true,"plan_sha256":true,"raw_member":true,"raw_sha256":true,"related_receipt_sha256":true,"operation_index":true,"value":true}
func occurrence(a,m string,i int)string{
 d:=sha256.Sum256([]byte(fmt.Sprintf("vhe-occurrence/v1\x00%s\x00%s\x00%d",a,m,i)));return hex.EncodeToString(d[:])
}
func decode(line []byte)(Event,error){
 var e Event
 d:=json.NewDecoder(bytes.NewReader(line))
 t,err:=d.Token();if err!=nil||t!=json.Delim('{'){return e,fmt.Errorf("not object")}
 seen:=map[string]bool{}
 for d.More(){
  key,err:=d.Token();if err!=nil{return e,err}
  k,ok:=key.(string);if !ok||!fields[k]||seen[k]{return e,fmt.Errorf("unknown/duplicate field")};seen[k]=true
  var raw json.RawMessage;if err=d.Decode(&raw);err!=nil||bytes.Equal(bytes.TrimSpace(raw),[]byte("null")){return e,fmt.Errorf("null or invalid field")}
 }
 t,err=d.Token();if err!=nil||t!=json.Delim('}')||len(seen)!=len(fields){return e,fmt.Errorf("incomplete object")}
 if _,err=d.Token();err!=io.EOF{return e,fmt.Errorf("trailing JSON")}
 err=json.Unmarshal(line,&e);return e,err
}

// Check validates shape, complete groups, fixed oracle and occurrence references.
// The archive digest is caller-supplied from the verified external custody.
// It does not verify raw bytes: run the R7 archive projector first. No trust promotion.
func Check(r io.Reader, archive string)(Report,error){
 var out Report
 if !digestRE.MatchString(archive){return out,fmt.Errorf("archive digest")}
 s:=bufio.NewScanner(io.LimitReader(r,1<<20));s.Buffer(make([]byte,4096),8192)
 groups:=map[string]*Group{};seen:=map[string]bool{};per:=map[string]map[int]bool{}
 for s.Scan(){
  e,err:=decode(s.Bytes());if err!=nil{return out,err}
  m:=memberRE.FindStringSubmatch(e.RawMember)
  want,ok:=oracle[e.OperationIndex]
  if e.Schema!="vhe-raw-observation/v1"||e.Scope!="synthetic-device-model"||e.ProducerAuthentication!="unverified"||e.Archive!=archive||e.Plan!=Plan||len(m)!=4||m[1]!=e.Vantage||m[2]!=e.Vantage||!digestRE.MatchString(e.RawDigest)||!digestRE.MatchString(e.Receipt)||!ok||e.Value!=want{return out,fmt.Errorf("unsupported observation")}
  if e.Occurrence!=occurrence(archive,e.RawMember,e.OperationIndex)||seen[e.Occurrence]{return out,fmt.Errorf("occurrence invalid or duplicated")}
  seen[e.Occurrence]=true
  g:=groups[e.RawMember]
  if g==nil {g=&Group{Vantage:e.Vantage,Member:e.RawMember,RawDigest:e.RawDigest,Receipt:e.Receipt};groups[e.RawMember]=g;per[e.RawMember]=map[int]bool{}}
  if g.RawDigest!=e.RawDigest||g.Receipt!=e.Receipt||per[e.RawMember][e.OperationIndex]{return out,fmt.Errorf("inconsistent witness group")}
  per[e.RawMember][e.OperationIndex]=true
  g.Occurrences=append(g.Occurrences,e.Occurrence)
  if len(seen)>80{return out,fmt.Errorf("too many observations")}
 }
 if err:=s.Err();err!=nil{return out,err}
 if len(seen)!=80||len(groups)!=16{return out,fmt.Errorf("incomplete cohort")}
 for _,v:=range []string{"qtest","tcg-guest"}{
  for i:=0;i<8;i++{
   member:=v+"/"+v+"-"+strconv.Itoa(i)+".raw";g:=groups[member]
   if g==nil||len(per[member])!=5{return Report{},fmt.Errorf("missing group")}
   sort.Strings(g.Occurrences);out.Groups=append(out.Groups,*g)
  }
 }
 out.ObservationCount=80;out.Equivalence="fixed-oracle-agreement";out.Causality="not-established";out.ProducerAuthentication="unverified"
 return out,nil
}
func JSONL(es []Event)[]byte{
 var b strings.Builder;enc:=json.NewEncoder(&b);for _,e:=range es{_ = enc.Encode(e)};return []byte(b.String())
}
