package cohort
import("bytes";"fmt";"strings";"testing")
var archive=strings.Repeat("a",64)
func fixture()[]Event{
 var es []Event
 for _,v:=range []string{"qtest","tcg-guest"}{for i:=0;i<8;i++{for _,op:=range []int{1,3,5,7,8}{
 m:=fmt.Sprintf("%s/%s-%d.raw",v,v,i)
 // All raw digests are deliberately identical; they cannot identify occurrences.
 es=append(es,Event{"vhe-raw-observation/v1","synthetic-device-model","unverified",v,occurrence(archive,m,op),archive,Plan,m,strings.Repeat("b",64),strings.Repeat("c",64),op,oracle[op]})
 }}}
 return es
}
func TestCohort(t *testing.T){
 es:=fixture();r,e:=Check(bytes.NewReader(JSONL(es)),archive)
 if e!=nil||len(r.Groups)!=16||r.ObservationCount!=80||r.Causality!="not-established"||r.ProducerAuthentication!="unverified"{t.Fatalf("%+v %v",r,e)}
 for i,j:=0,len(es)-1;i<j;i,j=i+1,j-1{es[i],es[j]=es[j],es[i]}
 if _,e=Check(bytes.NewReader(JSONL(es)),archive);e!=nil{t.Fatal(e)}
}
func TestRefusal(t *testing.T){
 for _,c:=range []struct{name string; change func([]Event)[]Event}{
 {"duplicate",func(a []Event)[]Event{a[1]=a[0];return a}},
 {"missing",func(a []Event)[]Event{return a[:79]}},
 {"forged-occurrence",func(a []Event)[]Event{a[0].Occurrence=strings.Repeat("d",64);return a}},
 {"wrong-value",func(a []Event)[]Event{a[0].Value=7;return a}},
 {"wrong-index",func(a []Event)[]Event{a[0].OperationIndex=2;return a}},
 {"wrong-vantage",func(a []Event)[]Event{a[0].Vantage="tcg-guest";return a}},
 {"live-promotion",func(a []Event)[]Event{a[0].Scope="live";return a}},
 {"auth-promotion",func(a []Event)[]Event{a[0].ProducerAuthentication="verified";return a}},
 {"other-archive",func(a []Event)[]Event{a[0].Archive=strings.Repeat("e",64);return a}},
 {"wrong-plan",func(a []Event)[]Event{a[0].Plan=strings.Repeat("e",64);return a}},
 {"wrong-raw-digest",func(a []Event)[]Event{a[0].RawDigest=strings.Repeat("d",64);return a}},
 {"wrong-receipt",func(a []Event)[]Event{a[0].Receipt=strings.Repeat("d",64);return a}},
 {"member-traversal",func(a []Event)[]Event{a[0].RawMember="../qtest-0.raw";return a}},
 }{t.Run(c.name,func(t *testing.T){if _,e:=Check(bytes.NewReader(JSONL(c.change(fixture()))),archive);e==nil{t.Fatal("accepted")}})}
 data:=JSONL(fixture())
 // Strict decoding must reject null, duplicate, missing zero-value, and extra fields.
 for _,c:=range []struct{name,old,new string}{
 {"duplicate-key",`"value":0`,`"value":0,"value":0`},
 {"null",`"value":0`,`"value":null`},
 {"missing",`,"value":0`,``},
 {"unknown",`"value":0`,`"value":0,"authority":true`},
 {"case",`"value":0`,`"Value":0`},
 }{t.Run(c.name,func(t *testing.T){b:=bytes.Replace(data,[]byte(c.old),[]byte(c.new),1);if _,e:=Check(bytes.NewReader(b),archive);e==nil{t.Fatal("accepted")}})}
}
