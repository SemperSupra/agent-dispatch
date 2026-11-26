package journal
import ("encoding/json";"strings";"testing")
func example()Window{
 return Window{Schema:"scoped-journal/v1",Scope:Scope{"run","root","guest-va","observer"},From:10,Until:30,FirstSeq:5,SealNext:7,Sealed:true,SourceSHA:strings.Repeat("a",64),Baseline:[]Mapping{{100,200,"allocation",1}},Events:[]Event{{5,15,"unmap",Mapping{100,200,"allocation",1}},{6,20,"map",Mapping{100,200,"allocation",2}}}}
}
func TestLifecycle(t *testing.T){
 w:=example();j,e:=Build(w);if e!=nil{t.Fatal(e)}
 for _,c:=range []struct{at,a U64;s string;g U64}{{10,100,"resolved",1},{14,199,"resolved",1},{15,100,"unmapped",0},{19,100,"unmapped",0},{20,100,"resolved",2},{29,199,"resolved",2},{29,200,"unmapped",0},{30,100,"coverage_gap",0},{9,100,"coverage_gap",0}}{
  r:=j.Resolve(w.Scope,c.at,c.a);if r.Status!=c.s{t.Fatal(c,r)};if c.g!=0&&(r.Mapping==nil||r.Mapping.Generation!=c.g){t.Fatal(c,r)};if c.g==0&&r.Mapping!=nil{t.Fatal(c,r)}
 }
 s:=w.Scope;s.Branch="restored";if r:=j.Resolve(s,20,100);r.Status!="unknown_scope"{t.Fatal(r)}
 w.Events[1].Mapping.Generation=99;w.Baseline[0].Object="mutated"
 if r:=j.Resolve(j.w.Scope,20,100);r.Mapping==nil||r.Mapping.Generation!=2{t.Fatal("input mutated journal",r)}
 r:=j.Resolve(j.w.Scope,20,100);r.Mapping.Generation=99
 if j.Resolve(j.w.Scope,20,100).Mapping.Generation!=2{t.Fatal("result mutated journal")}
}
func TestGap(t *testing.T){
 for name,mut:=range map[string]func(*Window){
 "unsealed":func(w *Window){w.Sealed=false},"loss":func(w *Window){w.Lost=1},
 "prefix":func(w *Window){w.Events=w.Events[1:]},"suffix":func(w *Window){w.Events=w.Events[:1]},
 "interior":func(w *Window){w.SealNext=8;w.Events[1].Seq=7},
 }{t.Run(name,func(t *testing.T){w:=example();mut(&w);j,e:=Build(w);if e!=nil{t.Fatal(e)};r:=j.Resolve(w.Scope,20,100);if r.Status!="coverage_gap"||r.Mapping!=nil{t.Fatal(r)}})}
}
func TestInvalid(t *testing.T){
 for name,mut:=range map[string]func(*Window){
 "overlap":func(w *Window){w.Baseline=append(w.Baseline,Mapping{150,220,"other",1})},
 "duplicate":func(w *Window){w.Events[1].Seq=5},
 "out-of-order":func(w *Window){w.Events[1].At=14},
 "missing-unmap":func(w *Window){w.Events[0].Mapping.Object="wrong"},
 "generation-zero":func(w *Window){w.Events[1].Mapping.Generation=0},
 "invalid-extent":func(w *Window){w.Baseline[0].End=99},
 "bad-scope":func(w *Window){w.Scope.Run="invalid/name"},
 "bad-digest":func(w *Window){w.SourceSHA="not-a-digest"},
 "duplicate-map":func(w *Window){w.Events[0].Kind="map"},
 }{t.Run(name,func(t *testing.T){w:=example();mut(&w);if _,e:=Build(w);e==nil{t.Fatal("accepted")}})}
}
func TestWire(t *testing.T){
 w:=example();b,e:=json.Marshal(w);if e!=nil{t.Fatal(e)}
 if x,e:=Decode(b);e!=nil||x.Scope!=w.Scope{t.Fatal(x,e)}
 s:=string(b)
 for name,bad:=range map[string]string{
 "duplicate":strings.Replace(s,"\"run\":\"run\"","\"run\":\"run\",\"run\":\"other\"",1),
 "case":strings.Replace(s,"\"run\":","\"Run\":",1),
 "unknown":strings.Replace(s,"\"run\":","\"extra\":1,\"run\":",1),
 "missing":strings.Replace(s,"\"run\":\"run\",","",1),
 "numeric":strings.Replace(s,"\"from\":\"10\"","\"from\":10",1),
 "leading-zero":strings.Replace(s,"\"from\":\"10\"","\"from\":\"010\"",1),
 "overflow":strings.Replace(s,"\"from\":\"10\"","\"from\":\"18446744073709551616\"",1),
 "null":strings.Replace(s,"\"sealed\":true","\"sealed\":null",1),
 "trailing":s+"{}",
 "nested-duplicate":strings.Replace(s,"\"base\":\"100\"","\"base\":\"100\",\"base\":\"200\"",1),
 }{t.Run(name,func(t *testing.T){if _,e:=Decode([]byte(bad));e==nil{t.Fatal("accepted")}})}
 if _,e:=Decode(append(b,0xff));e==nil{t.Fatal("invalid UTF8")}
 if _,e:=Decode(make([]byte,MaxBytes+1));e==nil{t.Fatal("oversize")}
 // Codepoints are rejected at the admission boundary, even if JSON decoded them.
 for _,id:=range []string{"\uFFFD","\u00e9","e\u0301","\x00","a b"}{w:=example();w.Scope.Run=id;if _,e:=Build(w);e==nil{t.Fatal(id)}}
}
