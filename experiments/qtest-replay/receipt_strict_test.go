package main
import("encoding/json";"strings";"testing")
func TestStrictReceipt(t *testing.T){
 p,e:=plan();if e!=nil{t.Fatal(e)}
 b,_:=json.Marshal(p);b=append(b,'\n')
 raw,_:=json.Marshal(Receipt{hash(b),"qtest",p.Expected,0,true,1});s:=string(raw)
 r,e:=decodeReceipt(raw);if e!=nil{t.Fatal(e)};if e=verify(p,b,r);e!=nil{t.Fatal(e)}
 cases:=map[string]string{
 "duplicate-root":strings.Replace(s,"\"cleanup\":true","\"cleanup\":true,\"cleanup\":true",1),
 "case-root":strings.Replace(s,"\"cleanup\"","\"Cleanup\"",1),
 "unknown-root":strings.Replace(s,"\"cleanup\":true","\"cleanup\":true,\"extra\":1",1),
 "missing-zero-exit":strings.Replace(s,"\"process_exit\":0,","",1),
 "null-exit":strings.Replace(s,"\"process_exit\":0","\"process_exit\":null",1),
 "null-obs":strings.Replace(s,"\"operation_index\":1","\"operation_index\":null",1),
 "missing-zero":strings.Replace(s,",\"value\":0","",1),
 "duplicate-obs":strings.Replace(s,"\"value\":0","\"value\":0,\"value\":0",1),
 "case-obs":strings.Replace(s,"\"value\":0","\"Value\":0",1),
 "unknown-obs":strings.Replace(s,"\"value\":0","\"value\":0,\"other\":0",1),
 "trailing":s+"{}",
 "oversize":s+strings.Repeat(" ",8192),
 }
 for name,bad:=range cases{t.Run(name,func(t *testing.T){if bad==s{t.Fatal("ineffective mutation")};if _,e:=decodeReceipt([]byte(bad));e==nil{t.Fatal("accepted ambiguous receipt")}})}
}
