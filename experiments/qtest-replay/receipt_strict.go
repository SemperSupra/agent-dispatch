package main

import (
 "bytes"
 "encoding/json"
 "fmt"
 "io"
 "os"
)

// Read one bounded JSON object with exact case-sensitive required keys.
// Reject ambiguous inputs before typed decoding; never accept missing zero values.
func receiptObject(raw []byte, keys ...string)(map[string]json.RawMessage,error){
 d:=json.NewDecoder(bytes.NewReader(raw))
 start,e:=d.Token();if e!=nil||start!=json.Delim('{'){return nil,fmt.Errorf("object required")}
 allowed:=map[string]bool{};for _,k:=range keys{allowed[k]=true}
 got:=map[string]json.RawMessage{}
 for d.More(){
  tok,e:=d.Token();if e!=nil{return nil,e};k,ok:=tok.(string)
  if !ok||!allowed[k]||got[k]!=nil{return nil,fmt.Errorf("unknown or duplicate field %v",tok)}
  var v json.RawMessage;if e=d.Decode(&v);e!=nil{return nil,e}
  if bytes.Equal(bytes.TrimSpace(v),[]byte("null")){return nil,fmt.Errorf("null field %s",k)}
  got[k]=v
 }
 end,e:=d.Token();if e!=nil||end!=json.Delim('}')||len(got)!=len(keys){return nil,fmt.Errorf("incomplete object")}
 if _,e=d.Token();e!=io.EOF{return nil,fmt.Errorf("trailing data")}
 return got,nil
}
func decodeReceipt(raw []byte)(Receipt,error){
 var r Receipt
 if len(raw)>8192{return r,fmt.Errorf("receipt byte limit")}
 f,e:=receiptObject(raw,"plan_sha256","vantage","observations","process_exit","cleanup","elapsed_ns");if e!=nil{return r,e}
 var obs []json.RawMessage
 if e=json.Unmarshal(f["observations"],&obs);e!=nil||len(obs)!=5{return r,fmt.Errorf("expected five observations")}
 for _,o:=range obs{if _,e=receiptObject(o,"operation_index","value");e!=nil{return r,e}}
 e=json.Unmarshal(raw,&r);return r,e
}
func readReceipt(path string)(Receipt,[]byte,error){
 var r Receipt
 f,e:=os.Open(path);if e!=nil{return r,nil,e};defer f.Close()
 b,e:=io.ReadAll(io.LimitReader(f,8193));if e!=nil{return r,nil,e}
 r,e=decodeReceipt(b);return r,b,e
}
