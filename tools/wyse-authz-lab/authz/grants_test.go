package authz

import (
 "bytes"
 "encoding/hex"
 "strings"
 "testing"
)
func TestLoadGrantsRejectsMalformedDuplicateAndUnknown(t *testing.T){
 fp:=strings.Repeat("a",64)
 happy:=`{"schema":"wyse-mtls-grants/v1","principals":[{"spki_sha256":"`+fp+`","audience":"agent","capabilities":["inventory.read","evidence.append"]}]}`
 a,err:=LoadGrants(strings.NewReader(happy))
 if err!=nil||a==nil{t.Fatalf("valid grants refused: %v",err)}
 for _,in:=range []string{
  "", "{}", strings.Replace(happy,"wyse-mtls-grants/v1","wrong",1),
  strings.Replace(happy,"inventory.read","firmware.flash",1),
  strings.Replace(happy,"agent","root",1),
  strings.Replace(happy,fp,strings.ToUpper(fp),1),
  strings.Replace(happy,fp,fp[:63],1),
  strings.Replace(happy,`["inventory.read","evidence.append"]`, `["inventory.read","inventory.read"]`,1),
  strings.Replace(happy,`}]}`, `},{"spki_sha256":"`+fp+`","audience":"human","capabilities":["inventory.read"]}]}`,1),
  happy+`{}`,
  strings.Replace(happy,`"audience":"agent"`,`"audience":"agent","unknown":"x"`,1),
 } {
  if _,err:=LoadGrants(strings.NewReader(in));err==nil{t.Errorf("bad grant accepted: %.70s",in)}
 }
 if _,err:=LoadGrants(bytes.NewReader(make([]byte,100000)));err==nil{t.Fatal("unbounded blob accepted")}
 raw,_:=hex.DecodeString(fp)
 if len(raw)!=32{t.Fatal("test fixture fingerprint invalid")}
}
