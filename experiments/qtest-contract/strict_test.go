package experiment

import ("strings";"testing")

func TestStrictShape(t *testing.T) {
 const prefix = `{"version":"v1","scope":"synthetic-device-model","operations":`
 const clock = `{"kind":"clock-step","nanoseconds":1000000000}`
 for _,c:=range []struct{name,body string}{
 {"duplicate-root",`{"version":"v1","version":"v1","scope":"synthetic-device-model","operations":[`+clock+`]}`},
 {"case-root",`{"Version":"v1","scope":"synthetic-device-model","operations":[`+clock+`]}`},
 {"duplicate-operation",prefix+`[{"kind":"clock-step","kind":"clock-step","nanoseconds":1}]}`},
 {"escaped-duplicate",prefix+`[{"kind":"clock-step","k\u0069nd":"clock-step","nanoseconds":1}]}`},
 {"case-operation",prefix+`[{"Kind":"clock-step","nanoseconds":1}]}`},
 {"explicit-null",prefix+`[{"kind":"clock-step","nanoseconds":1,"port":null}]}`},
 {"null-operation",prefix+`[null]}`},
 {"null-version",`{"version":null,"scope":"synthetic-device-model","operations":[`+clock+`]}`},
 {"wrong-shape",prefix+`{"kind":"clock-step","nanoseconds":1}}`},
 {"clock-budget",prefix+"["+strings.Repeat(clock+",",10)+clock+"]}"},
 {"operation-budget",prefix+"["+strings.Repeat(clock+",",128)+clock+"]}"},
 {"input-budget",strings.Repeat(" ",65537)},
 }{t.Run(c.name,func(t *testing.T){if _,err:=Decode(strings.NewReader(c.body));err==nil{t.Fatal("ambiguous or excessive proposal admitted")}})}
 if _,err:=Decode(strings.NewReader(prefix+"["+strings.Repeat(clock+",",9)+clock+"]}"));err!=nil{t.Fatal("exact clock budget rejected",err)}
}
