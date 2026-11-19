// Command batchplan only produces an offline selection plan; an authorized
// executor must separately bind/dispatch each item and record receipts.
package main

import (
 "encoding/json"
 "fmt"
 "os"

 "example.org/usb-fabric-r21/batchplanner"
)
func main(){
 if len(os.Args)!=2&&len(os.Args)!=3{fmt.Fprintln(os.Stderr,"usage: batchplan batch.json [statuses.json]");os.Exit(2)}
 raw,e:=os.ReadFile(os.Args[1]);if e!=nil{panic(e)}
 var m batchplanner.Manifest;if e=json.Unmarshal(raw,&m);e!=nil{panic(e)}
 var statuses []batchplanner.Status
 if len(os.Args)==3{
  raw,e=os.ReadFile(os.Args[2]);if e!=nil{panic(e)}
  if e=json.Unmarshal(raw,&statuses);e!=nil{panic(e)}
 }
 plan,e:=batchplanner.Schedule(m,statuses);if e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(3)}
 output,e:=json.MarshalIndent(plan,"","  ");if e!=nil{panic(e)}
 fmt.Println(string(output))
}
