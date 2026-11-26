// Fixed synthetic schedule receipt checker. Not producer authentication.
package main

import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "os"
 "path/filepath"
)

type Snap [3]uint32
type Step struct {
 Actor string `json:"actor"`
 Action string `json:"action"`
 Before Snap `json:"before"`
 After Snap `json:"after"`
}
type Receipt struct {
 Schedule string `json:"schedule"`
 Steps []Step `json:"steps"`
 Present Snap `json:"present"`
 Absent Snap `json:"absent"`
 Status uint32 `json:"status"`
 ResetStatus uint32 `json:"reset_status"`
 ResetPresent Snap `json:"reset_present"`
 ProcessExit int `json:"process_exit"`
 Cleanup bool `json:"cleanup"`
 ElapsedNS int64 `json:"elapsed_ns"`
 RawSHA256 string `json:"raw_sha256"`
}
var p=Snap{0,256,0}
var a=Snap{1,0,0}
var w=Snap{0,256,1}
// Hand-enumerated after-state oracles, independent of replay implementation.
var oracle=map[string][4]Snap{
 "AABB":{a,a,p,p}, "ABAB":{a,p,w,w}, "ABBA":{a,p,p,w},
 "BAAB":{p,a,a,a}, "BABA":{p,a,a,a}, "BBAA":{p,p,a,a},
}
var orders=[]string{"AABB","ABAB","ABBA","BAAB","BABA","BBAA"}
func digest(b []byte) string {h:=sha256.Sum256(b);return hex.EncodeToString(h[:])}
func decode(raw []byte)(Receipt,error){
 var r Receipt
 if len(raw)>8192{return r,fmt.Errorf("receipt size")}
 if e:=json.Unmarshal(raw,&r);e!=nil{return r,e}
 canon,e:=json.Marshal(r);if e!=nil{return r,e}
 // Exact canonical JSON ensures no unknown/duplicate/case/null/missing fields.
 if !bytes.Equal(raw,append(canon,'\n')){return r,fmt.Errorf("noncanonical receipt")}
 return r,nil
}
func check(r Receipt, order string, raw []byte)error{
 states,ok:=oracle[order]
 if !ok||r.Schedule!=order||len(r.Steps)!=4{return fmt.Errorf("schedule binding")}
 if len(raw)==0||len(raw)>1<<20||r.RawSHA256!=digest(raw){return fmt.Errorf("raw digest")}
 prior:=p; counts:=map[byte]int{}
 for i,step:=range r.Steps{
  actor:=order[i];action:="select"
  if counts[actor]>0 {if actor=='A'{action="write"}else{action="read"}}
  counts[actor]++
  if step.Actor!=string(actor)||step.Action!=action||step.Before!=prior||step.After!=states[i]{return fmt.Errorf("step %d: oracle mismatch",i)}
  prior=states[i]
 }
 final:=p;if order=="ABAB"||order=="ABBA"{final=w}
 if r.Present!=final||r.Absent!=a||r.Status!=3||r.ResetStatus!=0||r.ResetPresent!=p||r.ProcessExit!=0||!r.Cleanup||r.ElapsedNS<=0{return fmt.Errorf("terminal oracle or lifecycle mismatch")}
 return nil
}
func bounded(path string, max int64)([]byte,error){
 f,e:=os.Open(path);if e!=nil{return nil,e};defer f.Close()
 b,e:=io.ReadAll(io.LimitReader(f,max+1));if e!=nil{return nil,e}
 if int64(len(b))>max{return nil,fmt.Errorf("input too large")};return b,nil
}
func run(dir string)error{
 entries,e:=os.ReadDir(dir);if e!=nil{return e};if len(entries)!=12{return fmt.Errorf("incomplete or extra schedule cohort")}
 var total int64
 for _,order:=range orders{
  b,e:=bounded(filepath.Join(dir,order+".json"),8192);if e!=nil{return e}
  r,e:=decode(b);if e!=nil{return e}
  raw,e:=bounded(filepath.Join(dir,order+".raw"),1<<20);if e!=nil{return e}
  if e=check(r,order,raw);e!=nil{return fmt.Errorf("%s: %w",order,e)}
  total+=r.ElapsedNS
  fmt.Printf("VERIFIED %s elapsed_ns=%d raw_sha256=%s\n",order,r.ElapsedNS,r.RawSHA256)
 }
 fmt.Printf("complete=6 expected_harness_hazards=4 serialized_safe=2 wall_sum_ns=%d verified_schedules_per_min=%.3f\n",total,360e9/float64(total))
 return nil
}
func main(){
 if len(os.Args)!=2 {fmt.Fprintln(os.Stderr,"usage: schedule-check EVIDENCE_DIR");os.Exit(2)}
 if e:=run(os.Args[1]);e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}
}
