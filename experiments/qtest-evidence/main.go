// Read-only projector for the qualified legacy queue replay fixture.
// An expected ZIP digest comes from the caller's trusted custody context.
// This is NOT runtime authentication, an actuator, or an Observatory schema.
package main

import (
 "archive/zip"
 "bytes"
 "crypto/sha256"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "os"
 "path"
 "regexp"
 "strconv"
 "strings"
)

const planDigest="37c4de04e82b2e11fb080797428641ba76510c4773a33bbec665a2f97dd9cf8c"
const sourceCommit="698104725efad4b29079d857dfdebbd804e34c99"
const maxZip=2<<20
const maxMember=2<<20

func digest(b []byte)string{h:=sha256.Sum256(b);return hex.EncodeToString(h[:])}
type read struct{ Index int; Value uint32 }
var oracle=[]read{{1,0},{3,0},{5,3},{7,256},{8,0}}
type pair struct{ cmd string; args []uint32; reply []uint32 }
// Explicit preconditions and experiment operations, independently enumerated.
// Every response is checked; no substring or tail-only matching.
var pairs=[]pair{
 {"outl",[]uint32{0xcf8,0x80003000},nil},{"inl",[]uint32{0xcfc},[]uint32{0x10011af4}},
 {"outl",[]uint32{0xcf8,0x80003010},nil},{"outl",[]uint32{0xcfc,0x1001},nil},
 {"outl",[]uint32{0xcf8,0x80003004},nil},{"outw",[]uint32{0xcfc,1},nil},
 {"outl",[]uint32{0xcf8,0x80003010},nil},{"inl",[]uint32{0xcfc},[]uint32{0x1001}},
 {"outb",[]uint32{0x1012,0},nil},{"outb",[]uint32{0x1012,1},nil},{"outb",[]uint32{0x1012,3},nil},
 {"outw",[]uint32{0x100e,0},nil},{"inb",[]uint32{0x1012},[]uint32{3}},
 {"inw",[]uint32{0x100c},[]uint32{256}},{"inl",[]uint32{0x1008},[]uint32{0}},
 {"outw",[]uint32{0x100e,1},nil},{"inw",[]uint32{0x100c},[]uint32{0}},
 {"outl",[]uint32{0x1008,1},nil},{"inl",[]uint32{0x1008},[]uint32{0}},
 {"outw",[]uint32{0x1010,1},nil},{"inb",[]uint32{0x1012},[]uint32{3}},
 {"outw",[]uint32{0x100e,0},nil},{"inw",[]uint32{0x100c},[]uint32{256}},
 {"inl",[]uint32{0x1008},[]uint32{0}},
}
var lineRE=regexp.MustCompile(`^\[([IRS]) [^\]\r\n]+\] (.+)$`)
func match(line,typ,verb string, values []uint32)bool{
 m:=lineRE.FindStringSubmatch(line);if len(m)!=3||m[1]!=typ{return false}
 fields:=strings.Fields(m[2]);if len(fields)!=len(values)+1||fields[0]!=verb{return false}
 for i,w:=range values{n,e:=strconv.ParseUint(fields[i+1],0,32);if e!=nil||uint32(n)!=w{return false}}
 return true
}
func qtest(raw []byte)([]read,error){
 if len(raw)>65536{return nil,errors.New("raw log bound")}
 lines:=strings.Split(strings.TrimSuffix(string(raw),"\n"),"\n")
 if len(lines)!=2+2*len(pairs)||!match(lines[0],"I","OPENED",nil)||!match(lines[len(lines)-1],"I","CLOSED",nil){return nil,errors.New("QTest framing/count")}
 out:=[]read{}
 for i,p:=range pairs{
  if !match(lines[1+2*i],"R",p.cmd,p.args)||!match(lines[2+2*i],"S","OK",p.reply){return nil,fmt.Errorf("QTest operation %d mismatch",i)}
  if i>=15&&len(p.reply)==1{
   // Return the actual independently parsed value, not a producer receipt.
   f:=strings.Fields(lineRE.FindStringSubmatch(lines[2+2*i])[2])
   v,_:=strconv.ParseUint(f[1],0,32);out=append(out,read{i-15,uint32(v)})
  }
 }
 return out,nil
}
func guest(raw []byte)([]read,error){
 if len(raw)!=44{return nil,errors.New("guest witness length")}
 pre:=[]uint32{0x35454856,0x10011af4,0x1001,3,256,0}
 for i,w:=range pre{if binary.LittleEndian.Uint32(raw[i*4:])!=w{return nil,errors.New("guest precondition")}}
 out:=[]read{}
 for i,w:=range oracle{v:=binary.LittleEndian.Uint32(raw[(i+6)*4:]);if v!=w.Value{return nil,errors.New("guest observation mismatch")};out=append(out,read{w.Index,v})}
 return out,nil
}
func members(blob []byte, expected string)(map[string][]byte,error){
 if len(blob)>maxZip||digest(blob)!=expected{return nil,errors.New("archive bound/digest")}
 r,e:=zip.NewReader(bytes.NewReader(blob),int64(len(blob)));if e!=nil{return nil,e}
 if len(r.File)>128{return nil,errors.New("member count")}
 m:=map[string][]byte{};var total uint64
 for _,f:=range r.File{
  n:=f.Name
  if n==""||path.Clean(n)!=n||strings.HasPrefix(n,"/")||strings.HasPrefix(n,"../")||n==".."||strings.Contains(n,"\\")||!f.Mode().IsRegular(){return nil,errors.New("unsafe member")}
  if _,ok:=m[n];ok{return nil,errors.New("duplicate member")}
  if f.UncompressedSize64>maxMember||total+f.UncompressedSize64>8<<20{return nil,errors.New("member bounds")}
  rr,e:=f.Open();if e!=nil{return nil,e};v,e:=io.ReadAll(io.LimitReader(rr,maxMember+1));ce:=rr.Close();if e!=nil||ce!=nil||uint64(len(v))!=f.UncompressedSize64||len(v)>maxMember{return nil,errors.New("member read/CRC")}
  total+=uint64(len(v));m[n]=v
 }
 manifest,ok:=m["SHA256SUMS"];if !ok{return nil,errors.New("manifest absent")}
 seen:=map[string]bool{}
 for _,l:=range strings.Split(strings.TrimSuffix(string(manifest),"\n"),"\n"){
  f:=strings.Fields(l);if len(f)!=2{return nil,errors.New("manifest shape")}
  n:=strings.TrimPrefix(f[1],"./");b,ok:=m[n]
  if !ok||n=="SHA256SUMS"||seen[n]||digest(b)!=f[0]{return nil,errors.New("manifest mismatch")};seen[n]=true
 }
 if len(seen)!=len(m)-1{return nil,errors.New("unlisted member")}
 return m,nil
}
type event struct{
 Schema string `json:"schema"`
 Scope string `json:"scope"`
 ProducerAuthentication string `json:"producer_authentication"`
 Vantage string `json:"vantage"`
 Occurrence string `json:"occurrence_id"`
 Archive string `json:"archive_sha256"`
 Plan string `json:"plan_sha256"`
 RawMember string `json:"raw_member"`
 RawDigest string `json:"raw_sha256"`
 RelatedReceipt string `json:"related_receipt_sha256"`
 OperationIndex int `json:"operation_index"`
 Value uint32 `json:"value"`
}
func project(blob []byte, expected string)([]event,error){
 m,e:=members(blob,expected);if e!=nil{return nil,e}
 if digest(m["plan.json"])!=planDigest||!strings.HasPrefix(string(m["source.txt"]),sourceCommit+" "){return nil,errors.New("unsupported fixture")}
 out:=[]event{}
 for _,v:=range []string{"qtest","tcg-guest"}{
  for i:=0;i<8;i++{
   prefix:=fmt.Sprintf("%s/%s-%d",v,v,i)
   raw,ok:=m[prefix+".raw"];rec,rok:=m[prefix+".json"];if !ok||!rok{return nil,errors.New("missing raw or related receipt")}
   var reads []read
   if v=="qtest"{reads,e=qtest(raw)}else{reads,e=guest(raw)}
   if e!=nil{return nil,fmt.Errorf("%s: %w",prefix,e)}
   if len(reads)!=5{return nil,errors.New("read count")}
   for _,r:=range reads{
    member:=prefix+".raw"
    id:=digest([]byte(fmt.Sprintf("vhe-occurrence/v1\x00%s\x00%s\x00%d",expected,member,r.Index)))
    out=append(out,event{"vhe-raw-observation/v1","synthetic-device-model","unverified",v,id,expected,planDigest,member,digest(raw),digest(rec),r.Index,r.Value})
   }
  }
 }
 return out,nil
}
func run()error{
 a:=flag.String("archive","","qualified replay artifact ZIP")
 h:=flag.String("sha256","","expected archive SHA-256 from trusted external custody")
 flag.Parse()
 if *a==""||len(*h)!=64||flag.NArg()!=0{return errors.New("provide -archive and -sha256; read-only fixed fixture")}
 if _,e:=hex.DecodeString(*h);e!=nil{return e}
 f,e:=os.Open(*a);if e!=nil{return e};defer f.Close()
 b,e:=io.ReadAll(io.LimitReader(f,maxZip+1));if e!=nil{return e}
 rows,e:=project(b,*h);if e!=nil{return e}
 enc:=json.NewEncoder(os.Stdout);for _,r:=range rows{if e=enc.Encode(r);e!=nil{return e}}
 return nil
}
func main(){if e:=run();e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}}
