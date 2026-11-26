package main

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "os"

 journal "example.invalid/offline-scoped-journal"
)

func openRegular(path string) (*os.File,error) {
 info,e:=os.Stat(path)
 if e!=nil{return nil,e}
 if !info.Mode().IsRegular(){return nil,fmt.Errorf("expected regular file")}
 f,e:=os.Open(path)
 if e!=nil{return nil,e}
 info,e=f.Stat()
 if e!=nil||!info.Mode().IsRegular(){f.Close();return nil,fmt.Errorf("expected regular file")}
 return f,nil
}

func run(args []string,out io.Writer)error{
 f:=flag.NewFlagSet("scoped-journal",flag.ContinueOnError)
 path:=f.String("journal","","bounded journal JSON file")
 at:=f.String("at","","observation coordinate (decimal or 0xhex)")
 addr:=f.String("address","","address (decimal or 0xhex)")
 source:=f.String("source","","optional immutable source artifact, max 64 MiB")
 runID:=f.String("expect-run","","expected run (all four scope flags required together)")
 branch:=f.String("expect-branch","","expected execution branch")
 space:=f.String("expect-space","","expected address space")
 producer:=f.String("expect-producer","","expected producer")
 if e:=f.Parse(args);e!=nil{return e}
 if *path==""||f.NArg()!=0{return fmt.Errorf("journal file required; no positional arguments")}
 a,e:=journal.ParseCoordinate(*at);if e!=nil{return e}
 x,e:=journal.ParseCoordinate(*addr);if e!=nil{return e}
 r,e:=openRegular(*path);if e!=nil{return e};defer r.Close()
 b,e:=io.ReadAll(io.LimitReader(r,journal.MaxBytes+1));if e!=nil{return e}
 w,e:=journal.Decode(b);if e!=nil{return e}
 j,e:=journal.Build(w);if e!=nil{return e}
 expected:=journal.Scope{Run:*runID,Branch:*branch,Space:*space,Producer:*producer}
 if expected!=(journal.Scope{})&&expected!=w.Scope{return fmt.Errorf("expected complete matching scope")}
 integrity:="declared_only"
 var sourceSize *journal.U64
 if *source!=""{
  sf,e:=openRegular(*source);if e!=nil{return e};defer sf.Close()
  size,e:=journal.VerifyArtifact(sf,w.SourceSHA);if e!=nil{return e}
  integrity="digest_matched";sourceSize=&size
 }
 h:=sha256.Sum256(b)
 return json.NewEncoder(out).Encode(struct{
  InputSHA string `json:"input_sha256"`
  SourceIntegrity string `json:"source_integrity"`
  SourceSize *journal.U64 `json:"source_size,omitempty"`
  Result journal.Result `json:"result"`
 }{hex.EncodeToString(h[:]),integrity,sourceSize,j.Resolve(w.Scope,a,x)})
}
func main(){if e:=run(os.Args[1:],os.Stdout);e!=nil{if e==flag.ErrHelp{return};fmt.Fprintln(os.Stderr,e);os.Exit(2)}}
