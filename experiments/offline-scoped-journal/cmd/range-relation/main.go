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

// Trusted immutable regular files only; no hostile filesystem race guarantee.
func openRegular(path string,limit int64)(*os.File,error){
	i,e:=os.Stat(path);if e!=nil{return nil,e};if !i.Mode().IsRegular()||i.Size()>limit{return nil,fmt.Errorf("expected bounded regular file")}
	f,e:=os.Open(path);if e!=nil{return nil,e};i,e=f.Stat();if e!=nil||!i.Mode().IsRegular()||i.Size()>limit{f.Close();return nil,fmt.Errorf("expected bounded regular file")};return f,nil
}
func bounded(path string,limit int64)([]byte,error){
	f,e:=openRegular(path,limit);if e!=nil{return nil,e};defer f.Close()
	b,e:=io.ReadAll(io.LimitReader(f,limit+1));if e!=nil{return nil,e};if int64(len(b))>limit{return nil,fmt.Errorf("input too large")};return b,nil
}
func ref(path string)(*journal.ArtifactRef,error){
	if path==""{return nil,nil}
	b,e:=bounded(path,4096);if e!=nil{return nil,e};r,e:=journal.DecodeArtifactRef(b);if e!=nil{return nil,e};return &r,nil
}
func run(args []string,out io.Writer)(int,error){
	f:=flag.NewFlagSet("range-relation",flag.ContinueOnError)
	query:=f.String("query","","strict range-relation/v1 request JSON")
	queryPin:=f.String("query-sha256","","independently retained exact request SHA-256")
	lp:=f.String("left-pin","","independently retained left ArtifactRef JSON")
	rp:=f.String("right-pin","","independently retained right ArtifactRef JSON")
	left:=f.String("left","","retained left source file")
	right:=f.String("right","","retained right source file")
	if e:=f.Parse(args);e!=nil{if e==flag.ErrHelp{return 0,nil};return 2,e}
	if *query==""||f.NArg()!=0{return 2,fmt.Errorf("query required; no positional arguments")}
	b,e:=bounded(*query,journal.MaxRelationRequestBytes);if e!=nil{return 2,e};q,e:=journal.DecodeRangeRelation(b);if e!=nil{return 2,e}
	h:=sha256.Sum256(b);digest:=hex.EncodeToString(h[:])
	emit:=func(r journal.RangeRelationResult,code int)(int,error){
		if e:=json.NewEncoder(out).Encode(struct{
			Schema string `json:"schema"`
			QuerySHA string `json:"query_sha256"`
			Result journal.RangeRelationResult `json:"result"`
		}{"range-relation-result/v1",digest,r});e!=nil{return 2,e};return code,nil
	}
	if *queryPin==""{
		return emit(journal.RangeRelationResult{Status:"unknown_no_query_pin",Content:"unknown",Occurrence:"unknown",Dependency:"unknown",EvidenceCeiling:"selected_retained_byte_relation_only",Causality:"unknown"},3)
	}
	if *queryPin!=digest{return 2,fmt.Errorf("independent query digest mismatch")}
	a,e:=ref(*lp);if e!=nil{return 2,e};z,e:=ref(*rp);if e!=nil{return 2,e}
	if a!=nil&&*a!=q.Left.Artifact||z!=nil&&*z!=q.Right.Artifact{return 2,fmt.Errorf("independent occurrence pin mismatch")}
	if a==nil||z==nil{r,e:=journal.CompareRetainedRanges(q,nil,nil,a,z);if e!=nil{return 2,e};return emit(r,3)}
	lf,e:=openRegular(*left,journal.MaxSourceBytes);if e!=nil{return 2,e};defer lf.Close()
	rf,e:=openRegular(*right,journal.MaxSourceBytes);if e!=nil{return 2,e};defer rf.Close()
	r,e:=journal.CompareRetainedRanges(q,lf,rf,a,z);if e!=nil{return 2,e}
	return emit(r,0)
}
func main(){code,e:=run(os.Args[1:],os.Stdout);if e!=nil{fmt.Fprintln(os.Stderr,e)};os.Exit(code)}
