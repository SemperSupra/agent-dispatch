package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	journal "example.invalid/offline-scoped-journal"
)

func runBatch(args []string,out io.Writer)(int,error){
	f:=flag.NewFlagSet("range-relation batch",flag.ContinueOnError)
	query:=f.String("query","","strict range-relation-batch/v1 request")
	queryPin:=f.String("query-sha256","","independently obtained exact request SHA-256")
	sources:=f.String("sources","","independent occurrence pins and trusted immutable paths")
	if e:=f.Parse(args);e!=nil{if e==flag.ErrHelp{return 0,nil};return 2,e}
	if *query==""||f.NArg()!=0{return 2,fmt.Errorf("query required; no positional arguments")}
	b,e:=bounded(*query,journal.MaxBatchRequestBytes);if e!=nil{return 2,e}
	q,e:=journal.DecodeRangeBatch(b);if e!=nil{return 2,e}
	h:=sha256.Sum256(b);digest:=hex.EncodeToString(h[:])
	emit:=func(r journal.BatchResult,code int)(int,error){
		if e:=json.NewEncoder(out).Encode(struct{
			Schema string `json:"schema"`
			QuerySHA string `json:"query_sha256"`
			Result journal.BatchResult `json:"result"`
		}{"range-relation-batch-result/v1",digest,r});e!=nil{return 2,e};return code,nil
	}
	if *queryPin==""{return emit(journal.BatchResult{Status:"unknown_no_query_pin",EvidenceCeiling:"selected_retained_byte_relation_only",Causality:"unknown"},3)}
	if *queryPin!=digest{return 2,fmt.Errorf("independent query digest mismatch")}
	var pins []journal.ArtifactRef;paths:=map[journal.ArtifactRef]string{}
	if *sources!=""{
		b,e:=bounded(*sources,journal.MaxBatchRequestBytes);if e!=nil{return 2,e}
		m,e:=journal.DecodeBatchSources(b);if e!=nil{return 2,e}
		for _,s:=range m.Sources{pins=append(pins,s.Artifact);paths[s.Artifact]=s.Path}
	}
	r,e:=journal.CompareRetainedBatch(q,pins,func(a journal.ArtifactRef)(io.ReadCloser,error){return openRegular(paths[a],journal.MaxSourceBytes)})
	if e!=nil{return 2,e}
	if r.Status!="batch_compared"{return emit(r,3)}
	return emit(r,0)
}
