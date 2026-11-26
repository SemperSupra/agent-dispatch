// artifact-verify checks an already-retained artifact against a separate pin.
// It never reads a source without an independent pin and valid reference.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	journal "example.invalid/offline-scoped-journal"
)

func openRegular(path string)(*os.File,error){
	info,err:=os.Stat(path)
	if err!=nil{return nil,err}
	if !info.Mode().IsRegular(){return nil,fmt.Errorf("expected regular file")}
	f,err:=os.Open(path)
	if err!=nil{return nil,err}
	info,err=f.Stat()
	if err!=nil||!info.Mode().IsRegular(){f.Close();return nil,fmt.Errorf("expected regular file")}
	return f,nil
}

func ref(path string)(journal.ArtifactRef,error){
	f,err:=openRegular(path)
	if err!=nil{return journal.ArtifactRef{},err}
	defer f.Close()
	b,err:=io.ReadAll(io.LimitReader(f,4097))
	if err!=nil{return journal.ArtifactRef{},err}
	return journal.DecodeArtifactRef(b)
}

func run(args []string,out io.Writer)(int,error){
	flags:=flag.NewFlagSet("artifact-verify",flag.ContinueOnError)
	claimPath:=flags.String("claim","","artifact reference JSON")
	pinPath:=flags.String("pin","","independently retained reference JSON")
	source:=flags.String("source","","immutable artifact file (required when pin is supplied)")
	if err:=flags.Parse(args);err!=nil{if err==flag.ErrHelp{return 0,nil};return 2,err}
	if *claimPath==""||flags.NArg()!=0{return 2,fmt.Errorf("claim required; no positional arguments")}
	claim,err:=ref(*claimPath)
	if err!=nil{return 2,err}
	emit:=func(status journal.BindingStatus)error{
		return json.NewEncoder(out).Encode(struct{
			Status journal.BindingStatus `json:"status"`
			Artifact journal.ArtifactRef `json:"artifact"`
		}{status,claim})
	}
	if *pinPath==""{if err=emit(journal.NoIndependentPin);err!=nil{return 2,err};return 3,nil}
	pin,err:=ref(*pinPath)
	if err!=nil{return 2,err}
	if claim!=pin{return 2,fmt.Errorf("independent occurrence pin mismatch")}
	if *source==""{return 2,fmt.Errorf("source required with pin")}
	if claim.Size>journal.MaxSourceBytes{return 2,fmt.Errorf("artifact exceeds verification limit")}
	f,err:=openRegular(*source)
	if err!=nil{return 2,err}
	defer f.Close()
	status,err:=journal.VerifyRetainedArtifact(f,claim,&pin)
	if err!=nil{return 2,err}
	if err=emit(status);err!=nil{return 2,err}
	return 0,nil
}

func main(){code,err:=run(os.Args[1:],os.Stdout);if err!=nil{fmt.Fprintln(os.Stderr,err)};os.Exit(code)}
