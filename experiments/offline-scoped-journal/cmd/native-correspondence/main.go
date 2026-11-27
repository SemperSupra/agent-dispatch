// native-correspondence resolves a pinned retained question without target access.
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

type Location struct{
	Address journal.U64 `json:"address"`
	FileOffset journal.U64 `json:"file_offset"`
	ELFVirtual journal.U64 `json:"elf_virtual"`
	MapBase journal.U64 `json:"map_base"`
	MapEnd journal.U64 `json:"map_end"`
	MapOffset journal.U64 `json:"map_offset"`
	Device string `json:"device"`
	Inode string `json:"inode"`
}
type Result struct{
	Schema string `json:"schema"`
	Status string `json:"status"`
	QuerySHA string `json:"query_sha256"`
	SelectionIntegrity string `json:"selection_integrity"`
	ArtifactIntegrity string `json:"artifact_integrity"`
	EvidenceCeiling string `json:"evidence_ceiling"`
	Association string `json:"association"`
	Coverage string `json:"coverage"`
	ExpectationCheck string `json:"expectation_check"`
	Location *Location `json:"location,omitempty"`
}

// Only trusted immutable regular-file paths are supported, not hostile filesystems.
func readRegular(path string,capBytes int64)([]byte,error){
	info,e:=os.Stat(path);if e!=nil{return nil,e}
	if !info.Mode().IsRegular()||info.Size()>capBytes{return nil,fmt.Errorf("expected bounded regular file")}
	f,e:=os.Open(path);if e!=nil{return nil,e};defer f.Close()
	info,e=f.Stat();if e!=nil||!info.Mode().IsRegular()||info.Size()>capBytes{return nil,fmt.Errorf("expected bounded regular file")}
	b,e:=io.ReadAll(io.LimitReader(f,capBytes+1));if e!=nil{return nil,e}
	if int64(len(b))>capBytes{return nil,fmt.Errorf("file exceeds limit")}
	return b,nil
}
func readRef(path string)(*journal.ArtifactRef,error){
	if path==""{return nil,nil}
	b,e:=readRegular(path,4096);if e!=nil{return nil,e}
	r,e:=journal.DecodeArtifactRef(b);if e!=nil{return nil,e};return &r,nil
}

func run(args []string,out io.Writer)(int,error){
	f:=flag.NewFlagSet("native-correspondence",flag.ContinueOnError)
	query:=f.String("query","","native-correspondence/v1 JSON request")
	queryPin:=f.String("query-sha256","","independently obtained exact request SHA-256")
	capPin:=f.String("capture-pin","","independently obtained capture reference JSON")
	imgPin:=f.String("image-pin","","independently obtained image reference JSON")
	capPath:=f.String("capture","","immutable retained capture")
	imgPath:=f.String("image","","immutable candidate ELF image")
	address:=f.String("expect-address","","optional independently supplied expected address")
	va:=f.String("expect-elf-virtual","","optional independently supplied expected ELF virtual address")
	base:=f.String("expect-map-base","","optional expected map base (requires end)")
	end:=f.String("expect-map-end","","optional expected exclusive map end (requires base)")
	if e:=f.Parse(args);e!=nil{if e==flag.ErrHelp{return 0,nil};return 2,e}
	if *query==""||f.NArg()!=0{return 2,fmt.Errorf("query required; no positional arguments")}
	if (*base=="")!=(*end==""){return 2,fmt.Errorf("expected map range must be complete")}
	expect:=map[string]journal.U64{}
	for k,s:=range map[string]string{"address":*address,"elf_virtual":*va,"map_base":*base,"map_end":*end}{
		if s!=""{n,e:=journal.ParseCoordinate(s);if e!=nil{return 2,e};expect[k]=n}
	}
	if *base!=""&&expect["map_base"]>=expect["map_end"]{return 2,fmt.Errorf("invalid expected range")}
	raw,e:=readRegular(*query,journal.MaxNativeRequestBytes);if e!=nil{return 2,e}
	req,e:=journal.DecodeNativeRequest(raw);if e!=nil{return 2,e}
	h:=sha256.Sum256(raw);digest:=hex.EncodeToString(h[:])
	r:=Result{Schema:"native-correspondence-result/v1",QuerySHA:digest,SelectionIntegrity:"unverified",ArtifactIntegrity:"not_checked",EvidenceCeiling:"reported_pointer_candidate_only",Association:"caller_asserted_path_image",Coverage:"selected_map_lines_only",ExpectationCheck:"not_requested"}
	if len(expect)>0{r.ExpectationCheck="unresolved"}
	emit:=func(status string,code int)(int,error){r.Status=status;if e:=json.NewEncoder(out).Encode(r);e!=nil{return 2,e};return code,nil}
	if *queryPin==""{return emit("unknown_no_query_pin",3)}
	if *queryPin!=digest{return 2,fmt.Errorf("independent query digest mismatch")}
	r.SelectionIntegrity="query_digest_matched"
	cp,e:=readRef(*capPin);if e!=nil{return 2,e}
	ip,e:=readRef(*imgPin);if e!=nil{return 2,e}
	if cp!=nil&&*cp!=req.Pointer.Artifact||ip!=nil&&*ip!=req.Image{return 2,fmt.Errorf("independent artifact pin mismatch")}
	if cp==nil||ip==nil{return emit("unknown_no_independent_pin",3)}
	if *capPath==""||*imgPath==""{return 2,fmt.Errorf("capture and image required with both pins")}
	if cp.Size>journal.MaxCaptureBytes||ip.Size>journal.MaxSourceBytes{return 2,fmt.Errorf("pinned artifact exceeds limit")}
	capture,e:=readRegular(*capPath,journal.MaxCaptureBytes);if e!=nil{return 2,e}
	image,e:=readRegular(*imgPath,journal.MaxSourceBytes);if e!=nil{return 2,e}
	got,e:=journal.ResolveNativeELF64(req.Query(),capture,image,cp,ip);if e!=nil{return 2,e}
	r.ArtifactIntegrity="retained_byte_match"
	if got.Status!="candidate_correspondence"{return emit(got.Status,3)}
	values:=map[string]journal.U64{"address":got.Address,"elf_virtual":got.ELFVirtual,"map_base":got.MapBase,"map_end":got.MapEnd}
	for k,v:=range expect{if values[k]!=v{return 2,fmt.Errorf("expected coordinate mismatch: %s",k)}}
	if len(expect)>0{r.ExpectationCheck="supplied_coordinates_match"}
	r.Location=&Location{got.Address,got.FileOffset,got.ELFVirtual,got.MapBase,got.MapEnd,got.MapOffset,got.Device,got.Inode}
	return emit(got.Status,0)
}

func main(){code,e:=run(os.Args[1:],os.Stdout);if e!=nil{fmt.Fprintln(os.Stderr,e)};os.Exit(code)}
