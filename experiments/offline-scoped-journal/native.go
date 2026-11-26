package journal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"strconv"
	"strings"
)

const MaxCaptureBytes = 1 << 20

// NativeQuery binds the selected pointer record and mapping rows to one retained
// capture. ModulePath and Image are an explicit external association, not a
// claim that procfs proves the file mapped in memory had these exact bytes.
type NativeQuery struct {
	ExpectedScope Scope
	Pointer EvidenceRange
	Maps EvidenceRange
	Label string
	ModulePath string
	Image ArtifactRef
}

type NativeResult struct {
	Status string
	Address U64
	FileOffset U64
	ELFVirtual U64
	MapBase U64
	MapEnd U64
	MapOffset U64
	Device string
	Inode string
}

// ResolveNativeELF64 translates a reported function-pointer address, not an
// executed PC. It accepts only pinned retained bytes, native Linux maps grammar,
// and file-backed executable ELF64 little-endian x86-64 PT_LOAD ranges.
func ResolveNativeELF64(q NativeQuery, capture, image []byte, capturePin, imagePin *ArtifactRef) (NativeResult,error) {
	refuse:=func(s string)(NativeResult,error){return NativeResult{Status:"refused"},errors.New(s)}
	if !validScope(q.ExpectedScope)||q.Pointer.Artifact.Scope!=q.ExpectedScope||q.Maps.Artifact!=q.Pointer.Artifact||!validID(q.Label)||q.ModulePath==""||strings.ContainsAny(q.ModulePath,"\r\n\x00")||len(q.ModulePath)>4096||!validArtifact(q.Image){
		return refuse("invalid scope or association")
	}
	if ValidateRange(q.Pointer)!=nil||ValidateRange(q.Maps)!=nil{return refuse("invalid capture extent")}
	if q.Pointer.Offset<q.Maps.Offset+q.Maps.Length&&q.Maps.Offset<q.Pointer.Offset+q.Pointer.Length{return refuse("overlapping capture extents")}
	if capturePin==nil||imagePin==nil{return NativeResult{Status:"unknown_no_independent_pin"},nil}
	if len(capture)>MaxCaptureBytes{return refuse("capture exceeds limit")}
	if s,e:=VerifyRetainedArtifact(bytes.NewReader(capture),q.Pointer.Artifact,capturePin);e!=nil||s!=RetainedByteMatch{return refuse("capture pin or bytes mismatch")}
	if s,e:=VerifyRetainedArtifact(bytes.NewReader(image),q.Image,imagePin);e!=nil||s!=RetainedByteMatch{return refuse("image pin or bytes mismatch")}
	p,e:=lineRange(capture,q.Pointer);if e!=nil{return refuse("pointer record boundary")}
	m,e:=lineRange(capture,q.Maps);if e!=nil{return refuse("mapping record boundary")}
	prefix:=q.Label+"=0x"
	raw:=string(p)
	if !strings.HasPrefix(raw,prefix)||strings.Count(raw,"\n")!=1{return refuse("invalid pointer record")}
	address,e:=hex64(strings.TrimSuffix(raw[len(prefix):],"\n"));if e!=nil{return refuse("invalid pointer address")}
	res:=NativeResult{Status:"unknown_mapping",Address:U64(address)}
	rows:=strings.Split(strings.TrimSuffix(string(m),"\n"),"\n")
	if len(rows)>MaxRecords{return refuse("too many map rows")}
	var prior uint64
	found:=false
	for i,row:=range rows{
		f,path:=mapFields(row)
		if len(f)!=5{return refuse("invalid proc map row")}
		interval:=strings.Split(f[0],"-")
		if len(interval)!=2{return refuse("invalid mapped interval")}
		lo,e1:=hex64(interval[0]);hi,e2:=hex64(interval[1]);off,e3:=hex64(f[2])
		dev:=strings.Split(f[3],":")
		if e1!=nil||e2!=nil||e3!=nil||lo>=hi||i>0&&lo<prior||len(dev)!=2||!validPerm(f[1]){return refuse("malformed or overlapping mappings")}
		if _,e=hex64(dev[0]);e!=nil{return refuse("invalid device")}
		if _,e=hex64(dev[1]);e!=nil{return refuse("invalid device")}
		inode,e:=strconv.ParseUint(f[4],10,64);if e!=nil{return refuse("invalid inode")}
		prior=hi
		if address<lo||address>=hi{continue}
		if found{return refuse("ambiguous address")}
		found=true
		if f[1][2]!='x'||path!=q.ModulePath||inode==0{continue}
		if address-lo>math.MaxUint64-off{return refuse("file offset overflow")}
		res.FileOffset=U64(off+address-lo);res.MapBase=U64(lo);res.MapEnd=U64(hi);res.MapOffset=U64(off);res.Device=f[3];res.Inode=f[4]
		res.Status="mapping_selected"
	}
	if res.Status!="mapping_selected"{return res,nil}
	va,ok,e:=elfExecVA(image,uint64(res.FileOffset),address)
	if e!=nil{return refuse(e.Error())}
	if !ok{res.Status="unknown_file_backing";return res,nil}
	res.ELFVirtual=U64(va);res.Status="candidate_correspondence"
	return res,nil
}

func lineRange(b []byte,r EvidenceRange)([]byte,error){
	if r.Offset>U64(len(b))||r.Length==0||r.Length>U64(len(b))-r.Offset{return nil,errors.New("range outside actual bytes")}
	lo,hi:=int(r.Offset),int(r.Offset+r.Length)
	if lo>0&&b[lo-1]!='\n'||b[hi-1]!='\n'{return nil,errors.New("not complete lines")}
	return b[lo:hi],nil
}
func hex64(s string)(uint64,error){
	if s==""||len(s)>16{return 0,errors.New("bad hex width")}
	for _,c:=range s{if !(c>='0'&&c<='9'||c>='a'&&c<='f'||c>='A'&&c<='F'){return 0,errors.New("bad hex digit")}}
	return strconv.ParseUint(s,16,64)
}
func mapFields(s string)([]string,string){
	f:=make([]string,0,5)
	for len(f)<5{
		s=strings.TrimLeft(s," \t")
		if s==""{return f,""}
		i:=strings.IndexAny(s," \t")
		if i<0{f=append(f,s);s="";break}
		f=append(f,s[:i]);s=s[i:]
	}
	return f,strings.TrimLeft(s," \t")
}
func validPerm(s string)bool{
	return len(s)==4&&(s[0]=='r'||s[0]=='-')&&(s[1]=='w'||s[1]=='-')&&(s[2]=='x'||s[2]=='-')&&(s[3]=='p'||s[3]=='s')
}
func elfExecVA(b []byte,offset,runtime uint64)(uint64,bool,error){
	bad:=func(s string)(uint64,bool,error){return 0,false,errors.New(s)}
	if len(b)<64||!bytes.Equal(b[:7],[]byte{0x7f,'E','L','F',2,1,1}){return bad("unsupported ELF identity")}
	le:=binary.LittleEndian
	typ:=le.Uint16(b[16:18])
	if (typ!=2&&typ!=3)||le.Uint16(b[18:20])!=62||le.Uint32(b[20:24])!=1||le.Uint16(b[52:54])!=64||le.Uint16(b[54:56])!=56{return bad("unsupported ELF header")}
	phoff:=le.Uint64(b[32:40]);n:=uint64(le.Uint16(b[56:58]))
	if n==0||n>256||phoff<64||phoff>uint64(len(b))||n*56>uint64(len(b))-phoff{return bad("invalid program header table")}
	var result uint64
	found:=false
	for i:=uint64(0);i<n;i++{
		p:=b[phoff+i*56:phoff+(i+1)*56]
		if le.Uint32(p[:4])!=1{continue}
		flags:=le.Uint32(p[4:8]);off:=le.Uint64(p[8:16]);va:=le.Uint64(p[16:24]);fs:=le.Uint64(p[32:40]);ms:=le.Uint64(p[40:48]);align:=le.Uint64(p[48:56])
		if fs>ms||off>uint64(len(b))||fs>uint64(len(b))-off||ms>math.MaxUint64-va||align>1&&(align&(align-1)!=0||off%align!=va%align){return bad("invalid load segment")}
		if flags&1==0||offset<off||offset-off>=fs{continue}
		if found{return bad("ambiguous executable load segment")}
		result=va+offset-off;found=true
	}
	if found&&typ==2&&result!=runtime{return bad("ET_EXEC address inconsistent")}
	return result,found,nil
}
