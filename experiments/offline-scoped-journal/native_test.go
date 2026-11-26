package journal

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func nativeRef(scope Scope,occ string,b []byte)ArtifactRef{
	return ArtifactRef{scope,occ,fmt.Sprintf("%x",sha256.Sum256(b)),U64(len(b))}
}
func nativeFixtureQuery(data,img []byte,path string)NativeQuery{
	scope:=Scope{"run","root","process","native"}
	c:=nativeRef(scope,"capture",data)
	i:=nativeRef(Scope{"run","root","file","build"},"image",img)
	n:=strings.IndexByte(string(data),'\n')+1
	return NativeQuery{ExpectedScope:scope,Pointer:EvidenceRange{c,0,U64(n)},Maps:EvidenceRange{c,U64(n),U64(len(data)-n)},Label:"p",ModulePath:path,Image:i}
}

func TestNativeELF(t *testing.T){
	if os.Getenv("NATIVE_ELF_TEST")!="1"{t.Skip("explicit native fixture opt-in")}
	d:=t.TempDir()
	src:=filepath.Join(d,"probe.c")
	if e:=os.WriteFile(src,[]byte("#include <stdio.h>\n#include <stdint.h>\n__attribute__((noinline,used)) int observed(int x){return x+7;}\nint main(void){printf(\"p=0x%jx\\n\",(uintmax_t)(uintptr_t)observed);FILE*f=fopen(\"/proc/self/maps\",\"r\");if(!f)return 2;char b[4096];while(fgets(b,sizeof(b),f))fputs(b,stdout);return fclose(f);}\n"),0600);e!=nil{t.Fatal(e)}
	for _,pie:=range []bool{true,false}{
		path:=filepath.Join(d,fmt.Sprintf("probe-%t",pie));flags:=[]string{"-O0","-g"}
		if pie{flags=append(flags,"-fPIE","-pie")}else{flags=append(flags,"-fno-pie","-no-pie")}
		flags=append(flags,"-o",path,src)
		if o,e:=exec.Command("cc",flags...).CombinedOutput();e!=nil{t.Fatal(e,string(o))}
		img,e:=os.ReadFile(path);if e!=nil{t.Fatal(e)}
		nm,e:=exec.Command("nm","-n",path).Output();if e!=nil{t.Fatal(e)}
		var want uint64
		for _,l:=range strings.Split(string(nm),"\n"){f:=strings.Fields(l);if len(f)==3&&f[2]=="observed"{want,e=strconv.ParseUint(f[0],16,64);if e!=nil{t.Fatal(e)}}}
		if want==0{t.Fatal("missing symbol oracle")}
		for rep:=0;rep<3;rep++{
			data,e:=exec.Command(path).Output();if e!=nil{t.Fatal(e)}
			q:=nativeFixtureQuery(data,img,path);cp,ip:=q.Pointer.Artifact,q.Image
			r,e:=ResolveNativeELF64(q,data,img,&cp,&ip)
			if e!=nil||r.Status!="candidate_correspondence"||uint64(r.ELFVirtual)!=want{t.Fatal(pie,rep,r,e)}
			t.Logf("native pie=%t rep=%d virtual=%#x address=%#x",pie,rep,r.ELFVirtual,r.Address)
			if r,e=ResolveNativeELF64(q,data,img,nil,&ip);e!=nil||r.Status!="unknown_no_independent_pin"{t.Fatal(r,e)}
			if r,e=ResolveNativeELF64(q,data,img,&cp,nil);e!=nil||r.Status!="unknown_no_independent_pin"{t.Fatal(r,e)}
			other:=q;other.ExpectedScope.Branch="sibling";if _,e=ResolveNativeELF64(other,data,img,&cp,&ip);e==nil{t.Fatal("wrong scope")}
			other=q;other.ModulePath+=".other";if r,e=ResolveNativeELF64(other,data,img,&cp,&ip);e!=nil||r.Status!="unknown_mapping"{t.Fatal(r,e)}
			other=q;other.Pointer.Offset++;other.Pointer.Length--;if _,e=ResolveNativeELF64(other,data,img,&cp,&ip);e==nil{t.Fatal("partial line")}
			bad:=append([]byte(nil),data...);bad[0]^=1;if _,e=ResolveNativeELF64(q,bad,img,&cp,&ip);e==nil{t.Fatal("capture tamper")}
			bad=append([]byte(nil),img...);bad[0]^=1;if _,e=ResolveNativeELF64(q,data,bad,&cp,&ip);e==nil{t.Fatal("image tamper")}
			other=q;other.Maps.Artifact.Occurrence="other";if _,e=ResolveNativeELF64(other,data,img,&cp,&ip);e==nil{t.Fatal("foreign map occurrence")}
		}
	}
}
