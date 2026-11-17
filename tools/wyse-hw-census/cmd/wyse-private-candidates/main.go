// Command wyse-private-candidates is an explicitly owner-run, read-only
// device census. It NEVER sends inventory to a remote user or stdout.
// The only output is one new root-owned private JSON on verified /run tmpfs.
package main
import (
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "syscall"

 census "example.com/wyse-hw-census"
)
const privateDir="/run/wyse/private"
const tmpfsMagic=0x01021994
func abort(reason string){
 fmt.Fprintln(os.Stderr,"R45_PRIVATE_CENSUS=DENIED:"+reason)
 os.Exit(2)
}
func safeRootPrivateDirectory(path string)bool{
 st,e:=os.Lstat(path)
 if e!=nil||!st.IsDir()||st.Mode()&os.ModeSymlink!=0||st.Mode().Perm()!=0700{return false}
 sys,ok:=st.Sys().(*syscall.Stat_t)
 return ok&&sys.Uid==0
}
func main(){
 if os.Geteuid()!=0||len(os.Args)!=1 {abort("OWNER_LOCAL_ROOT_ONLY_NO_ARGUMENTS")}
 fs:=&syscall.Statfs_t{}
 if e:=syscall.Statfs("/run",fs);e!=nil||fs.Type!=tmpfsMagic{abort("RUN_MUST_BE_TMPFS")}
 if !safeRootPrivateDirectory("/run/wyse")||!safeRootPrivateDirectory(privateDir) {
  abort("PREPROVISIONED_0700_ROOT_ONLY_PATH_REQUIRED")
 }
 v,e:=census.CollectHostCandidates("/")
 if e!=nil{abort("G0_INCOMPLETE")}
 data,e:=json.MarshalIndent(v,"","  ")
 if e!=nil{abort("REPORT_ENCODE")}
 // The path is a root-owned fixed directory; a generation-specific filename
 // and O_EXCL deny overwriting/replaying any earlier operator receipt.
 name:="candidates-"+v.Generation[:20]+".json"
 target:=filepath.Join(privateDir,name)
 f,e:=os.OpenFile(target,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if e!=nil{abort("PRIVATE_REPORT_EXISTS_OR_PATH_UNSAFE")}
 if n,e:=f.Write(append(data,'\n'));e!=nil||n!=len(data)+1 {
  _=f.Close();_=os.Remove(target);abort("INCOMPLETE_PRIVATE_WRITE")
 }
 if e:=f.Sync();e!=nil{_=f.Close();_=os.Remove(target);abort("PRIVATE_SYNC")}
 if e:=f.Close();e!=nil{_=os.Remove(target);abort("PRIVATE_CLOSE")}
 // No IDs, count, GPU or device capability appears on stdout.
 fmt.Println("R45_PRIVATE_CENSUS_WRITTEN_LOCAL_TMPFS_ONLY=PASS")
 fmt.Println("R45_PASSTHROUGH_ELIGIBILITY=NOT_TESTED")
}
