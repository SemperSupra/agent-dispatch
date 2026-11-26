// USB Edge inventory is read-only. It is not an exporter or grant authority.
package main

import (
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "runtime"
 "strings"
)

var busID=regexp.MustCompile("^[0-9]+-[0-9]+([.][0-9]+)*$")
var hex4=regexp.MustCompile("^[0-9a-fA-F]{4}$")
var hex2=regexp.MustCompile("^[0-9a-fA-F]{2}$")
var driverName=regexp.MustCompile("^[A-Za-z0-9_.-]{1,96}$")

type Device struct{
 BusID string `json:"observed_busid"`
 Vendor string `json:"vendor_id,omitempty"`
 Product string `json:"product_id,omitempty"`
 Class string `json:"device_class,omitempty"`
 Driver string `json:"device_driver,omitempty"`
 Authorized string `json:"authorized,omitempty"`
 Observation string `json:"observation"`
}
type Inventory struct{
 Schema string `json:"schema"`
 Architecture string `json:"architecture"`
 Status string `json:"status"`
 Authority string `json:"authority"`
 Devices []Device `json:"devices"`
}
func contained(root,path string) bool{
 rel,err:=filepath.Rel(root,path)
 return err==nil && rel!=".." && !strings.HasPrefix(rel,".."+string(os.PathSeparator))
}
func attr(dir,name string) string{
 p:=filepath.Join(dir,name)
 i,err:=os.Lstat(p)
 if err!=nil||!i.Mode().IsRegular(){return ""}
 f,err:=os.Open(p)
 if err!=nil{return ""}
 defer f.Close()
 b,err:=io.ReadAll(io.LimitReader(f,257))
 if err!=nil||len(b)>256{return ""}
 return strings.TrimSpace(string(b))
}
func inventory(root string)(Inventory,error){
 out:=Inventory{Schema:"usb-edge/inventory/v1",Architecture:runtime.GOARCH,Status:"OBSERVED",Authority:"READ_ONLY_NOT_ENROLLED_NOT_A_GRANT",Devices:[]Device{}}
 if !filepath.IsAbs(root)||filepath.Clean(root)!=root{return out,errors.New("sysfs root must be canonical absolute path")}
 canonical,err:=filepath.EvalSymlinks(root)
 if err!=nil{return out,err}
 dir,err:=filepath.EvalSymlinks(filepath.Join(canonical,"bus","usb","devices"))
 if err!=nil||!contained(canonical,dir){return out,errors.New("USB sysfs directory unavailable or foreign")}
 entries,err:=os.ReadDir(dir)
 if err!=nil{return out,err}
 if len(entries)>2048{return out,errors.New("USB inventory entry budget exceeded")}
 for _,e:=range entries{
  id:=e.Name()
  if len(id)>64||!busID.MatchString(id){continue}
  d:=Device{BusID:id,Observation:"OBSERVED_NOT_ENROLLED"}
  target,err:=filepath.EvalSymlinks(filepath.Join(dir,id))
  if err!=nil||!contained(canonical,target){
   d.Observation="UNKNOWN_FOREIGN_OR_DISAPPEARED"
   out.Status="PARTIAL"
   out.Devices=append(out.Devices,d)
   continue
  }
  vid,pid,cls:=attr(target,"idVendor"),attr(target,"idProduct"),attr(target,"bDeviceClass")
  if hex4.MatchString(vid){d.Vendor=strings.ToLower(vid)}
  if hex4.MatchString(pid){d.Product=strings.ToLower(pid)}
  if hex2.MatchString(cls){d.Class=strings.ToLower(cls)}
  a:=attr(target,"authorized")
  if a=="0"||a=="1"{d.Authorized=a}
  if p,e:=filepath.EvalSymlinks(filepath.Join(target,"driver"));e==nil&&contained(canonical,p)&&driverName.MatchString(filepath.Base(p)){d.Driver=filepath.Base(p)}
  if d.Vendor==""||d.Product==""||d.Class==""||d.Authorized==""{d.Observation="PARTIAL_NOT_ENROLLED";out.Status="PARTIAL"}
  out.Devices=append(out.Devices,d)
 }
 return out,nil
}
func main(){
 root:=flag.String("sysfs-root","/sys","trusted Linux sysfs mount (fixture override)")
 flag.Parse()
 if flag.NArg()!=0{fmt.Fprintln(os.Stderr,"unexpected arguments");os.Exit(2)}
 v,err:=inventory(*root)
 if err!=nil{fmt.Fprintln(os.Stderr,"USB inventory unavailable:",err);os.Exit(1)}
 e:=json.NewEncoder(os.Stdout);e.SetIndent("","  ")
 if err=e.Encode(v);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
}
