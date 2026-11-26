package main

import (
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)
func fixture(t *testing.T)string{
 t.Helper()
 root:=t.TempDir()
 dir:=filepath.Join(root,"bus","usb","devices")
 dev:=filepath.Join(root,"devices","usb1","1-2")
 driver:=filepath.Join(root,"bus","usb","drivers","usb")
 for _,p:=range []string{dir,dev,driver}{if err:=os.MkdirAll(p,0700);err!=nil{t.Fatal(err)}}
 for k,v:=range map[string]string{"idVendor":"1209\n","idProduct":"0001\n","bDeviceClass":"00\n","authorized":"1\n","serial":"must-never-appear","manufacturer":"private-label"}{
  if err:=os.WriteFile(filepath.Join(dev,k),[]byte(v),0600);err!=nil{t.Fatal(err)}
 }
 if err:=os.Symlink(dev,filepath.Join(dir,"1-2"));err!=nil{t.Fatal(err)}
 if err:=os.Symlink(driver,filepath.Join(dev,"driver"));err!=nil{t.Fatal(err)}
 for _,n:=range []string{"usb1","1-2:1.0"}{if err:=os.Mkdir(filepath.Join(dir,n),0700);err!=nil{t.Fatal(err)}}
 return root
}
func TestInventoryObservedNotAuthority(t *testing.T){
 root:=fixture(t)
 v,err:=inventory(root)
 if err!=nil||v.Status!="OBSERVED"||len(v.Devices)!=1{t.Fatalf("inventory %+v %v",v,err)}
 d:=v.Devices[0]
 if d.BusID!="1-2"||d.Vendor!="1209"||d.Product!="0001"||d.Class!="00"||d.Driver!="usb"||d.Authorized!="1"{t.Fatalf("wrong observation %+v",d)}
 b,err:=json.Marshal(v)
 if err!=nil||strings.Contains(string(b),"must-never-appear")||strings.Contains(string(b),"private-label"){t.Fatalf("unneeded descriptor disclosure: %v",err)}
 if v.Authority!="READ_ONLY_NOT_ENROLLED_NOT_A_GRANT"{t.Fatal("authority overclaim")}
}
func TestForeignAndMissingFailClosed(t *testing.T){
 root:=fixture(t)
 dir:=filepath.Join(root,"bus","usb","devices")
 if err:=os.Symlink(t.TempDir(),filepath.Join(dir,"1-3"));err!=nil{t.Fatal(err)}
 if err:=os.Remove(filepath.Join(root,"devices","usb1","1-2","idVendor"));err!=nil{t.Fatal(err)}
 v,err:=inventory(root)
 if err!=nil||v.Status!="PARTIAL"||len(v.Devices)!=2||v.Devices[0].Vendor!=""||v.Devices[1].Observation!="UNKNOWN_FOREIGN_OR_DISAPPEARED"{t.Fatalf("wrong negative: %+v %v",v,err)}
 if _,err=inventory(filepath.Join(root,"absent"));err==nil{t.Fatal("missing sysfs admitted")}
}
func TestAttributeSymlinkRejected(t *testing.T){
 root:=fixture(t)
 dir:=filepath.Join(root,"devices","usb1","1-2")
 if err:=os.Remove(filepath.Join(dir,"idProduct"));err!=nil{t.Fatal(err)}
 if err:=os.Symlink(filepath.Join(dir,"idVendor"),filepath.Join(dir,"idProduct"));err!=nil{t.Fatal(err)}
 v,err:=inventory(root)
 if err!=nil||v.Status!="PARTIAL"||v.Devices[0].Product!=""{t.Fatalf("symlink attribute accepted: %+v %v",v,err)}
}
