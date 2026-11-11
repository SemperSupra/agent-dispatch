package main
import (
 "encoding/json"
 "fmt"
 "os"
 gitops "example.invalid/mcp-gitops-qualification"
)
func main(){
 if len(os.Args)!=2{fmt.Fprintln(os.Stderr,"usage: validate <saved-belt-bundle.json>");os.Exit(2)}
 data,e:=os.ReadFile(os.Args[1]);if e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}
 snap,e:=gitops.Load(data);if e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}
 result:=struct{SnapshotDigest string `json:"snapshotDigest"`; BeltCount int `json:"beltCount"`; CatalogCount int `json:"catalogCount"`}{snap.Digest,len(snap.Manifest.Belts),len(snap.Manifest.Catalog)}
 e=json.NewEncoder(os.Stdout).Encode(result);if e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}
}
