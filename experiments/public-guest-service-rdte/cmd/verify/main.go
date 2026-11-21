// verify is an independent public-safe guest install receipt adjudicator.
package main
import (
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "strings"
 "public-guest-service-rdte/internal/proof"
)
func run(args []string)error{
 if len(args)!=3{return errors.New("usage: verify RECEIPT_JSON RUN_ID SOURCE_SHA")}
 f,e:=os.Open(args[0]);if e!=nil{return e};defer f.Close()
 b,e:=io.ReadAll(io.LimitReader(f,65537));if e!=nil{return e}
 if len(b)>65536{return errors.New("oversized receipt")}
 d:=json.NewDecoder(strings.NewReader(string(b)));d.DisallowUnknownFields()
 var r proof.Receipt
 if e=d.Decode(&r);e!=nil{return e}
 if _,e=d.Token();e!=io.EOF{return errors.New("trailing receipt data")}
 return proof.VerifyReceipt(r,args[1],args[2])
}
func main(){if err:=run(os.Args[1:]);err!=nil{fmt.Fprintln(os.Stderr,"PUBLIC_GUEST_SERVICE_RDTE_NOT_ACCEPTED:",err);os.Exit(1)};fmt.Println("PUBLIC_BOOTED_WINDOWS_GUEST_SERVICE_LIFECYCLE_AND_CLEANUP_ACCEPTED; PRIVATE_PRODUCT_NOT_INSTALLED")}
