// Command mail-benchmark exports synthetic model-facing contexts or an
// independently scored typed reference report. It never runs a model.
package main
import (
	"encoding/json"
	"fmt"
	"os"
	"sempersupra/mail-evidence-challenge/benchmark"
)
func main(){
	if len(os.Args)!=2{fmt.Fprintln(os.Stderr,"usage: mail-benchmark contexts|reference");os.Exit(2)}
	var result any;var err error
	switch os.Args[1]{
	case "contexts":result,err=benchmark.Contexts(19)
	case "reference":result,err=benchmark.Reference(19)
	default:fmt.Fprintln(os.Stderr,"unknown mode");os.Exit(2)
	}
	if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(2)}
	if err=json.NewEncoder(os.Stdout).Encode(result);err!=nil{os.Exit(2)}
}
