// Command mail-annotation-benchmark exports context or grades normalized
// source annotations. It performs no inference or reviewer admission.
package main
import(
	"encoding/json"
	"fmt"
	"io"
	"os"
	bench "sempersupra/mail-evidence-challenge/annotation_benchmark"
)
func main(){
	if len(os.Args)!=2{fmt.Fprintln(os.Stderr,"usage: mail-annotation-benchmark contexts|reference|score|score-raw");os.Exit(2)}
	var v any;var err error
	switch os.Args[1]{
	case "contexts":v,err=bench.Contexts()
	case "reference":v,err=bench.Reference()
	case "score","score-raw":
		var b []byte;b,err=io.ReadAll(io.LimitReader(os.Stdin,bench.MaxInput+1))
		if err==nil{if os.Args[1]=="score-raw"{v,err=bench.ScoreRawJSON(b)}else{v,err=bench.ScoreJSON(b)}}
	default:fmt.Fprintln(os.Stderr,"unknown mode");os.Exit(2)
	}
	if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(2)}
	if err=json.NewEncoder(os.Stdout).Encode(v);err!=nil{os.Exit(2)}
}
