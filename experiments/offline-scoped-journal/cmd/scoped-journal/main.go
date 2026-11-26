package main
import("crypto/sha256";"encoding/hex";"encoding/json";"flag";"fmt";"io";"os";journal "example.invalid/offline-scoped-journal")
func run(args []string,out io.Writer)error{
 f:=flag.NewFlagSet("scoped-journal",flag.ContinueOnError)
 path:=f.String("journal","","bounded journal JSON file");at:=f.String("at","","observation coordinate (decimal or 0xhex)");addr:=f.String("address","","address (decimal or 0xhex)")
 if e:=f.Parse(args);e!=nil{return e};if *path==""||f.NArg()!=0{return fmt.Errorf("journal file required; no positional arguments")}
 a,e:=journal.ParseCoordinate(*at);if e!=nil{return e};x,e:=journal.ParseCoordinate(*addr);if e!=nil{return e}
 r,e:=os.Open(*path);if e!=nil{return e};defer r.Close()
 b,e:=io.ReadAll(io.LimitReader(r,journal.MaxBytes+1));if e!=nil{return e};w,e:=journal.Decode(b);if e!=nil{return e};j,e:=journal.Build(w);if e!=nil{return e}
 h:=sha256.Sum256(b)
 return json.NewEncoder(out).Encode(struct{InputSHA string `json:"input_sha256"`;Result journal.Result `json:"result"`}{hex.EncodeToString(h[:]),j.Resolve(w.Scope,a,x)})
}
func main(){if e:=run(os.Args[1:],os.Stdout);e!=nil{if e==flag.ErrHelp{return};fmt.Fprintln(os.Stderr,e);os.Exit(2)}}
