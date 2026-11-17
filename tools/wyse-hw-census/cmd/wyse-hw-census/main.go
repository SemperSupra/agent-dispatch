// wyse-hw-census reads non-sensitive Linux capability information only.
// Run on each physical device locally after owner-approved read-only G0 access.
// Raw device identity binding occurs separately in the private fleet registry.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	census "example.com/wyse-hw-census"
)

func main() {
	root:=flag.String("root","/","read-only sysfs/proc root; test fixtures use an isolated path")
 preflight:=flag.Bool("preflight",false,"emit coarse MVP1 canary HOLD preflight only; never authorizes deployment")
	flag.Parse()
	if flag.NArg()!=0 {
		fmt.Fprintln(os.Stderr,"R43_CENSUS_UNEXPECTED_ARGUMENT=FAIL_CLOSED")
		os.Exit(2)
	}
	s,err:=census.Collect(*root)
	if err!=nil {
		fmt.Fprintln(os.Stderr,"R43_CENSUS_INCOMPLETE=FAIL_CLOSED:",err)
		os.Exit(2)
	}
	var record any=s
 if *preflight {record=census.Preflight(s)}
 out,err:=json.MarshalIndent(record,"","  ")
	if err!=nil{fmt.Fprintln(os.Stderr,"R43_CENSUS_SERIALIZATION=RED");os.Exit(2)}
	fmt.Println(string(out))
}
