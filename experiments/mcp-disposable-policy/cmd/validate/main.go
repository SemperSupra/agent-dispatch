package main

import (
 "encoding/json"
 "fmt"
 "os"
 policy "example.invalid/m1-deployment-policy-rdte"
)

func main() {
 if len(os.Args)!=2 {fmt.Fprintln(os.Stderr,"usage: validate <manifest.json>");os.Exit(2)}
 b,e:=os.ReadFile(os.Args[1]);if e!=nil {fmt.Fprintln(os.Stderr,e);os.Exit(2)}
 m,e:=policy.Parse(b);if e!=nil {fmt.Fprintln(os.Stderr,e);os.Exit(2)}
 r:=policy.Evaluate(m)
 _=json.NewEncoder(os.Stdout).Encode(r)
 if !r.Accepted {os.Exit(1)}
}
