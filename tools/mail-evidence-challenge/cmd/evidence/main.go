package main

import (
    "encoding/json"
    "fmt"
    "os"
    evidence "sempersupra/mail-evidence-challenge"
)

func main() {
    result,err:=evidence.Evaluate("testdata/gold.json")
    if err!=nil {
        fmt.Fprintln(os.Stderr,"MAIL_EVIDENCE_CHALLENGE_FAILED:",err)
        os.Exit(2)
    }
    raw,err:=json.Marshal(result);if err!=nil{os.Exit(2)}
    fmt.Println(string(raw))
}
