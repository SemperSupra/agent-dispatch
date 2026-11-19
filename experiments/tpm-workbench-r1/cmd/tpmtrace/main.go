// tpmtrace converts annotated TPM2 wire frames to redacted JSON lines.
// It does not attach to a VM or claim to identify a guest process.
// Input: "request HEX" or "response HEX", one line per wire event.
package main

import (
 "bufio"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "os"
 "strings"
 "time"
 trace "example.org/tpm-workbench-r1"
)
func run()error{
 var c trace.Correlator
 scan:=bufio.NewScanner(os.Stdin);scan.Buffer(make([]byte,1024),2<<20)
 enc:=json.NewEncoder(os.Stdout)
 for line:=1;scan.Scan();line++{
  txt:=strings.TrimSpace(scan.Text());if txt==""||strings.HasPrefix(txt,"#"){continue}
  parts:=strings.Fields(txt)
  if len(parts)!=2{return fmt.Errorf("line %d: require DIRECTION HEX",line)}
  b,err:=hex.DecodeString(parts[1]);if err!=nil{return fmt.Errorf("line %d: invalid hex: %w",line,err)}
  event,err:=c.Observe(parts[0],b,time.Now());if err!=nil{return fmt.Errorf("line %d: %w",line,err)}
  if err=enc.Encode(event);err!=nil{return err}
 }
 if err:=scan.Err();err!=nil{return err}
 if c.Pending(){return fmt.Errorf("unmatched TPM request at end of input")}
 return nil
}
func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,"TPM_TRACE_RED:",err);os.Exit(2)}}
