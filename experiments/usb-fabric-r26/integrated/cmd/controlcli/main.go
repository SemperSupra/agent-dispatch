// r26ctl is a minimal deterministic host-local controller CLI for humans,
// automation and agents. It never receives a raw QMP or guest receipt socket.
// Linux SO_PEERCRED at the server is the only opt-in synthetic authorization
// gate; the client-provided actor label is never a security credential.
package main

import (
 "bufio"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "net"
 "os"
 "strings"
 "time"
)
type request struct {
 Op string `json:"op"`
 Actor string `json:"actor,omitempty"`
 Epoch string `json:"epoch,omitempty"`
 Generation uint64 `json:"generation,omitempty"`
 Command string `json:"command,omitempty"`
}
type reply struct {
 OK bool `json:"ok"`
 Error string `json:"error,omitempty"`
 Epoch string `json:"epoch,omitempty"`
 Generation uint64 `json:"generation,omitempty"`
}
func execute(socket string,commands []string)error{
 if socket==""{return errors.New("socket path required")}
 conn,err:=net.DialTimeout("unix",socket,4*time.Second)
 if err!=nil{return fmt.Errorf("controller unavailable: %w",err)}
 defer conn.Close()
 encoder:=json.NewEncoder(conn)
 decoder:=json.NewDecoder(bufio.NewReader(conn))
 leaseEpoch:=""
 var leaseGeneration uint64
 for _,line:=range commands{
  args:=strings.Fields(line)
  if len(args)==0||strings.HasPrefix(strings.TrimSpace(line),"#"){continue}
  if len(args)>2{return fmt.Errorf("invalid extra arguments: %s",args[0])}
  op:=args[0]
  req:=request{Op:op}
  switch op {
  case "status","ports":
   if len(args)!=1{return errors.New("status/ports take no arguments")}
  case "reserve":
   if len(args)!=1{return errors.New("reserve takes no arguments")}
   if leaseGeneration!=0{return errors.New("connection already has a lease")}
   req.Actor="approved-agent" // test selector ONLY; server authenticates UID
  case "attach","start","revoke","detach":
   if len(args)!=1||leaseGeneration==0{return errors.New("missing established lease or unexpected argument")}
   req.Actor="approved-agent";req.Epoch=leaseEpoch;req.Generation=leaseGeneration
  case "input":
   if len(args)!=2||leaseGeneration==0{return errors.New("input requires active lease and key command")}
   if args[1]!="key-a-down"&&args[1]!="key-a-up"{return errors.New("unsupported input command")}
   req.Actor="approved-agent";req.Epoch=leaseEpoch;req.Generation=leaseGeneration;req.Command=args[1]
  default:
   return fmt.Errorf("unsupported controller operation: %s",op)
  }
  _=conn.SetDeadline(time.Now().Add(20*time.Second))
  if err:=encoder.Encode(req);err!=nil{return err}
  var resp json.RawMessage
  if err:=decoder.Decode(&resp);err!=nil{return fmt.Errorf("controller did not answer: %w",err)}
  // Preserve complete typed, newline-delimited wire JSON for all audiences.
  fmt.Println(string(resp))
  var ack reply
  if err:=json.Unmarshal(resp,&ack);err!=nil{return err}
  if !ack.OK{return fmt.Errorf("controller rejected %s: %s",op,ack.Error)}
  if op=="reserve"{
   if ack.Epoch==""||ack.Generation==0{return errors.New("controller returned incomplete lease")}
   leaseEpoch=ack.Epoch;leaseGeneration=ack.Generation
  }
  if op=="revoke"{leaseEpoch="";leaseGeneration=0}
 }
 return nil
}
func main(){
 socket:=flag.String("socket","","local protected actuator Unix endpoint")
 op:=flag.String("op","status","one-shot read-only: status or ports")
 batch:=flag.Bool("batch",false,"read strict commands from stdin; one connection retains its lease")
 flag.Parse()
 if flag.NArg()!=0{fmt.Fprintln(os.Stderr,"unexpected CLI arguments");os.Exit(2)}
 commands:=[]string{*op}
 if *batch {
  commands=nil
  in:=bufio.NewScanner(os.Stdin)
  in.Buffer(make([]byte,512),8192)
  for in.Scan(){commands=append(commands,in.Text())}
  if err:=in.Err();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(2)}
 }else if *op!="status"&&*op!="ports"{
  fmt.Fprintln(os.Stderr,"mutations require --batch to retain lease on one socket");os.Exit(2)
 }
 if err:=execute(*socket,commands);err!=nil{
  fmt.Fprintln(os.Stderr,err)
  os.Exit(3)
 }
}
