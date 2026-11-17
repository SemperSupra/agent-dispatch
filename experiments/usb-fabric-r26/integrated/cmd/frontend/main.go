// R26-L2 synthetic broker/frontend: knows only the guarded actuator Unix
// socket; it has no QMP socket path, QMP decoder or USB backend privileges.
package main

import (
 "bufio"
 "flag"
 "fmt"
 "net"
 "os"
 "time"
)
func main(){
 socket:=flag.String("socket","","sole local actuator endpoint")
 flag.Parse()
 if *socket==""{fmt.Fprintln(os.Stderr,"socket required");os.Exit(2)}
 conn,err:=net.DialTimeout("unix",*socket,4*time.Second)
 if err!=nil{fmt.Fprintln(os.Stderr,"actuator unavailable:",err);os.Exit(3)}
 defer conn.Close()
 in:=bufio.NewScanner(os.Stdin)
 in.Buffer(make([]byte,1024),8192)
 out:=bufio.NewScanner(conn)
 out.Buffer(make([]byte,1024),8192)
 writer:=bufio.NewWriter(os.Stdout)
 fmt.Fprintln(writer,`{"ok":true,"state":"frontend-ready"}`)
 _=writer.Flush()
 for in.Scan(){
  _=conn.SetDeadline(time.Now().Add(15*time.Second))
  if _,err:=fmt.Fprintln(conn,in.Text());err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(4)}
  if !out.Scan(){fmt.Fprintln(os.Stderr,"actuator disconnect");os.Exit(5)}
  fmt.Fprintln(writer,out.Text())
  if err=writer.Flush();err!=nil{os.Exit(6)}
 }
 if err=in.Err();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(7)}
}
