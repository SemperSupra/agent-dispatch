// Public synthetic Linux USB/IP v1.1.1 frame test server. It models a single
// HID interrupt endpoint ONLY: no Linux kernel USBIP host/vHCI, physical USB,
// QEMU usbredir translation, real guest input, or production security.
package usbipwire
import (
 "bytes"
 "encoding/binary"
 "fmt"
 "io"
 "net"
 "sync"
 "time"
)
const (
 Version=0x0111
 ReqDevlist=0x8005
 RepDevlist=0x0005
 ReqImport=0x8003
 RepImport=0x0003
 CmdSubmit=1
 CmdUnlink=2
 RetSubmit=3
 RetUnlink=4
 syntheticDev=0x00010002
)
var order=binary.BigEndian
type Server struct{
 listener net.Listener
 wg sync.WaitGroup
}
func fixed(s string,n int)[]byte {
 b:=make([]byte,n)
 copy(b,[]byte(s))
 return b
}
func record()[]byte{
 d:=make([]byte,312)
 copy(d[0:256],[]byte("/sys/devices/virtual/r20-synthetic"))
 copy(d[256:288],[]byte("1-1"))
 order.PutUint32(d[288:292],1)
 order.PutUint32(d[292:296],2)
 order.PutUint32(d[296:300],3)
 order.PutUint16(d[300:302],0x1209)
 order.PutUint16(d[302:304],0x2019)
 order.PutUint16(d[304:306],0x0100)
 d[306]=3;d[307]=1;d[308]=1;d[309]=1;d[310]=1;d[311]=1
 return d
}
func send(conn net.Conn,b []byte)error{
 for len(b)>0{
  n,e:=conn.Write(b)
  if e!=nil{return e}
  if n<=0{return io.ErrUnexpectedEOF}
  b=b[n:]
 }
 return nil
}
func headerReply(code uint16,status uint32)[]byte{
 b:=make([]byte,8)
 order.PutUint16(b[0:2],Version)
 order.PutUint16(b[2:4],code)
 order.PutUint32(b[4:8],status)
 return b
}
func Start()(s *Server,err error){
 l,e:=net.Listen("tcp","127.0.0.1:3240")
 if e!=nil{return nil,e}
 s=&Server{listener:l}
 s.wg.Add(1)
 go func(){
  defer s.wg.Done()
  for{
   c,e:=l.Accept()
   if e!=nil{return}
   s.wg.Add(1)
   go func(){defer s.wg.Done();handle(c)}()
  }
 }()
 return s,nil
}
func (s *Server) Close(){
 if s==nil{return}
 _=s.listener.Close()
 s.wg.Wait()
}
func handle(c net.Conn){
 defer c.Close()
 _=c.SetDeadline(time.Now().Add(5*time.Second))
 var h [8]byte
 if _,e:=io.ReadFull(c,h[:]);e!=nil{return}
 if order.Uint16(h[0:2])!=Version||order.Uint32(h[4:8])!=0{return}
 switch order.Uint16(h[2:4]){
 case ReqDevlist:
  b:=append(headerReply(RepDevlist,0),0,0,0,1)
  b=append(b,record()...)
  b=append(b,3,1,1,0)
  _=send(c,b)
 case ReqImport:
  var bid[32]byte
  if _,e:=io.ReadFull(c,bid[:]);e!=nil{return}
  name:=bytes.TrimRight(bid[:],"\x00")
  if !bytes.Equal(name,[]byte("1-1")){
   _=send(c,headerReply(RepImport,1));return
  }
  if e:=send(c,append(headerReply(RepImport,0),record()...));e!=nil{return}
  serveURBs(c)
 }
}
func basicFrame(command,sequence,devid,direction,ep uint32)[]byte{
 b:=make([]byte,48)
 for i,v:=range []uint32{command,sequence,devid,direction,ep}{
  order.PutUint32(b[i*4:(i+1)*4],v)
 }
 return b
}
func syntheticHID()[]byte{return []byte{0,0,0x04,0,0,0,0,0}}
func serveURBs(c net.Conn){
 pending:=map[uint32]bool{}
 for{
  var b[48]byte
  if _,e:=io.ReadFull(c,b[:]);e!=nil{return}
  cmd:=order.Uint32(b[0:4])
  seq:=order.Uint32(b[4:8])
  devid:=order.Uint32(b[8:12])
  dir:=order.Uint32(b[12:16])
  ep:=order.Uint32(b[16:20])
  if seq==0||devid!=syntheticDev{return}
  switch cmd {
  case CmdSubmit:
   flags:=order.Uint32(b[20:24])
   length:=order.Uint32(b[24:28])
   npackets:=order.Uint32(b[32:36])
   if dir!=1||ep!=1||flags!=0||length!=8||npackets!=0xffffffff||
    !bytes.Equal(b[40:48],make([]byte,8)){return}
   if seq==20{
    pending[seq]=true
    continue
   }
   if seq!=10{return}
   ret:=basicFrame(RetSubmit,seq,0,0,0)
   order.PutUint32(ret[20:24],0)
   order.PutUint32(ret[24:28],8)
   order.PutUint32(ret[32:36],0xffffffff)
   ret=append(ret,syntheticHID()...)
   if e:=send(c,ret);e!=nil{return}
  case CmdUnlink:
   target:=order.Uint32(b[20:24])
   if dir!=0||ep!=0||!pending[target]{return}
   delete(pending,target)
   ret:=basicFrame(RetUnlink,seq,0,0,0)
   order.PutUint32(ret[20:24],0xffffff98) // -ECONNRESET
   if e:=send(c,ret);e!=nil{return}
  default:return
  }
 }
}
func requestImport(c net.Conn,busid string)error{
 b:=append(headerReply(ReqImport,0),fixed(busid,32)...)
 if e:=send(c,b);e!=nil{return e}
 var rep[8]byte
 if _,e:=io.ReadFull(c,rep[:]);e!=nil{return e}
 if order.Uint16(rep[:2])!=Version||order.Uint16(rep[2:4])!=RepImport{return fmt.Errorf("unexpected import response")}
 if order.Uint32(rep[4:8])!=0{return fmt.Errorf("import rejected")}
 var dev[312]byte
 if _,e:=io.ReadFull(c,dev[:]);e!=nil{return e}
 if order.Uint16(dev[300:302])!=0x1209{return fmt.Errorf("wrong synthetic device")}
 return nil
}
