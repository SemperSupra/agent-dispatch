package usbipwire
import (
 "bytes"
 "encoding/binary"
 "io"
 "net"
 "os/exec"
 "strings"
 "testing"
 "time"
)
func connect(t *testing.T)net.Conn{
 t.Helper()
 c,e:=net.DialTimeout("tcp","127.0.0.1:3240",time.Second)
 if e!=nil{t.Fatal(e)}
 _=c.SetDeadline(time.Now().Add(2*time.Second))
 return c
}
func withServer(t *testing.T)*Server{
 t.Helper()
 s,e:=Start()
 if e!=nil{t.Fatal(e)}
 t.Cleanup(s.Close)
 return s
}
func TestActualUpstreamClientDeviceDiscovery(t *testing.T){
 withServer(t)
 cmd:=exec.Command("usbip","list","--remote=127.0.0.1")
 out,e:=cmd.CombinedOutput()
 if e!=nil{t.Fatalf("actual Linux usbip userspace client failure: %s %v",out,e)}
 if !strings.Contains(string(out),"1-1"){t.Fatalf("synthetic busid not discoverable: %s",out)}
 t.Log("R20_ACTUAL_UPSTREAM_LINUX_USBIP_DEVLIST=PASS")
}
func TestSyntheticImportSubmitAndUnlinkWire(t *testing.T){
 withServer(t)
 c:=connect(t);defer c.Close()
 if e:=requestImport(c,"1-1");e!=nil{t.Fatal(e)}
 t.Log("R20_SYNTHETIC_IMPORT_NEGOTIATED=PASS")
 b:=basicFrame(CmdSubmit,10,syntheticDev,1,1)
 order.PutUint32(b[24:28],8)
 order.PutUint32(b[32:36],0xffffffff)
 if e:=send(c,b);e!=nil{t.Fatal(e)}
 var rep[56]byte
 if _,e:=io.ReadFull(c,rep[:]);e!=nil{t.Fatal(e)}
 if order.Uint32(rep[0:4])!=RetSubmit||
  order.Uint32(rep[4:8])!=10||
  order.Uint32(rep[24:28])!=8||
  !bytes.Equal(rep[48:],syntheticHID()){t.Fatal("incorrect USBIP IN interrupt URB answer")}
 t.Log("R20_USBIP_INTERRUPT_IN_URB_PAYLOAD_OBSERVED=PASS")
 b=basicFrame(CmdSubmit,20,syntheticDev,1,1)
 order.PutUint32(b[24:28],8)
 order.PutUint32(b[32:36],0xffffffff)
 if e:=send(c,b);e!=nil{t.Fatal(e)}
 unlink:=basicFrame(CmdUnlink,21,syntheticDev,0,0)
 order.PutUint32(unlink[20:24],20)
 if e:=send(c,unlink);e!=nil{t.Fatal(e)}
 var ur[48]byte
 if _,e:=io.ReadFull(c,ur[:]);e!=nil{t.Fatal(e)}
 if order.Uint32(ur[0:4])!=RetUnlink||order.Uint32(ur[4:8])!=21||
  int32(order.Uint32(ur[20:24]))!=-104{t.Fatal("unlink reply not kernel-spec -ECONNRESET")}
 t.Log("R20_USBIP_PENDING_URB_UNLINK_NEGATIVE_ORACLE=PASS")
}
func TestMalformedFramesAreClosedAndUnknownDeviceDenied(t *testing.T){
 withServer(t)
 c:=connect(t)
 bad:=headerReply(ReqImport,0)
 binary.BigEndian.PutUint16(bad[:2],0x9999)
 if e:=send(c,append(bad,fixed("1-1",32)...));e!=nil{t.Fatal(e)}
 var p[8]byte
 if _,e:=io.ReadFull(c,p[:]);e==nil{t.Fatal("bad protocol version accepted")}
 c.Close()
 c=connect(t)
 if e:=send(c,append(headerReply(ReqImport,0),fixed("host-real-device",32)...));e!=nil{t.Fatal(e)}
 if _,e:=io.ReadFull(c,p[:]);e!=nil{t.Fatal(e)}
 if binary.BigEndian.Uint32(p[4:8])!=1{t.Fatal("unknown import not denied")}
 c.Close()
 c=connect(t);defer c.Close()
 if e:=requestImport(c,"1-1");e!=nil{t.Fatal(e)}
 frame:=basicFrame(CmdSubmit,30,syntheticDev,1,1)
 order.PutUint32(frame[24:28],4096)
 order.PutUint32(frame[32:36],0xffffffff)
 if e:=send(c,frame);e!=nil{t.Fatal(e)}
 _=c.SetReadDeadline(time.Now().Add(500*time.Millisecond))
 if _,e:=io.ReadFull(c,p[:]);e==nil{t.Fatal("oversize URB accepted")}
 if bytes.Equal(p[:],make([]byte,8)) { /* only a diagnostic buffer */ }
 t.Log("R20_MALFORMED_AND_UNKNOWN_USBIP_FRAME_FAIL_CLOSED=PASS")
}
