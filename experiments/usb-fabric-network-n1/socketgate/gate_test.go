// SPDX-License-Identifier: MIT
package socketgate

import (
 "context"
 "errors"
 "net"
 "net/netip"
 "testing"
 "time"

 "github.com/SemperSupra/agent-dispatch/experiments/usb-fabric-network-n1/usbnetpolicy"
)

func TestLoopbackSocketRevocationAndReAdmission(t *testing.T) {
 listener, err:=net.Listen("tcp4","127.0.0.1:0")
 if err != nil {t.Fatal(err)}
 defer listener.Close()
 serverConn:=make(chan net.Conn,1)
 go func(){c,e:=listener.Accept();if e==nil{serverConn<-c}}()
 sources:=[]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
 d:=usbnetpolicy.DecisionInput{SourceIP:"127.0.0.2",DestinationIP:"127.0.0.1",DestinationPort:3240,Transport:"usbip-tcp",DeviceID:"device",PrincipalID:"consumer",LeaseDeviceID:"device",LeasePrincipalID:"consumer",LeaseEpoch:1,ActiveEpoch:1,LeaseActive:true,Authenticated:true,PathAuthenticated:true}
 gate:=new(Gate)
 // Dialer uses ephemeral listener port for test only and checks the destination
 // address requested by the gate, without opening any public port.
 dialer:=func(ctx context.Context, network, addr string)(net.Conn,error){
  if network!="tcp" || addr!="127.0.0.1:3240" {return nil,errors.New("wrong policy endpoint")}
  var nd net.Dialer
  return nd.DialContext(ctx,"tcp4",listener.Addr().String())
 }
 untrusted:=d;untrusted.PathAuthenticated=false
 if _,err:=gate.Connect(context.Background(),untrusted,sources,sources,dialer);err==nil {t.Fatal("unauthorized connection")}
 conn,err:=gate.Connect(context.Background(),d,sources,sources,dialer)
 if err!=nil {t.Fatal(err)}
 peer:=<-serverConn
 defer peer.Close()
 if _,err:=gate.Connect(context.Background(),d,sources,sources,dialer);!errors.Is(err,ErrAlreadyActive){t.Fatalf("duplicate attach %v",err)}
 readResult:=make(chan error,1)
 go func(){buf:=make([]byte,1);_,e:=conn.Read(buf);readResult<-e}()
 if err:=gate.Revoke();err!=nil {t.Fatal(err)}
 select{case err:=<-readResult:if err==nil {t.Fatal("read survived revoke")};case <-time.After(time.Second):t.Fatal("connection survived revoke")}
 if _,err:=gate.Connect(context.Background(),d,sources,sources,dialer);!errors.Is(err,ErrRevoked){t.Fatalf("stale lease %v",err)}
 if err:=gate.ResetForNewLease(1);!errors.Is(err,ErrRevoked){t.Fatal("old epoch accepted")}
 if err:=gate.ResetForNewLease(2);err!=nil {t.Fatal(err)}
 d.ActiveEpoch=2;d.LeaseEpoch=2
 // Direct proof that retired generation cannot be reused.
 if _,err:=gate.Connect(context.Background(),d,sources,sources,dialer);err!=nil {t.Fatal(err)}
 if err:=gate.Revoke();err!=nil {t.Fatal(err)}
}
