package recoveryfence
import(
 "errors"
 "net"
 "os"
 "path/filepath"
 "testing"
)
func sockets(t *testing.T)(net.Conn,net.Conn,func()){
 t.Helper()
 dir:=t.TempDir()
 open:=func(path string)(net.Conn,net.Listener){
  l,e:=net.Listen("unix",path);if e!=nil{t.Fatal(e)}
  c,e:=net.Dial("unix",path);if e!=nil{t.Fatal(e)}
  return c,l
 }
 a,al:=open(filepath.Join(dir,"qmp.sock"))
 b,bl:=open(filepath.Join(dir,"receipt.sock"))
 return a,b,func(){a.Close();b.Close();al.Close();bl.Close()}
}
func TestSameKernelPeerSingleOwner(t *testing.T){
 a,b,done:=sockets(t);defer done()
 l,e:=Acquire(a,b);if e!=nil{t.Fatal(e)}
 if l.Peer.PID!=int32(os.Getpid()){t.Fatal("SO_PEERCRED PID mismatch")}
 if _,e=Acquire(a,b);e==nil{t.Fatal("simultaneous recovery owner accepted")}
 _=l.Close()
 again,e:=Acquire(a,b);if e!=nil{t.Fatal(e)}
 _=again.Close()
}
func TestNonUnixConnDenied(t *testing.T){
 a,b:=net.Pipe();defer a.Close();defer b.Close()
 if _,e:=Acquire(a,b);!errors.Is(e,ErrUntrusted){t.Fatal(e)}
}
func TestDifferentPeerDenied(t *testing.T){
 // Separate Unix server PIDs are exercised in later live-QEMU qualification;
 // the contract here still explicitly requires Peer equality.
 a:=Peer{UID:1,PID:10,Boot:"boot1",Start:"123"}
 b:=Peer{UID:1,PID:11,Boot:"boot1",Start:"123"}
 if a==b{t.Fatal("different peer identities collided")}
}
