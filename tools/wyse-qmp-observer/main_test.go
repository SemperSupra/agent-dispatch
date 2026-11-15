package main
import(
 "encoding/json"
 "net"
 "path/filepath"
 "strings"
 "sync"
 "testing"
)
func TestQueriesAreStrictlyReadOnly(t *testing.T){
 for _,v:=range allowedQueries{if !strings.HasPrefix(v,"query-"){t.Fatalf("mutation admitted: %s",v)}}
}
func TestFakeQMPReadOnlyAndEvents(t *testing.T){
 path:=filepath.Join(t.TempDir(),"qmp.sock")
 l,err:=net.Listen("unix",path);if err!=nil{t.Fatal(err)}
 defer l.Close()
 var wg sync.WaitGroup;wg.Add(1)
 go func(){
  defer wg.Done()
  c,err:=l.Accept();if err!=nil{return}
  defer c.Close()
  enc:=json.NewEncoder(c);dec:=json.NewDecoder(c)
  _=enc.Encode(map[string]any{"QMP":map[string]string{"version":"synthetic"}})
  for {
   var cmd struct{Execute string `json:"execute"`;ID string `json:"id"`}
   if err=dec.Decode(&cmd);err!=nil{return}
   if cmd.Execute!="qmp_capabilities"&&!strings.HasPrefix(cmd.Execute,"query-"){t.Errorf("mutating QMP %s",cmd.Execute);return}
   if cmd.Execute=="query-cpus-fast"{_ =enc.Encode(map[string]any{"event":"STOP"})}
   _=enc.Encode(map[string]any{"id":cmd.ID,"return":map[string]any{"state":"synthetic"}})
  }
 }()
 r,err:=Observe(path);if err!=nil{t.Fatal(err)}
 if !r.QMPReadOnly||r.PhysicalTPMExposed||len(r.Metrics)!=len(allowedQueries){t.Fatal(r)}
 for _,row:=range r.Metrics{if !row.Supported{t.Fatalf("unsupported %s",row.Query)}}
 _=l.Close();wg.Wait()
}
func TestNotQMPRefused(t *testing.T){
 path:=filepath.Join(t.TempDir(),"fake.sock")
 l,err:=net.Listen("unix",path);if err!=nil{t.Fatal(err)}
 defer l.Close()
 go func(){c,e:=l.Accept();if e==nil{_,_=c.Write([]byte("{}\n"));_ =c.Close()}}()
 if _,err:=Observe(path);err==nil{t.Fatal("accepted non-QMP socket")}
}
