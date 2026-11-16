// Public R16: Linux-hosted virtual USB hub management + USB/IP discover-only.
// Synthetic test devices, NOT physical USB, host USB/IP kernel forwarding,
// production TLS/auth, or real guest attachment. Stateless disposable service.
package main

import (
 "bytes"
 "crypto/rand"
 "crypto/subtle"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "os"
 "strconv"
 "strings"
 "sync"
 "time"
)

const (
 apiAddr=":18081"
 usbipAddr="127.0.0.1:3240"
 testToken="r16-public-synthetic-control"
 ownerToken="r16-public-synthetic-owner"
)
type Port struct {
 Port int `json:"port"`
 ID string `json:"id"`
 Kind string `json:"kind"`
 Backend string `json:"backend"`
 Owner string `json:"owner,omitempty"`
 Guest string `json:"guest,omitempty"`
 Mission string `json:"mission,omitempty"`
 Attached bool `json:"attached"`
 Generation uint64 `json:"generation"`
 ExpiresAt int64 `json:"expires_at,omitempty"`
 lease string
}
type Hub struct {
 Name string `json:"name"`
 Ports []Port `json:"ports"`
}
type Command struct {
 Action string `json:"action"`
 Device string `json:"device"`
 Actor string `json:"actor"`
 Guest string `json:"guest"`
 Mission string `json:"mission"`
 Lease string `json:"lease"`
 Generation uint64 `json:"generation"`
 TTLSeconds int `json:"ttl_seconds"`
}
type Reply struct {
 Accepted bool `json:"accepted"`
 Reason string `json:"reason,omitempty"`
 Lease string `json:"lease,omitempty"`
 Generation uint64 `json:"generation,omitempty"`
}
type Gateway struct {
 mu sync.Mutex
 ports []Port
}
func newGateway()*Gateway{
 return &Gateway{ports:[]Port{
  {Port:1,ID:"kbd-1",Kind:"usb-hid-keyboard",Backend:"synthetic-only",Generation:1},
  {Port:2,ID:"tablet-1",Kind:"usb-hid-pointer",Backend:"synthetic-only",Generation:1},
  {Port:3,ID:"storage-1",Kind:"usb-mass-storage-readonly",Backend:"synthetic-only",Generation:1},
 }}
}
func (g *Gateway) find(id string)*Port{
 for i:=range g.ports {if g.ports[i].ID==id{return &g.ports[i]}}
 return nil
}
func validLabel(s string)bool{
 if s==""||len(s)>80{return false}
 for _,r:=range s {
  if !((r>='a'&&r<='z')||(r>='A'&&r<='Z')||(r>='0'&&r<='9')||r=='-'||r=='_') {return false}
 }
 return true
}
func token() (string,error) {
 var b [16]byte
 if _,err:=rand.Read(b[:]);err!=nil{return "",err}
 return hex.EncodeToString(b[:]),nil
}
func (g *Gateway) execute(c Command,admin bool,now time.Time)Reply{
 g.mu.Lock();defer g.mu.Unlock()
 p:=g.find(c.Device)
 if p==nil{return Reply{Reason:"unknown_device"}}
 // Generation is checked for EVERY mutation, including claims and revokes.
 if c.Generation!=p.Generation{return Reply{Reason:"stale_generation",Generation:p.Generation}}
 if p.lease!="" && now.Unix()>=p.ExpiresAt {
  p.lease="";p.Owner="";p.Guest="";p.Mission="";p.Attached=false;p.ExpiresAt=0;p.Generation++
  return Reply{Reason:"expired_lease_reset_retry_with_new_generation",Generation:p.Generation}
 }
 if c.Action=="revoke" {
  if !admin{return Reply{Reason:"owner_approval_required"}}
  p.lease="";p.Owner="";p.Guest="";p.Mission="";p.Attached=false;p.ExpiresAt=0;p.Generation++
  return Reply{Accepted:true,Generation:p.Generation}
 }
 if !validLabel(c.Actor)||!validLabel(c.Guest)||!validLabel(c.Mission){
  return Reply{Reason:"invalid_actor_guest_or_mission"}
 }
 if c.Action=="claim" {
  if p.lease!="" {return Reply{Reason:"exclusive_lease_conflict"}}
  if c.TTLSeconds<1||c.TTLSeconds>30{return Reply{Reason:"ttl_out_of_range"}}
  l,err:=token();if err!=nil{return Reply{Reason:"internal_nonce_failure"}}
  p.lease=l;p.Owner=c.Actor;p.Guest=c.Guest;p.Mission=c.Mission
  p.Attached=false;p.ExpiresAt=now.Unix()+int64(c.TTLSeconds);p.Generation++
  return Reply{Accepted:true,Lease:l,Generation:p.Generation}
 }
 if p.lease==""||c.Lease==""||subtle.ConstantTimeCompare([]byte(c.Lease),[]byte(p.lease))!=1 ||
  p.Owner!=c.Actor||p.Guest!=c.Guest||p.Mission!=c.Mission {
   return Reply{Reason:"invalid_or_missing_lease_scope"}
 }
 switch c.Action {
 case "attach":
  if p.Attached{return Reply{Reason:"already_attached"}}
  p.Attached=true;p.Generation++
  // Control-plane mock only: no QMP or USB/IP kernel action.
  return Reply{Accepted:true,Generation:p.Generation}
 case "detach":
  if !p.Attached{return Reply{Reason:"not_attached"}}
  p.Attached=false;p.Generation++
  return Reply{Accepted:true,Generation:p.Generation}
 case "release":
  p.Attached=false;p.lease="";p.Owner="";p.Guest="";p.Mission="";p.ExpiresAt=0;p.Generation++
  return Reply{Accepted:true,Generation:p.Generation}
 default:return Reply{Reason:"unsupported_action"}
 }
}
func authorized(r *http.Request,tokenValue string)bool{
 h:=r.Header.Get("Authorization")
 want:="Bearer "+tokenValue
 return len(h)==len(want) && subtle.ConstantTimeCompare([]byte(h),[]byte(want))==1
}
func (g *Gateway) handler()http.Handler{
 mux:=http.NewServeMux()
 mux.HandleFunc("/health",func(w http.ResponseWriter,r *http.Request){
  if r.Method!="GET"{http.Error(w,"method",405);return}
  fmt.Fprint(w,"R16_HEALTH_OK")
 })
 mux.HandleFunc("/v1/hubs",func(w http.ResponseWriter,r *http.Request){
  if !authorized(r,testToken) && !authorized(r,ownerToken){http.Error(w,"unauthorized",401);return}
  if r.Method!="GET"{http.Error(w,"method",405);return}
  g.mu.Lock()
  // Never disclose opaque active bearer leases in inventory.
  copyPorts:=append([]Port(nil),g.ports...)
  g.mu.Unlock()
  w.Header().Set("Content-Type","application/json")
  _=json.NewEncoder(w).Encode(Hub{Name:"linux-virtual-hub-r16",Ports:copyPorts})
 })
 mux.HandleFunc("/v1/commands",func(w http.ResponseWriter,r *http.Request){
  auth:=authorized(r,testToken)
  admin:=authorized(r,ownerToken)
  if !auth && !admin{http.Error(w,"unauthorized",401);return}
  if r.Method!="POST"{http.Error(w,"method",405);return}
  r.Body=http.MaxBytesReader(w,r.Body,4096)
  dec:=json.NewDecoder(r.Body);dec.DisallowUnknownFields()
  var c Command
  if err:=dec.Decode(&c);err!=nil{http.Error(w,"bad_json",400);return}
  var extra interface{}
  if err:=dec.Decode(&extra);err!=io.EOF{http.Error(w,"trailing_data",400);return}
  ans:=g.execute(c,admin,time.Now())
  w.Header().Set("Content-Type","application/json")
  if !ans.Accepted{w.WriteHeader(http.StatusForbidden)}
  _=json.NewEncoder(w).Encode(ans)
 })
 return mux
}
func sendDevice(conn net.Conn,p Port,index int)error{
 path:=make([]byte,256)
 copy(path,[]byte("/sys/devices/virtual/linuxhub/"+p.ID))
 busid:=make([]byte,32)
 copy(busid,[]byte(fmt.Sprintf("1-%d",p.Port)))
 if _,err:=conn.Write(append(path,busid...));err!=nil{return err}
 fields:=make([]byte,24)
 binary.BigEndian.PutUint32(fields[0:4],1)
 binary.BigEndian.PutUint32(fields[4:8],uint32(index+1))
 binary.BigEndian.PutUint32(fields[8:12],3)
 binary.BigEndian.PutUint16(fields[12:14],0x1209)
 binary.BigEndian.PutUint16(fields[14:16],uint16(0x5100+index))
 binary.BigEndian.PutUint16(fields[16:18],0x0100)
 fields[18]=0;fields[19]=0;fields[20]=0;fields[21]=1;fields[22]=1;fields[23]=1
 if _,err:=conn.Write(fields);err!=nil{return err}
 iface:=[]byte{3,1,1,0}
 if p.Kind=="usb-mass-storage-readonly"{iface=[]byte{8,6,80,0}}
 _,err:=conn.Write(iface)
 return err
}
func handleUSBIP(conn net.Conn,g *Gateway){
 defer conn.Close()
 _=conn.SetDeadline(time.Now().Add(5*time.Second))
 var header [8]byte
 if _,err:=io.ReadFull(conn,header[:]);err!=nil{return}
 version:=binary.BigEndian.Uint16(header[0:2])
 request:=binary.BigEndian.Uint16(header[2:4])
 if version!=0x0111 || binary.BigEndian.Uint32(header[4:8])!=0{return}
 switch request {
 case 0x8005:
  g.mu.Lock();ports:=append([]Port(nil),g.ports...);g.mu.Unlock()
  answer:=make([]byte,12)
  binary.BigEndian.PutUint16(answer[0:2],0x0111)
  binary.BigEndian.PutUint16(answer[2:4],0x0005)
  binary.BigEndian.PutUint32(answer[8:12],uint32(len(ports)))
  if _,err:=conn.Write(answer);err!=nil{return}
  for i,p:=range ports {if sendDevice(conn,p,i)!=nil{return}}
 case 0x8003:
  var requested [32]byte
  if _,err:=io.ReadFull(conn,requested[:]);err!=nil{return}
  // Explicit deny: real imported hardware must first be admitted by a
  // separate hardware owner and actual Linux kernel USB/IP gateway.
  reply:=[]byte{0x01,0x11,0x00,0x03,0,0,0,1}
  _,_=conn.Write(reply)
 default:
  return
 }
}
func runServer()error{
 g:=newGateway()
 listener,err:=net.Listen("tcp",usbipAddr)
 if err!=nil{return err}
 defer listener.Close()
 go func(){
  for {
   conn,err:=listener.Accept()
   if err!=nil{return}
   go handleUSBIP(conn,g)
  }
 }()
 fmt.Println("R16_USBIP_LOOPBACK_ONLY_LISTENER=PASS",usbipAddr)
 server:=&http.Server{Addr:apiAddr,Handler:g.handler(),ReadHeaderTimeout:3*time.Second}
 fmt.Println("R16_LINUX_MANAGEMENT_HTTP_API_READY=PASS",apiAddr)
 return server.ListenAndServe()
}
func request(client *http.Client,url,auth string,command *Command)(int,Reply,[]byte,error){
 method:="GET"
 var body io.Reader
 if command!=nil{
  method="POST"
  data,_:=json.Marshal(command)
  body=bytes.NewReader(data)
 }
 r,err:=http.NewRequest(method,url,body)
 if err!=nil{return 0,Reply{},nil,err}
 if auth!=""{r.Header.Set("Authorization","Bearer "+auth)}
 r.Header.Set("Content-Type","application/json")
 resp,err:=client.Do(r)
 if err!=nil{return 0,Reply{},nil,err}
 defer resp.Body.Close()
 b,err:=io.ReadAll(io.LimitReader(resp.Body,16384))
 if err!=nil{return 0,Reply{},nil,err}
 var ans Reply
 if command!=nil{if err=json.Unmarshal(b,&ans);err!=nil{return 0,Reply{},b,err}}
 return resp.StatusCode,ans,b,nil
}
func verifyClient()error{
 httpClient:=&http.Client{Timeout:4*time.Second}
 base:="http://r16-gateway:18081"
 for i:=0;i<40;i++{
  resp,err:=httpClient.Get(base+"/health")
  if err==nil{
   _=resp.Body.Close()
   if resp.StatusCode==200{break}
  }
  if i==39{return errors.New("gateway HTTP unavailable")}
  time.Sleep(100*time.Millisecond)
 }
 if status,_,_,err:=request(httpClient,base+"/v1/hubs","",nil);err!=nil||status!=401{return fmt.Errorf("unauthed inventory accepted status=%d err=%v",status,err)}
 fmt.Println("R16_REMOTE_UNAUTHENTICATED_API_DENIED=PASS")
 status,_,data,err:=request(httpClient,base+"/v1/hubs",testToken,nil)
 if err!=nil||status!=200{return fmt.Errorf("inventory missing status=%d err=%v",status,err)}
 var inventory Hub
 if err=json.Unmarshal(data,&inventory);err!=nil{return err}
 if inventory.Name!="linux-virtual-hub-r16"||len(inventory.Ports)!=3{return errors.New("virtual hub ports missing")}
 for i,p:=range inventory.Ports {
  if p.Port!=i+1 || p.Backend!="synthetic-only" || p.Generation!=1{return errors.New("unexpected port config")}
 }
 fmt.Println("R16_REMOTE_IP_VIRTUAL_HUB_INVENTORY=PASS")
 cmd:=Command{Action:"claim",Device:"kbd-1",Actor:"actor-a",Guest:"linux-guest-1",Mission:"rdte",Generation:1,TTLSeconds:30}
 status,claim,_,err:=request(httpClient,base+"/v1/commands",testToken,&cmd)
 if err!=nil||status!=200||!claim.Accepted||claim.Lease==""||claim.Generation!=2{return errors.New("first lease not granted")}
 other:=cmd;other.Actor="actor-b";other.Guest="windows-guest-2";other.Generation=2
 status,_,_,err=request(httpClient,base+"/v1/commands",testToken,&other)
 if err!=nil||status!=403{return errors.New("exclusive device lease not enforced")}
 fmt.Println("R16_EXCLUSIVE_PER_DEVICE_GUEST_LEASE=PASS")
 action:=cmd;action.Action="attach";action.Lease=claim.Lease
 action.Generation=1
 status,_,_,err=request(httpClient,base+"/v1/commands",testToken,&action)
 if err!=nil||status!=403{return errors.New("stale device generation admitted")}
 action.Generation=2;action.Lease="invalid"
 status,_,_,err=request(httpClient,base+"/v1/commands",testToken,&action)
 if err!=nil||status!=403{return errors.New("invalid lease admitted")}
 action.Lease=claim.Lease
 status,attached,_,err:=request(httpClient,base+"/v1/commands",testToken,&action)
 if err!=nil||status!=200||attached.Generation!=3{return errors.New("mock attach denied")}
 fmt.Println("R16_AUTHORIZED_SIMULATED_ROUTE_ATTACHED=PASS")
 action.Action="release";action.Generation=3
 status,released,_,err:=request(httpClient,base+"/v1/commands",testToken,&action)
 if err!=nil||status!=200||released.Generation!=4{return errors.New("release failed")}
 status,_,_,err=request(httpClient,base+"/v1/commands",testToken,&action)
 if err!=nil||status!=403{return errors.New("replayed release accepted")}
 other.Generation=4
 status,second,_,err:=request(httpClient,base+"/v1/commands",testToken,&other)
 if err!=nil||status!=200||!second.Accepted||second.Generation!=5{return errors.New("second guest denied after release")}
 fmt.Println("R16_RELEASE_REASSIGN_AND_REPLAY_DENIAL=PASS")
 revoke:=Command{Action:"revoke",Device:"kbd-1",Generation:5}
 status,_,_,err=request(httpClient,base+"/v1/commands",testToken,&revoke)
 if err!=nil||status!=403{return errors.New("unauthorized owner revoke accepted")}
 status,revoked,_,err:=request(httpClient,base+"/v1/commands",ownerToken,&revoke)
 if err!=nil||status!=200||revoked.Generation!=6{return errors.New("authorized revoke failed")}
 action.Generation=6
 status,_,_,err=request(httpClient,base+"/v1/commands",testToken,&action)
 if err!=nil||status!=403{return errors.New("stale actor reattached after revoke")}
 fmt.Println("R16_SEPARATE_OWNER_REVOKE_AND_FENCING=PASS")
 // A management-plane client on the isolated Docker bridge must not be able
 // to access the unauthenticated USB/IP import port: USB/IP binds loopback.
 conn,err:=net.DialTimeout("tcp","r16-gateway:3240",650*time.Millisecond)
 if err==nil{
  _=conn.Close()
  return errors.New("USB/IP import port exposed to management clients")
 }
 fmt.Println("R16_RAW_USBIP_PORT_NOT_EXPOSED_TO_REMOTE_CLIENT=PASS")
 fmt.Println("R16_SYNTHETIC_INVENTORY_ONLY_NO_REAL_USB_ROUTING=PASS")
 return nil
}
func probeImport()error{
 conn,err:=net.DialTimeout("tcp","127.0.0.1:3240",time.Second)
 if err!=nil{return err}
 defer conn.Close()
 _=conn.SetDeadline(time.Now().Add(2*time.Second))
 data:=make([]byte,8+32)
 binary.BigEndian.PutUint16(data[0:2],0x0111)
 binary.BigEndian.PutUint16(data[2:4],0x8003)
 copy(data[8:],[]byte("1-1"))
 if _,err=conn.Write(data);err!=nil{return err}
 reply:=make([]byte,8)
 if _,err=io.ReadFull(conn,reply);err!=nil{return err}
 if binary.BigEndian.Uint16(reply[0:2])!=0x0111 || binary.BigEndian.Uint16(reply[2:4])!=0x0003 ||
 binary.BigEndian.Uint32(reply[4:8])!=1{return errors.New("USBIP import unexpectedly accepted")}
 fmt.Println("R16_USBIP_IMPORT_ATTEMPT_DENIED=PASS")
 return nil
}
func main(){
 if len(os.Args)<2{fmt.Fprintln(os.Stderr,"need server|client|probe-import");os.Exit(2)}
 var err error
 switch os.Args[1]{
 case "server":err=runServer()
 case "client":err=verifyClient()
 case "probe-import":err=probeImport()
 default:err=errors.New("unknown mode: "+strconv.Quote(os.Args[1]))
 }
 if err!=nil{fmt.Fprintln(os.Stderr,"R16_RESULT=RED",strings.ReplaceAll(err.Error(),string(rune(10)),";"));os.Exit(1)}
}
