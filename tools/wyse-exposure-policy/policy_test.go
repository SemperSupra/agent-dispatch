package exposure

import (
 "encoding/json"
 "strings"
 "testing"
)
func valid() Plan{
 return Plan{
  Version:1,OverlayProvider:"headscale",OverlayInterface:"tailscale0",
  OverlayPrefixes:[]string{"100.64.0.0/10"},OverlayPolicySHA256:strings.Repeat("a",64),
  OverlayState:"observed_up",
  Services:[]Service{
   {Name:"human_ui",Mode:"both",Port:8443,LANIP:"192.168.50.10",OverlayIP:"100.101.102.103",Auth:"oidc",Roles:[]string{"owner","operator"}},
   {Name:"recoverd_ssh",Mode:"overlay",Port:2222,OverlayIP:"100.101.102.103",Auth:"ssh_key",Roles:[]string{"owner"}},
   {Name:"health",Mode:"local",Port:8080,Auth:"none",Roles:[]string{"owner"}},
   {Name:"inventory_admin",Mode:"local",UnixSocket:"/run/wyse/inventory.sock",Auth:"mtls",Roles:[]string{"owner"}},
  },
 }
}
func TestTransportPlanAndDefaultDenials(t *testing.T){
 p:=valid()
 x,e:=Compile(p);if e!=nil{t.Fatal(e)}
 if len(x.Listeners)!=5 {t.Fatalf("expected five exact listeners, got %+v",x.Listeners)}
 for _,l:=range x.Listeners {
  if strings.Contains(l.Address,"0.0.0.0")||strings.Contains(l.Address,"[::]"){t.Fatalf("wildcard published %s",l.Address)}
  if l.Service=="inventory_admin" && l.Network!="local_unix" {t.Fatal("private inventory exposed")}
 }
 if _,e:=Compile(Plan{Version:1,Services:nil});e!=nil{t.Fatalf("default should expose nothing: %v",e)}
}
func TestFailClosedNegativeMatrix(t *testing.T){
 tests:=[]struct{name string; mutate func(*Plan)}{
  {"missing-policy",func(p *Plan){p.OverlayPolicySHA256=""}},
  {"overlay-down-no-lan-fallback",func(p *Plan){p.OverlayState="down"}},
  {"missing-overlay-interface",func(p *Plan){p.OverlayInterface=""}},
  {"unknown-overlay-provider",func(p *Plan){p.OverlayProvider="unknown"}},
  {"overlay-public-ip",func(p *Plan){p.Services[0].OverlayIP="8.8.8.8"}},
  {"overlay-wildcard",func(p *Plan){p.Services[0].OverlayIP="0.0.0.0"}},
  {"lan-public-ip",func(p *Plan){p.Services[0].LANIP="8.8.8.8"}},
  {"lan-wildcard",func(p *Plan){p.Services[0].LANIP="0.0.0.0"}},
  {"lan-loopback",func(p *Plan){p.Services[0].LANIP="127.0.0.1"}},
  {"service-unknown",func(p *Plan){p.Services[0].Name="mystery"}},
  {"role-unknown",func(p *Plan){p.Services[0].Roles=[]string{"anonymous"}}},
  {"same-binding-collision",func(p *Plan){p.Services=append(p.Services,Service{Name:"telemetry",Mode:"lan",Port:8443,LANIP:"192.168.50.10",Auth:"mtls",Roles:[]string{"agent"}})}},
  {"inventory-on-lan",func(p *Plan){p.Services[3].Mode="lan";p.Services[3].Port=5000;p.Services[3].LANIP="192.168.50.10"}},
  {"inventory-on-overlay",func(p *Plan){p.Services[3].Mode="overlay";p.Services[3].Port=5000;p.Services[3].OverlayIP="100.101.102.103"}},
  {"inventory-guest-role",func(p *Plan){p.Services[3].Roles=[]string{"owner","guest"}}},
  {"inventory-unsafe-unix-path",func(p *Plan){p.Services[3].UnixSocket="/tmp/inventory.sock"}},
  {"guest-lan-unauthenticated",func(p *Plan){p.Services[0].Auth="none"}},
  {"trust-proxy-identity",func(p *Plan){p.TrustProxyIdentityHeaders=true}},
  {"duplicate-service",func(p *Plan){p.Services=append(p.Services,p.Services[0])}},
  {"overlay-address-in-lan-only",func(p *Plan){p.Services[0].Mode="lan"}},
  {"unknown-mode",func(p *Plan){p.Services[0].Mode="funnel"}},
 }
 for _,tc:=range tests{t.Run(tc.name,func(t *testing.T){p:=valid();tc.mutate(&p);if _,e:=Compile(p);e==nil{t.Fatal("unsafe plan accepted")}})}
}
func TestOverlayOnlyCannotFallbackToLAN(t *testing.T){
 p:=valid()
 p.Services=[]Service{{Name:"controller_api",Mode:"overlay",Port:8443,OverlayIP:"100.101.102.103",Auth:"mtls",Roles:[]string{"owner"}}}
 x,e:=Compile(p);if e!=nil{t.Fatal(e)}
 if len(x.Listeners)!=1||x.Listeners[0].Network!="overlay_tcp"{t.Fatal("fallback to ordinary stack")}
 p.OverlayState="down"
 if _,e:=Compile(p);e==nil{t.Fatal("overlay down silently permitted LAN")}
}
func TestTenantProjectionCannotLeakHostPassthroughEvenWhenDetailsKnown(t *testing.T){
 status:=ProjectTenant("ready","guest_001")
 b,e:=json.Marshal(status);if e!=nil{t.Fatal(e)}
 for _,leak:=range []string{"pci","device","vfio","gpu","iommu","render","mdev","passthrough","usb","serial","network","tailnet","candidate","inventory","available","count"}{
  if strings.Contains(strings.ToLower(string(b)),leak){t.Fatalf("host inventory leaked: %s",leak)}
 }
 // Invalid guest names disappear, not embedded verbatim.
 p:=ProjectTenant("ready","0000:00:02.0/vendor_id")
 if p.GuestID!=""{t.Fatalf("raw host BDF in tenant response: %s",p.GuestID)}
}
