// Package exposure validates a proposed network exposure plan. Nothing here
// opens a listener, edits a firewall or contacts Tailscale/Headscale.
package exposure

import (
 "errors"
 "fmt"
 "net"
 "net/netip"
 "path/filepath"
 "regexp"
 "sort"
 "strings"
)

type Service struct {
 Name string `json:"name"`
 Mode string `json:"mode"` // disabled, local, lan, overlay, both
 Port int `json:"port,omitempty"`
 LANIP string `json:"lan_ip,omitempty"`
 OverlayIP string `json:"overlay_ip,omitempty"`
 UnixSocket string `json:"unix_socket,omitempty"`
 Auth string `json:"auth,omitempty"` // mtls, oidc, ssh_key; no HTTP identity header
 Roles []string `json:"roles,omitempty"`
}
type Plan struct {
 Version int `json:"version"`
 OverlayProvider string `json:"overlay_provider,omitempty"`
 OverlayInterface string `json:"overlay_interface,omitempty"`
 OverlayPrefixes []string `json:"overlay_prefixes,omitempty"`
 OverlayPolicySHA256 string `json:"overlay_policy_sha256,omitempty"`
 OverlayState string `json:"overlay_state,omitempty"` // only 'observed_up' permits overlay plan
 TrustProxyIdentityHeaders bool `json:"trust_proxy_identity_headers,omitempty"`
 Services []Service `json:"services"`
}
type Listener struct {
 Service string `json:"service"`
 Network string `json:"network"` // local_unix / lan_tcp / overlay_tcp
 Address string `json:"address"`
 Auth string `json:"auth"`
}
type Result struct {
 Scope string `json:"scope"`
 Listeners []Listener `json:"listeners"`
}
var idRE=regexp.MustCompile("^[a-z][a-z0-9_]{1,42}$")
var shaRE=regexp.MustCompile("^[a-f0-9]{64}$")
var known=map[string]bool{
 "health":true, "controller_api":true, "human_ui":true,
 "recoverd_ssh":true, "telemetry":true,"artifact_transfer":true,
 "guest_display":true, "workload":true, "inventory_admin":true,
}
func errf(code string) error { return errors.New("DENIED:"+code) }
func isPrivateLAN(s string) bool {
 ip,e:=netip.ParseAddr(s)
 return e==nil&&ip.IsValid()&&!ip.Is4In6()&&ip.IsPrivate()&&!ip.IsUnspecified()&&!ip.IsLoopback()&&!ip.IsMulticast()
}
func overlayIPInPrefixes(ipText string, prefixes []string) bool {
 ip,e:=netip.ParseAddr(ipText);if e!=nil||!ip.IsValid()||ip.Is4In6()||ip.IsUnspecified()||ip.IsLoopback(){return false}
 for _,s:=range prefixes {p,e:=netip.ParsePrefix(s);if e==nil && p.IsValid() && p.Contains(ip) {return true}}
 return false
}
func validLocalSocket(path string) bool {
 if !filepath.IsAbs(path)||strings.Contains(path,"..") {return false}
 clean:=filepath.Clean(path)
 return strings.HasPrefix(clean,"/run/wyse/")&&len(clean)>len("/run/wyse/")
}
func validRoles(roles []string, inventory bool) bool {
 if len(roles)==0{return false}
 seen:=map[string]bool{}
 for _,role:=range roles {
  if seen[role] {return false}; seen[role]=true
  switch role {case "owner","operator","agent","guest":default:return false}
  if inventory && role!="owner" {return false}
 }
 return true
}
// Compile refuses anything remotely ambiguous. Declared overlay "up" and a
// policy digest are NOT attestations; an independent integration must verify
// real interface addresses, live tailnet/Headscale grants and caller identity.
func Compile(p Plan) (Result,error) {
 out:=Result{Scope:"PLAN_ONLY_NO_ACTUATION_OR_NETWORK_AUTH",Listeners:[]Listener{}}
 if p.Version!=1 {return out,errf("VERSION")}
 if p.TrustProxyIdentityHeaders {return out,errf("PROXY_HEADER_IMPERSONATION")}
 seenServices:=map[string]bool{}
 used:=map[string]bool{}
 overlayUsed:=false
 for _,s:=range p.Services{
  if !known[s.Name]||!idRE.MatchString(s.Name)||seenServices[s.Name]{return out,errf("SERVICE_UNKNOWN_OR_DUPLICATE")}
  seenServices[s.Name]=true
  switch s.Mode {
  case "disabled":
   // Reject stale dangerous values rather than silently storing dormant
   // listener addresses, which could later be activated by a mode typo.
   if s.Port!=0||s.LANIP!=""||s.OverlayIP!=""||s.UnixSocket!=""||s.Auth!=""||len(s.Roles)!=0{
    return out,errf("DISABLED_SERVICE_HAS_DORMANT_EXPOSURE")
   }
   continue
  case "local","lan","overlay","both":
  default:return out,errf("MODE")
  }
  if s.Name=="inventory_admin" {
   if s.Mode!="local"||s.Port!=0||s.LANIP!=""||s.OverlayIP!=""||
    !validLocalSocket(s.UnixSocket)||s.Auth!="mtls"||!validRoles(s.Roles,true) {
    return out,errf("INVENTORY_MUST_STAY_PRIVATE_LOCAL_UNIX")
   }
   out.Listeners=append(out.Listeners,Listener{Service:s.Name,Network:"local_unix",Address:s.UnixSocket,Auth:s.Auth})
   continue
  }
  if s.Port<1||s.Port>65535||!validRoles(s.Roles,false) {return out,errf("PORT_OR_ROLES")}
  if s.Auth!="mtls"&&s.Auth!="oidc"&&s.Auth!="ssh_key" {
   if !(s.Name=="health"&&s.Mode=="local"&&s.Auth=="none"){return out,errf("AUTH_REQUIRED")}
  }
  if s.Mode=="local" {
   if s.LANIP!=""||s.OverlayIP!=""||s.UnixSocket!="" {return out,errf("LOCAL_MIXED_BIND")}
   addr:=net.JoinHostPort("127.0.0.1",fmt.Sprint(s.Port))
   key:="tcp:"+addr
   if used[key]{return out,errf("BIND_COLLISION")};used[key]=true
   out.Listeners=append(out.Listeners,Listener{Service:s.Name,Network:"local_tcp",Address:addr,Auth:s.Auth})
   continue
  }
  if s.UnixSocket!="" {return out,errf("NETWORK_UNIX_CONFUSION")}
  if s.Mode=="lan"||s.Mode=="both"{
   if !isPrivateLAN(s.LANIP){return out,errf("LAN_REQUIRES_LITERAL_PRIVATE_ADDRESS")}
   addr:=net.JoinHostPort(s.LANIP,fmt.Sprint(s.Port));key:="tcp:"+addr
   if used[key]{return out,errf("BIND_COLLISION")};used[key]=true
   out.Listeners=append(out.Listeners,Listener{Service:s.Name,Network:"lan_tcp",Address:addr,Auth:s.Auth})
  }else if s.LANIP!="" {return out,errf("UNUSED_LAN_BIND")}
  if s.Mode=="overlay"||s.Mode=="both" {
   overlayUsed=true
   if !overlayIPInPrefixes(s.OverlayIP,p.OverlayPrefixes){return out,errf("OVERLAY_BIND_OUTSIDE_EXPLICIT_PREFIX")}
   if s.OverlayIP==s.LANIP {return out,errf("ALIAS_LAN_OVERLAY_BIND")}
   addr:=net.JoinHostPort(s.OverlayIP,fmt.Sprint(s.Port));key:="tcp:"+addr
   if used[key]{return out,errf("BIND_COLLISION")};used[key]=true
   out.Listeners=append(out.Listeners,Listener{Service:s.Name,Network:"overlay_tcp",Address:addr,Auth:s.Auth})
  }else if s.OverlayIP!="" {return out,errf("UNUSED_OVERLAY_BIND")}
 }
 if overlayUsed {
  if p.OverlayProvider!="headscale"&&p.OverlayProvider!="tailscale" {return out,errf("OVERLAY_PROVIDER")}
  if !idRE.MatchString(p.OverlayInterface)||p.OverlayState!="observed_up"||!shaRE.MatchString(p.OverlayPolicySHA256){
   return out,errf("OVERLAY_DOWN_OR_UNVERIFIED_POLICY")
  }
  if len(p.OverlayPrefixes)==0 {return out,errf("OVERLAY_PREFIX_MISSING")}
  // Explicit per-operator policy configuration must still be proven live.
 }
 sort.Slice(out.Listeners,func(i,j int)bool{
  if out.Listeners[i].Service!=out.Listeners[j].Service{return out.Listeners[i].Service<out.Listeners[j].Service}
  return out.Listeners[i].Network<out.Listeners[j].Network
 })
 return out,nil
}

// PublicStatus is the ONLY allowed ordinary/tenant response shape. It does
// not report host inventory presence, candidate count, GPU/VFIO capability,
// privileged endpoint names or network/IP topology.
type PublicStatus struct {
 Health string `json:"health"`
 GuestID string `json:"guest_id,omitempty"`
}
func ProjectTenant(health,guestID string) PublicStatus {
 if health!="ready"{health="unavailable"}
 if len(guestID)>64||!idRE.MatchString(guestID){guestID=""}
 return PublicStatus{Health:health,GuestID:guestID}
}
