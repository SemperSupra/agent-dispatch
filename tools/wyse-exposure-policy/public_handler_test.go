package exposure

import (
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)
func TestRemoteRouteCannotDiscoverHostDeviceInventory(t *testing.T){
 h:=NewTenantStatusHandler("ready","guest_001")
 forbidden:=[]string{
  "/v1/hosts","/v1/host-devices","/v1/inventory",
  "/v1/passthrough","/v1/candidates","/v1/gpu",
  "/v1/usb","/v1/vfio","/v1/iommu",
  "/metrics","/debug/vars","/openapi.json","/v1/events",
 }
 var baseline string
 for _,path:=range forbidden{
  r:=httptest.NewRequest(http.MethodGet,"http://example.invalid"+path,nil)
  r.Header.Set("Tailscale-User-Login","forged-owner@example.invalid")
  r.Header.Set("Tailscale-App-Capabilities",`{"role":"owner"}`)
  r.Header.Set("X-Forwarded-For","127.0.0.1")
  r.Header.Set("X-Remote-User","owner")
  rec:=httptest.NewRecorder()
  h.ServeHTTP(rec,r)
  if rec.Code!=http.StatusNotFound{t.Fatalf("route leaked: %s status %d",path,rec.Code)}
  if baseline==""{baseline=rec.Body.String()}
  if rec.Body.String()!=baseline{t.Fatalf("response variation is an existence oracle: %s",path)}
  if !strings.Contains(rec.Header().Get("Cache-Control"),"no-store"){t.Fatal("sensitive route cacheable")}
 }
 r:=httptest.NewRequest(http.MethodGet,"http://example.invalid/v1/status",nil)
 rec:=httptest.NewRecorder();h.ServeHTTP(rec,r)
 if rec.Code!=http.StatusOK{t.Fatal("ordinary guest status unavailable")}
 b:=rec.Body.String()
 for _,s:=range []string{
  "inventory","passthrough","pci","vfio","iommu","gpu",
  "mdev","count","serial","tailscale","headscale","device",
  "100.101","192.168", "renderD","0000:00:",
 }{
  if strings.Contains(strings.ToLower(b),strings.ToLower(s)) {t.Fatalf("host fact escaped status: %s",s)}
 }
 if !strings.Contains(b,`"health":"ready"`){t.Fatal("status not useful")}
}
func TestDeniedMethodAndHTTPUpgradeDoNotRevealCapabilities(t *testing.T){
 h:=NewTenantStatusHandler("ready","guest_001")
 for _,m:=range []string{"HEAD","POST","OPTIONS","PUT","DELETE"}{
  r:=httptest.NewRequest(m,"http://example.invalid/v1/status",nil)
  r.Header.Set("Upgrade","websocket")
  w:=httptest.NewRecorder();h.ServeHTTP(w,r)
  if w.Code!=http.StatusNotFound{t.Fatalf("unexpected route for %s",m)}
 }
}
