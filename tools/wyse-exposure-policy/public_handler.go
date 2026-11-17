package exposure

import (
 "encoding/json"
 "net/http"
)
// NewTenantStatusHandler exposes ONE sanitised synthetic status endpoint.
// There is intentionally no admin or inventory route in this handler.
// An actual production server must independently enforce authentication,
// network ACLs, token audience and rate limits BEFORE calling this handler.
func NewTenantStatusHandler(health, guestID string) http.Handler {
 safe:=ProjectTenant(health,guestID)
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Cache-Control","no-store")
  w.Header().Set("X-Content-Type-Options","nosniff")
  w.Header().Set("Content-Security-Policy","default-src 'none'")
  if r.URL.Path!="/v1/status" || r.Method!=http.MethodGet {
   // The 404 body is independent of inventory content and caller-provided
   // Tailscale/Headscale identity headers. No capability-existence oracle.
   http.NotFound(w,r)
   return
  }
  w.Header().Set("Content-Type","application/json")
  w.WriteHeader(http.StatusOK)
  _=json.NewEncoder(w).Encode(safe)
 })
}
