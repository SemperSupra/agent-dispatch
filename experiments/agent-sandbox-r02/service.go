// Public synthetic fixture. The service runs as an unprivileged,
// no-network, disposable container with read-only image and tmpfs state.
package main

import (
 "crypto/rand"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "net/http"
 "os"
 "strings"
 "time"
)

const (
 baseURL = "http://127.0.0.1:18081"
 marker = "PUBLIC_SYNTHETIC_EPHEMERAL_ONLY"
 markerPath = "/tmp/marker"
 instancePath = "/tmp/instance-id"
)

func request(method, path, payload string) (int, string, error) {
 client := &http.Client{Timeout: 2 * time.Second}
 req, err := http.NewRequest(method, baseURL+path, strings.NewReader(payload))
 if err != nil { return 0, "", err }
 resp, err := client.Do(req)
 if err != nil { return 0, "", err }
 defer resp.Body.Close()
 b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
 return resp.StatusCode, string(b), err
}

func probe(op string) error {
 status, _, err := request("GET", "/health", "")
 if err != nil || status != http.StatusOK { return fmt.Errorf("health not ready: status=%d err=%v", status, err) }
 switch op {
 case "empty":
  status, _, err = request("GET", "/state", "")
  if err != nil || status != http.StatusNotFound { return fmt.Errorf("expected empty state: status=%d err=%v", status, err) }
  fmt.Println("R02_NEW_DISPOSABLE_STATE_EMPTY=PASS")
 case "mark":
  status, _, err = request("POST", "/state", marker)
  if err != nil || status != http.StatusNoContent { return fmt.Errorf("mark write: status=%d err=%v", status, err) }
  status, body, err := request("GET", "/state", "")
  if err != nil || status != http.StatusOK || body != marker { return fmt.Errorf("mark readback: status=%d err=%v", status, err) }
  fmt.Println("R02_EPHEMERAL_MARKER_READBACK=PASS")
 case "id":
  status, body, err := request("GET", "/instance", "")
  if err != nil || status != http.StatusOK || len(strings.TrimSpace(body)) != 32 { return fmt.Errorf("instance not usable: status=%d err=%v", status, err) }
  fmt.Println(strings.TrimSpace(body))
 case "readonly":
  if err := os.WriteFile("/illegal-root-write", []byte(marker), 0600); err == nil { return errors.New("immutable root unexpectedly writable") }
  fmt.Println("R02_READONLY_ROOT_WRITE_DENIED=PASS")
 default:
  return fmt.Errorf("unknown probe %q", op)
 }
 return nil
}

func serve() error {
 var id [16]byte
 if _, err := rand.Read(id[:]); err != nil { return err }
 if err := os.WriteFile(instancePath, []byte(hex.EncodeToString(id[:])), 0600); err != nil { return err }
 mux := http.NewServeMux()
 mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
  if r.Method != "GET" { http.Error(w,"method",405); return }
  _, _ = w.Write([]byte("ok"))
 })
 mux.HandleFunc("/instance", func(w http.ResponseWriter, r *http.Request) {
  if r.Method != "GET" { http.Error(w,"method",405); return }
  b, err := os.ReadFile(instancePath)
  if err != nil { http.Error(w,"unavailable",500); return }
  _, _ = w.Write(b)
 })
 mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
  switch r.Method {
  case "GET":
   b, err := os.ReadFile(markerPath)
   if errors.Is(err, os.ErrNotExist) { http.NotFound(w,r); return }
   if err != nil { http.Error(w,"read failure",500); return }
   _, _ = w.Write(b)
  case "POST":
   b, err := io.ReadAll(io.LimitReader(r.Body,128))
   if err != nil || string(b) != marker { http.Error(w,"invalid fixture",400); return }
   if err := os.WriteFile(markerPath, b, 0600); err != nil { http.Error(w,"write failure",500); return }
   w.WriteHeader(http.StatusNoContent)
  default:
   http.Error(w,"method",405)
  }
 })
 return http.ListenAndServe("127.0.0.1:18081", mux)
}

func main() {
 var err error
 if len(os.Args) == 3 && os.Args[1] == "probe" { err = probe(os.Args[2]) } else if len(os.Args) == 1 { err = serve() } else { err = errors.New("usage: service [probe empty|mark|id|readonly]") }
 if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}
