// A read-only, public-safe MCP canary for disposable GitHub Actions workers.
// It has no code execution, filesystem or private-repository access.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	name    = "gha-mcp-worker-canary"
	version = "0.1.0"
	maxBody = 65536
)

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func failure(id json.RawMessage, code int, msg string) response {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

func parseEmptyObject(b json.RawMessage) bool {
	if len(b) == 0 || string(b) == "null" {
		return true
	}
	var x map[string]json.RawMessage
	if err := json.Unmarshal(b, &x); err != nil {
		return false
	}
	return len(x) == 0
}

func dispatch(req request) response {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		selected := "2025-06-18"
		switch p.ProtocolVersion {
		case "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25":
			selected = p.ProtocolVersion
		}
		return response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
			"protocolVersion": selected,
			"serverInfo":      map[string]string{"name": name, "version": version},
			"capabilities":    map[string]any{"tools": map[string]bool{"listChanged": false}},
		}}
	case "ping":
		return response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}}
	case "tools/list":
		return response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": []any{map[string]any{
			"name":        "worker_ping",
			"description": "Read-only public synthetic liveness check. Never accesses runner data or executes commands.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false},
		}}}}
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name != "worker_ping" || !parseEmptyObject(p.Arguments) {
			return failure(req.ID, -32602, "Unknown tool or invalid arguments")
		}
		return response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"content": []any{
			map[string]string{"type": "text", "text": "PUBLIC_SYNTHETIC_MCP_WORKER_OK"},
		}, "isError": false}}
	default:
		return failure(req.ID, -32601, "Method not found")
	}
}

func handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","kind":"public-synthetic"}`)
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.Header().Set("Allow", "POST")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "Unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Request too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		var req request
		if err := json.Unmarshal(data, &req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(failure(nil, -32700, "Parse error"))
			return
		}
		if req.JSONRPC != "2.0" || req.Method == "" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(failure(req.ID, -32600, "Invalid request"))
			return
		}
		if len(req.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(dispatch(req))
	})
	return mux
}

func validateListen(s string) error {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("MCP worker must bind a literal loopback IP")
	}
	return nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:18765", "loopback-only HTTP bind")
	flag.Parse()
	if err := validateListen(*listen); err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: *listen, Handler: handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 20 * time.Second}
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-done
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
