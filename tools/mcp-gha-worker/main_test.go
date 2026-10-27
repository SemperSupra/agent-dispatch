package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func do(t *testing.T, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	handler().ServeHTTP(w, req)
	result := map[string]any{}
	if strings.Contains(w.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
	}
	return w, result
}

func TestReadOnlyMCPHandshakeAndCanary(t *testing.T) {
	_, init := do(t, "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	if init["error"] != nil {
		t.Fatalf("initialize: %v", init)
	}
	result := init["result"].(map[string]any)
	if result["protocolVersion"] != "2025-06-18" {
		t.Fatalf("protocol version: %v", result)
	}
	_, tools := do(t, "POST", "/mcp", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	listed := tools["result"].(map[string]any)["tools"].([]any)
	if len(listed) != 2 || listed[0].(map[string]any)["name"] != "worker_ping" || listed[1].(map[string]any)["name"] != "worker_describe" {
		t.Fatalf("tools: %v", listed)
	}
	_, call := do(t, "POST", "/mcp", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"worker_ping","arguments":{}}}`)
	if call["error"] != nil {
		t.Fatalf("canary error: %v", call)
	}
	text := call["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"]
	if text != "PUBLIC_SYNTHETIC_MCP_WORKER_OK" {
		t.Fatalf("unexpected: %v", text)
	}
}

func TestDenyUnboundedOperations(t *testing.T) {
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"worker_ping","arguments":{"command":"sh"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"worker_ping","arguments":[1]}}`,
	} {
		_, v := do(t, "POST", "/mcp", body)
		if v["error"] == nil {
			t.Fatalf("call accepted: %s", body)
		}
	}
}

func TestRequestAndTransportBounds(t *testing.T) {
	if w, _ := do(t, "GET", "/mcp", ""); w.Code != 405 {
		t.Fatal(w.Code)
	}
	if w, _ := do(t, "POST", "/mcp", `{bad`); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w, _ := do(t, "POST", "/mcp", strings.Repeat("x", maxBody+2)); w.Code != 413 {
		t.Fatal(w.Code)
	}
	if w, _ := do(t, "POST", "/mcp", `{"jsonrpc":"2.0","method":"notifications/initialized"}`); w.Code != 202 {
		t.Fatal(w.Code)
	}
	if w, _ := do(t, "GET", "/healthz", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
}

func TestLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:1", ":1", "10.1.2.3:1", "example.com:1"} {
		if validateListen(addr) == nil {
			t.Fatalf("accepted %s", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:18765", "[::1]:18765"} {
		if err := validateListen(addr); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMCPNativeDescriptionPreservesCustodyAndAudienceBoundaries(t *testing.T) {
	_, call := do(t, "POST", "/mcp", `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"worker_describe","arguments":{}}}`)
	if call["error"] != nil {
		t.Fatalf("worker_describe rejected: %+v", call)
	}
	body := call["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	var description map[string]any
	if err := json.Unmarshal([]byte(body), &description); err != nil {
		t.Fatal(err)
	}
	if description["schema"] != "mcp-gha-worker-discovery/v1" {
		t.Fatal(description)
	}
	audience := description["audiences"].([]any)
	if len(audience) != 3 || audience[0] != "human" || audience[1] != "automation" || audience[2] != "agent" {
		t.Fatal(audience)
	}
	if description["research_evidence"] != "NOT_VALIDATED" {
		t.Fatal("unearned semantic acceptance")
	}
	if !strings.Contains(description["cancel"].(string), "GitHub Actions") {
		t.Fatal("inaccurate cancellation control")
	}
}
