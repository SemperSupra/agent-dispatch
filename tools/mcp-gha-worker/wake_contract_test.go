package main

import (
	"os"
	"strings"
	"testing"
)

// Defense-in-depth source contract. Native GitHub Actions still makes the
// authoritative event permission decision at job evaluation time.
func TestWakeCommandIsLimitedToExactAuthenticatedPRComment(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/mcp-gha-worker.yml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	required := []string{
		"issue_comment:",
		"types: [created]",
		"github.event.issue.number == 553",
		"github.event.issue.pull_request != null",
		"github.event.comment.user.id == 1854350",
		"github.event.comment.body == '/mcp gha start smoke'",
		"github.event.comment.body == '/mcp gha start live'",
		"github.event.comment.body == '/mcp gha sweep pilot'",
		"vars.MCP_GHA_AGE_RECIPIENT",
		"name: MCP GHA Ephemeral MCP Worker",
		"github.event.comment.body == '/mcpgha start smoke'",
		"github.event.comment.body == '/mcpgha start live'",
		"format('comment-wake:{0}', github.event.comment.id)",
		"github.ref == 'refs/heads/main'",
		"environment: mcp-ephemeral-live",
		"LEASE_SECONDS: ${{ inputs.lease_seconds || '600' }}",
		"^tunnel_([a-z0-9]{32}|[a-z0-9]{4}_[a-z0-9]{32})$",
		"secrets.OPENAI_TUNNEL_RUNTIME_KEY",
		"secrets.OPENAI_GHA_MCP_TUNNEL_ID",
		"permissions:\n  contents: read",
		"cancel-in-progress: false",
	}
	for _, clause := range required {
		if !strings.Contains(s, clause) {
			t.Errorf("missing required wake restriction %q", clause)
		}
	}
	for _, forbidden := range []string{
		"pull_request_target:",
		"workflow_run:",
		"repository_dispatch:",
		"secrets.OPENAI_ADMIN_KEY",
		"permissions: write-all",
		"request-cancel:",
		"/mcp gha cancel ",
		"actions: write",
	} {
		if strings.Contains(s, forbidden) {
			t.Errorf("disallowed wake authority %q", forbidden)
		}
	}
}
