package main

import (
	"path"
	"strings"
	"testing"
)

// ValidatePublicationCandidatePath enforces fail-closed path safety before any
// public or free-tier model projection (#830 / #833):
// 1. Path must be relative, non-empty, and clean (no ".." traversal, leading "/", or Windows "\").
// 2. Reserved control/custody/secret prefixes (.git, .github, custody, secrets, private) are denied.
// 3. Symlink or gitlink modes ("120000", "160000") are denied; only regular file modes ("100644", "100755") are allowed.
func ValidatePublicationCandidatePath(relPath string, gitMode string, approvedRoots []string) string {
	if strings.TrimSpace(relPath) == "" {
		return "HOLD_EMPTY_PATH"
	}
	if strings.Contains(relPath, "\\") || strings.HasPrefix(relPath, "/") {
		return "HOLD_NON_RELATIVE_OR_BACKSLASH_PATH"
	}
	parts := strings.Split(relPath, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return "HOLD_PATH_TRAVERSAL_OR_UNCLEAN_SEGMENT"
		}
	}
	cleaned := path.Clean(relPath)
	if cleaned != relPath {
		return "HOLD_UNCLEAN_PATH"
	}
	first := parts[0]
	if first == ".git" || first == ".github" || first == "custody" || first == "secrets" || strings.HasSuffix(first, "-private") {
		return "HOLD_RESERVED_OR_PRIVATE_ROOT"
	}
	if gitMode == "120000" {
		return "HOLD_SYMLINK_IN_RELEASE_ROOT"
	}
	if gitMode == "160000" {
		return "HOLD_GITLINK_IN_RELEASE_ROOT"
	}
	if gitMode != "100644" && gitMode != "100755" {
		return "HOLD_UNSUPPORTED_GIT_MODE"
	}
	approved := false
	for _, root := range approvedRoots {
		if relPath == root || strings.HasPrefix(relPath, strings.TrimSuffix(root, "/")+"/") {
			approved = true
			break
		}
	}
	if !approved {
		return "HOLD_UNCLASSIFIED_RELEASE_PATH"
	}
	return "PUBLICATION_PATH_ADMISSIBLE"
}

// ReleaseTreeEntry represents a file in an exact Git tree candidate for R0/R1 value-separated release (#623).
type ReleaseTreeEntry struct {
	Path       string
	Mode       string
	BlobSHA256 string
	Tier       string // "R0_PUBLIC_PRODUCT", "R1_PUBLIC_HARNESS", "R2_PRIVATE_EXAM", ""
}

// VerifyValueSeparatedReleaseTree enforces R0/R1 value-separated release invariants:
// 1. Every entry in the candidate release tree must have a non-empty 64-hex BlobSHA256 and unique path.
// 2. No R2_PRIVATE_EXAM or unclassified ("") entry may appear in a public projection.
// 3. Every path must pass ValidatePublicationCandidatePath under the declared public roots.
func VerifyValueSeparatedReleaseTree(entries []ReleaseTreeEntry, publicRoots []string) string {
	if len(entries) == 0 {
		return "HOLD_EMPTY_RELEASE_TREE"
	}
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if seen[e.Path] {
			return "HOLD_DUPLICATE_TREE_PATH"
		}
		seen[e.Path] = true
		if len(e.BlobSHA256) != 64 {
			return "HOLD_INVALID_BLOB_DIGEST"
		}
		if e.Tier == "R2_PRIVATE_EXAM" {
			return "HOLD_PRIVATE_EXAM_LEAK_BLOCKED"
		}
		if e.Tier != "R0_PUBLIC_PRODUCT" && e.Tier != "R1_PUBLIC_HARNESS" {
			return "HOLD_UNCLASSIFIED_PRODUCT_FILE"
		}
		if verdict := ValidatePublicationCandidatePath(e.Path, e.Mode, publicRoots); verdict != "PUBLICATION_PATH_ADMISSIBLE" {
			return verdict
		}
	}
	return "VALUE_SEPARATED_TREE_VERIFIED"
}

func TestPublicationPathSafetyOracle(t *testing.T) {
	roots := []string{"tools/mcp-gha-control", "docs/public"}

	if got := ValidatePublicationCandidatePath("tools/mcp-gha-control/main.go", "100644", roots); got != "PUBLICATION_PATH_ADMISSIBLE" {
		t.Fatalf("expected PUBLICATION_PATH_ADMISSIBLE, got %s", got)
	}

	cases := []struct {
		path string
		mode string
		want string
	}{
		{"../secrets/token.json", "100644", "HOLD_PATH_TRAVERSAL_OR_UNCLEAN_SEGMENT"},
		{"/etc/passwd", "100644", "HOLD_NON_RELATIVE_OR_BACKSLASH_PATH"},
		{"tools\\mcp-gha-control\\main.go", "100644", "HOLD_NON_RELATIVE_OR_BACKSLASH_PATH"},
		{"custody/mcp_tokens.json", "100644", "HOLD_RESERVED_OR_PRIVATE_ROOT"},
		{"tools/mcp-gha-control/link.go", "120000", "HOLD_SYMLINK_IN_RELEASE_ROOT"},
		{"tools/mcp-gha-control/submodule", "160000", "HOLD_GITLINK_IN_RELEASE_ROOT"},
		{"unlisted/file.go", "100644", "HOLD_UNCLASSIFIED_RELEASE_PATH"},
	}

	for _, tc := range cases {
		if got := ValidatePublicationCandidatePath(tc.path, tc.mode, roots); got != tc.want {
			t.Fatalf("path=%q mode=%q: expected %s, got %s", tc.path, tc.mode, tc.want, got)
		}
	}
}

func TestValueSeparatedReleaseTreeOracle(t *testing.T) {
	roots := []string{"tools/mcp-gha-control", "tests/public"}
	validDigest := strings.Repeat("a", 64)

	validTree := []ReleaseTreeEntry{
		{Path: "tools/mcp-gha-control/main.go", Mode: "100644", BlobSHA256: validDigest, Tier: "R0_PUBLIC_PRODUCT"},
		{Path: "tests/public/smoke_test.go", Mode: "100644", BlobSHA256: validDigest, Tier: "R1_PUBLIC_HARNESS"},
	}

	if got := VerifyValueSeparatedReleaseTree(validTree, roots); got != "VALUE_SEPARATED_TREE_VERIFIED" {
		t.Fatalf("expected VALUE_SEPARATED_TREE_VERIFIED, got %s", got)
	}

	// Held-out private exam file must fail closed
	withPrivateExam := append([]ReleaseTreeEntry{}, validTree...)
	withPrivateExam = append(withPrivateExam, ReleaseTreeEntry{
		Path: "tests/public/held_out_exam.go", Mode: "100644", BlobSHA256: validDigest, Tier: "R2_PRIVATE_EXAM",
	})
	if got := VerifyValueSeparatedReleaseTree(withPrivateExam, roots); got != "HOLD_PRIVATE_EXAM_LEAK_BLOCKED" {
		t.Fatalf("expected HOLD_PRIVATE_EXAM_LEAK_BLOCKED, got %s", got)
	}

	// Unclassified file must fail closed
	withUnclassified := append([]ReleaseTreeEntry{}, validTree...)
	withUnclassified = append(withUnclassified, ReleaseTreeEntry{
		Path: "tools/mcp-gha-control/new_unclassified.go", Mode: "100644", BlobSHA256: validDigest, Tier: "",
	})
	if got := VerifyValueSeparatedReleaseTree(withUnclassified, roots); got != "HOLD_UNCLASSIFIED_PRODUCT_FILE" {
		t.Fatalf("expected HOLD_UNCLASSIFIED_PRODUCT_FILE, got %s", got)
	}

	// Duplicate path must fail closed
	withDuplicate := append([]ReleaseTreeEntry{}, validTree...)
	withDuplicate = append(withDuplicate, validTree[0])
	if got := VerifyValueSeparatedReleaseTree(withDuplicate, roots); got != "HOLD_DUPLICATE_TREE_PATH" {
		t.Fatalf("expected HOLD_DUPLICATE_TREE_PATH, got %s", got)
	}
}
