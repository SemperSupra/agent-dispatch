package main

// Public Go JSON decoder behavior oracle for ambiguous field spellings.
// Fictional-only data. This file is NOT private admission product source.
import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"unicode"
)

type fictionalRecord struct {
	ClientID string `json:"client_id"`
}

// Demonstrate why exact-string duplicate checks are not sufficient when
// encoding/json resolves Go struct fields case-insensitively.
func TestNativeDecoderCaseAliasLastMemberWitness(t *testing.T) {
	raw := []byte(`{"client_id":"fictional-first","CLIENT_ID":"fictional-second"}`)
	var v fictionalRecord
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.ClientID != "fictional-second" {
		t.Fatalf("fixture expected last case-alias member, got %q", v.ClientID)
	}
}

func canonicalSyntheticJSONKey(s string) string {
	return strings.Map(func(r rune) rune {
		min := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < min {
				min = next
			}
		}
		return min
	}, s)
}

// A reference pre-decode guard. Go's native JSON token walker traverses each
// object, including nested objects. This only models the required semantic
// invariant; it does not test a private product or signed authority.
func syntheticUniqueMembers(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var consume func(depth int) error
	consume = func(depth int) error {
		if depth > 32 {
			return errors.New("depth limit")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		mark, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch mark {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				next, err := d.Token()
				if err != nil {
					return err
				}
				field, ok := next.(string)
				if !ok {
					return errors.New("invalid object field")
				}
				key := canonicalSyntheticJSONKey(field)
				if seen[key] {
					return errors.New("ambiguous aliases")
				}
				seen[key] = true
				if err := consume(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case '[':
			for d.More() {
				if err := consume(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		default:
			return errors.New("invalid token")
		}
	}
	if err := consume(0); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

func TestSyntheticUniqueMembersRejectLogicalDuplicateAliases(t *testing.T) {
	invalid := map[string]string{
		"top": `{"client_id":"first","CLIENT_ID":"other"}`,
		"nested": `{"metadata":{"phase":"HOLD","PHASE":"EFFECTIVE"}}`,
		"unicode": `{"size":1,"ſize":2}`,
		"array": `{"clients":[{"id":1,"ID":2}]}`,
		"exact": `{"id":1,"id":2}`,
		"trailing": `{"id":1}{"id":2}`,
	}
	for name, raw := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := syntheticUniqueMembers([]byte(raw)); err == nil {
				t.Fatal("ambiguous fictional JSON was admitted")
			}
		})
	}
	for name, raw := range map[string]string{
		"distinct": `{"id":1,"alias":2}`,
		"separate_objects": `{"entries":[{"id":1},{"id":2}]}`,
		"nested": `{"meta":{"id":1},"id":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := syntheticUniqueMembers([]byte(raw)); err != nil {
				t.Fatalf("unambiguous fictional JSON rejected: %v", err)
			}
		})
	}
}


// This public fixture captures the API-contract hazard of deriving an
// approved request digest from two different JSON serializations. No private
// request, authorization, or production source is imported.
func TestFictionalCrossLanguageRequestBytesAreNotInterchangeable(t *testing.T) {
	type fictionalAdmission struct {
		Ref        string `json:"workset_ref"`
		Delegation string `json:"delegation"`
		Class      string `json:"caller_class"`
	}
	type fictionalRequest struct {
		ClientID  string             `json:"client_id"`
		Mode      string             `json:"mode"`
		Admission fictionalAdmission `json:"admission"`
	}
	request := fictionalRequest{
		ClientID: "fictional-test", Mode: "revoke",
		Admission: fictionalAdmission{Ref: "fictional-ref", Delegation: "observe", Class: "observe"},
	}
	goStructBytes, err := json.Marshal(request)
	if err != nil { t.Fatal(err) }
	// Python json.dumps(value,sort_keys=True,separators=(",",":")).
	pythonSortedBytes := []byte(`{"admission":{"caller_class":"observe","delegation":"observe","workset_ref":"fictional-ref"},"client_id":"fictional-test","mode":"revoke"}`)
	pyDigest := sha256.Sum256(pythonSortedBytes)
	goDigest := sha256.Sum256(goStructBytes)
	if goDigest == pyDigest {
		t.Fatal("fixture lost intentional cross-language encoding difference")
	}
	// A verifier using the wrong canonical encoding fails a legitimate call.
	if bytes.Equal(goStructBytes, pythonSortedBytes) {
		t.Fatal("struct and sorted encodings unexpectedly identical")
	}
	// Map-based Go encoding matches the sorted JSON for this ASCII-only
	// fictional specimen, demonstrating a possible shared contract, NOT
	// proving a stable production canonicalization specification.
	m := map[string]any{
		"client_id": "fictional-test", "mode": "revoke",
		"admission": map[string]any{"workset_ref": "fictional-ref", "delegation": "observe", "caller_class": "observe"},
	}
	sortedMapBytes, err := json.Marshal(m)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(sortedMapBytes, pythonSortedBytes) {
		t.Fatal("synthetic shared ASCII encoding contract mismatch")
	}
	if got := sha256.Sum256(sortedMapBytes); got != pyDigest {
		t.Fatal("synthetic canonical intent digest mismatch")
	}
}
