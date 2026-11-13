package main

// Public Go JSON decoder behavior oracle for ambiguous field spellings.
// Fictional-only data. This file is NOT private admission product source.
import (
	"bytes"
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
