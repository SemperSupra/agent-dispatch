// Command wyse-release-guard checks a synthetic JSON release transition.
// No network, signing, secrets, boot actions or hardware access.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	releaseguard "example.com/wyse-release-guard"
)

// scanJSON detects duplicate keys at every object depth before the ordinary
// decoder can silently replace an earlier security-critical field. Limit the
// nesting depth to keep the preflight bounded on untrusted input.
func scanJSON(d *json.Decoder, depth int) error {
	if depth > 64 { return fmt.Errorf("JSON depth exceeded") }
	t, err := d.Token()
	if err != nil { return err }
	delim, ok := t.(json.Delim)
	if !ok { return nil }
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for d.More() {
			k, err := d.Token()
			if err != nil { return err }
			key, ok := k.(string)
			if !ok || seen[key] { return fmt.Errorf("duplicate or invalid object key") }
			seen[key] = true
			if err := scanJSON(d, depth+1); err != nil { return err }
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') { return fmt.Errorf("malformed object end") }
	case '[':
		for d.More() {
			if err := scanJSON(d, depth+1); err != nil { return err }
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') { return fmt.Errorf("malformed array end") }
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSON(d, 0); err != nil { return err }
	var extra any
	if err := d.Decode(&extra); err != io.EOF { return fmt.Errorf("trailing JSON") }
	return nil
}

func main() {
	buf, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20+1))
	if err != nil || len(buf) > 1<<20 {
		fmt.Fprintln(os.Stderr, "R42_RELEASE_GUARD=DENIED:INPUT_LIMIT")
		os.Exit(2)
	}
	if err := rejectDuplicateKeys(buf); err != nil {
		fmt.Fprintln(os.Stderr, "R42_RELEASE_GUARD=DENIED:DUPLICATE_OR_MALFORMED_JSON")
		os.Exit(2)
	}
	dec := json.NewDecoder(bytes.NewReader(buf))
	dec.DisallowUnknownFields()
	var m releaseguard.Manifest
	if err := dec.Decode(&m); err != nil {
		fmt.Fprintln(os.Stderr, "R42_RELEASE_GUARD=DENIED:INVALID_JSON_SCHEMA")
		os.Exit(2)
	}
	var more any
	if err := dec.Decode(&more); err != io.EOF {
		fmt.Fprintln(os.Stderr, "R42_RELEASE_GUARD=DENIED:TRAILING_JSON")
		os.Exit(2)
	}
	if err := releaseguard.Validate(m); err != nil {
		fmt.Fprintln(os.Stderr, "R42_RELEASE_GUARD="+err.Error())
		os.Exit(1)
	}
	fmt.Println(releaseguard.Verdict(m))
}
