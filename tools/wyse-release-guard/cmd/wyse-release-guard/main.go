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

func main() {
	buf, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20+1))
	if err != nil || len(buf) > 1<<20 {
		fmt.Fprintln(os.Stderr, "R42_RELEASE_GUARD=DENIED:INPUT_LIMIT")
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
