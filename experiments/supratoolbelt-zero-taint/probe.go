package main

// Disposable source: its build and all generated output MUST stay inside tmpfs
// within an ephemeral OCI execution cell. No writable host bind permitted.
import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	data, err := os.ReadFile("/src/spec.txt")
	if err != nil { panic(err) }
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	if err := os.MkdirAll("/work/generated", 0700); err != nil { panic(err) }
	out := filepath.Join("/work/generated", "receipt.txt")
	if err := os.WriteFile(out, []byte(digest+"\n"), 0600); err != nil { panic(err) }
	fmt.Printf("M1_ZERO_TAINT_BUILD_OK sha256=%s\n", digest)
}
