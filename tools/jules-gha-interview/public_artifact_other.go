//go:build !linux

package main

import "errors"

// The public synthetic artifact ingest is qualified only on hosted Linux.
// Do not silently fall back to path-based reads on other platforms.
func readPinnedArtifactJSON(_ string,_ int64)([]byte,error){
 return nil,errors.New("public pinned artifact ingress requires qualified Linux")
}
