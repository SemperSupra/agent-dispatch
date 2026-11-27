package journal

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "io"
)

// ArtifactRef identifies a producer-scoped occurrence, not just equal content.
// SHA256 binds the bytes; Occurrence distinguishes copies and repeated captures.
type ArtifactRef struct {
 Scope Scope `json:"scope"`
 Occurrence string `json:"occurrence"`
 SHA256 string `json:"sha256"`
 Size U64 `json:"size"`
}

type EvidenceRange struct {
 Artifact ArtifactRef `json:"artifact"`
 Offset U64 `json:"offset"`
 Length U64 `json:"length"`
}

// ValidateRange checks an immutable artifact locator, not its semantics.
func ValidateRange(r EvidenceRange) error {
 a:=r.Artifact
 if !validScope(a.Scope)||!validID(a.Occurrence)||!validSHA(a.SHA256) {return errors.New("invalid artifact reference")}
 if r.Length==0||r.Offset>a.Size||r.Length>a.Size-r.Offset {return errors.New("invalid evidence extent")}
 return nil
}

const MaxSourceBytes = 64 << 20

// VerifyArtifact reads at most MaxSourceBytes+1 bytes from the supplied stream.
// A successful match proves byte equality with the declared digest only.
func VerifyArtifact(src io.Reader, declared string) (U64,error) {
 if !validSHA(declared) {return 0,errors.New("invalid declared digest")}
 h:=sha256.New()
 n,e:=io.Copy(h,io.LimitReader(src,MaxSourceBytes+1))
 if e!=nil{return 0,e}
 if n>MaxSourceBytes{return 0,errors.New("source exceeds verification limit")}
 if hex.EncodeToString(h.Sum(nil))!=declared{return 0,errors.New("source digest mismatch")}
 return U64(n),nil
}
