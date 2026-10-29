package main
import (
 "bytes"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

// This fixture was independently encoded in Python from synthetic PUBLIC bytes.
// It is not the private projector, an approved CCG decision or a release signer.
func TestMembraneSourceNeutralPythonVector(t *testing.T) {
 raw,e:=os.ReadFile("testdata/source-neutral-public-vector-v1.json")
 if e!=nil{t.Fatal(e)}
 var v struct {
  Schema string `json:"schema"`
  ScienceStatus string `json:"science_status"`
  Manifest ProjectionManifest `json:"manifest"`
  Contents map[string]string `json:"contents_base64"`
 }
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 if e=d.Decode(&v);e!=nil{t.Fatal(e)}
 if v.Schema!="public-projection-vector/v1"||v.ScienceStatus!="SYNTHETIC_ONLY_NOT_RELEASE_AUTHORITY"{
  t.Fatal("unexpected provenance/authority of synthetic vector")
 }
 const independentlyExpectedDigest="ad85714b560aea25183d00f93013c9c133a56e887297df89c3828c2ad7f6a4d3"
 if v.Manifest.CapsuleDigest!=independentlyExpectedDigest || len(v.Manifest.Files)!=3{
  t.Fatal("independent Python vector identity changed")
 }
 if independentlyEncodedFileSetDigest(v.Manifest.Files)!=independentlyExpectedDigest{
  t.Fatal("Go/Python public manifest byte digest mismatch")
 }
 root:=t.TempDir()
 for _,item:=range v.Manifest.Files {
  encoded,ok:=v.Contents[item.Path]
  if !ok{t.Fatalf("missing Python synthetic byte entry %q",item.Path)}
  content,e:=base64.StdEncoding.DecodeString(encoded);if e!=nil{t.Fatal(e)}
  digest:=sha256.Sum256(content)
  if item.Size!=int64(len(content))||item.SHA256!=hex.EncodeToString(digest[:]){
   t.Fatal("synthetic fixture file digest mismatch")
  }
  dest:=filepath.Join(root,item.Path)
  if e=os.MkdirAll(filepath.Dir(dest),0700);e!=nil{t.Fatal(e)}
  if e=os.WriteFile(dest,content,0600);e!=nil{t.Fatal(e)}
 }
 publicManifest,e:=json.Marshal(v.Manifest);if e!=nil{t.Fatal(e)}
 for _,field:=range []string{"source_ref","source_revision","source_path","source_content_digest","output_content_digest","projection_digest","private_repo"}{
  if bytes.Contains(publicManifest,[]byte(field)){t.Fatalf("private-side field leaked into public fixture: %s",field)}
 }
 seed:=sha256.Sum256([]byte("PUBLIC SYNTHETIC SOURCE-NEUTRAL TEST KEY ONLY"))
 signer:=ed25519.NewKeyFromSeed(seed[:]);pinned:=signer.Public().(ed25519.PublicKey)
 if e=verifyProjection(root,publicManifest,ed25519.Sign(signer,publicManifest),pinned);e!=nil{
  t.Fatalf("independent Python vector rejected by signed Go verifier: %v",e)
 }
 // Re-signing an otherwise valid byte set does not authorize extra metadata.
 changed:=strings.TrimSuffix(string(publicManifest),"}")+,"source_ref":"private/denied"}
 hostile:=[]byte(changed)
 if e=verifyProjection(root,hostile,ed25519.Sign(signer,hostile),pinned);e==nil{
  t.Fatal("signed private-provenance field accepted")
 }
}
