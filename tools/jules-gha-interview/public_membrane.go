package main

// Public-side independent verification of a *previously authorized* constructive
// projection. This code does not classify private source or grant declassification.
import (
 "bytes"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "io/fs"
 "os"
 "path/filepath"
 "regexp"
 "strconv"
 "strings"
)
const publicProjectionSchema = "public-projection-boundary/v1"
type ProjectionFile struct {
 Path string "json:\"path\""
 Class string "json:\"class\""
 SHA256 string "json:\"sha256\""
 Size int64 "json:\"size\""
}
type ProjectionManifest struct {
 Schema string "json:\"schema\""
 PolicyDigest string "json:\"policy_digest\""
 CapsuleDigest string "json:\"capsule_digest\""
 Files []ProjectionFile "json:\"files\""
}
var safeProjectionPath=regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]*$`)
var sha256Hex=regexp.MustCompile("^[a-f0-9]{64}$")

// Verify against the controller's independently configured, pinned trusted
// public key. NEVER accept a public key supplied by the candidate itself.
func verifyProjection(root string, rawManifest,signature []byte,pinnedKey ed25519.PublicKey)error{
 if len(pinnedKey)!=ed25519.PublicKeySize{return errors.New("missing pinned trusted key")}
 if len(rawManifest)==0||len(rawManifest)>65536||len(signature)!=ed25519.SignatureSize{return errors.New("invalid manifest/signature bounds")}
 if !ed25519.Verify(pinnedKey,rawManifest,signature){return errors.New("trusted release signature mismatch")}
 d:=json.NewDecoder(bytes.NewReader(rawManifest));d.DisallowUnknownFields()
 var m ProjectionManifest
 if e:=d.Decode(&m);e!=nil{return e}
 var extra any;if d.Decode(&extra)!=io.EOF{return errors.New("manifest trailing data")}
 if m.Schema!=publicProjectionSchema||!sha256Hex.MatchString(m.PolicyDigest)||!sha256Hex.MatchString(m.CapsuleDigest) {return errors.New("invalid manifest identity")}
 if len(m.Files)<1||len(m.Files)>128{return errors.New("invalid manifest file count")}
 allowed:=make(map[string]ProjectionFile,len(m.Files))
 var last string
 var total int64
 digest:=sha256.New()
 for i,f:=range m.Files {
  if !safeProjectionPath.MatchString(f.Path)||filepath.IsAbs(f.Path)||filepath.Clean(f.Path)!=f.Path||strings.Contains(f.Path,"\\")||strings.HasPrefix(f.Path,".")||strings.Contains("/"+f.Path+"/","/../")||strings.Contains("/"+f.Path+"/","/./")||strings.Contains("/"+f.Path+"/","/.git/")||f.Path==".git" {return fmt.Errorf("invalid public path item %d",i)}
  if i>0&&f.Path<=last{return errors.New("paths not sorted and unique")};last=f.Path
  if f.Class!="V0"&&f.Class!="V1"&&f.Class!="V4"{return errors.New("unapproved value class")}
  if !sha256Hex.MatchString(f.SHA256)||f.Size<0||f.Size>8<<20{return errors.New("invalid file digest or size")}
  total+=f.Size;if total>16<<20{return errors.New("projection exceeds size bound")}
  _,_=io.WriteString(digest,f.Path+"\x00"+f.Class+"\x00"+f.SHA256+"\x00"+strconv.FormatInt(f.Size,10)+"\n")
  allowed[f.Path]=f
 }
 if hex.EncodeToString(digest.Sum(nil))!=m.CapsuleDigest{return errors.New("capsule manifest digest mismatch")}
 seen:=map[string]bool{}
 err:=filepath.WalkDir(root,func(path string,entry fs.DirEntry,walkErr error)error{
  if walkErr!=nil{return walkErr}
  rel,e:=filepath.Rel(root,path);if e!=nil{return e};if rel=="."{return nil}
  rel=filepath.ToSlash(rel)
  if entry.Type()&os.ModeSymlink!=0{return errors.New("symlink in projection")}
  if entry.IsDir(){
   if rel==".git"||strings.HasPrefix(rel,".git/")||strings.HasPrefix(rel,".") {return errors.New("hidden/metadata directory")}
   expectedPrefix:=rel+"/"
   found:=false
   for listed:=range allowed{if strings.HasPrefix(listed,expectedPrefix){found=true;break}}
   if !found{return errors.New("unmanifested directory")}
   return nil
  }
  if !entry.Type().IsRegular(){return errors.New("non-regular projection entry")}
  expected,ok:=allowed[rel];if !ok{return errors.New("unmanifested output: "+rel)}
  finfo,e:=entry.Info();if e!=nil{return e};if finfo.Size()!=expected.Size{return errors.New("size mismatch: "+rel)}
  f,e:=os.Open(path);if e!=nil{return e};h:=sha256.New();n,copyErr:=io.Copy(h,io.LimitReader(f,expected.Size+1));closeErr:=f.Close()
  if copyErr!=nil{return copyErr};if closeErr!=nil{return closeErr}
  if n!=expected.Size||hex.EncodeToString(h.Sum(nil))!=expected.SHA256{return errors.New("content mismatch: "+rel)}
  seen[rel]=true;return nil
 })
 if err!=nil{return err}
 if len(seen)!=len(allowed){return errors.New("required public file missing")}
 return nil
}
