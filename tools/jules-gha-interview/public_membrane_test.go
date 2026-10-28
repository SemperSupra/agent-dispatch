package main
import (
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)
func projectionFixture(t *testing.T)(string,[]byte,[]byte,ed25519.PublicKey,ed25519.PrivateKey){
 t.Helper()
 root:=t.TempDir()
 if e:=os.Mkdir(filepath.Join(root,"src"),0700);e!=nil{t.Fatal(e)}
 data:=[]byte("public synthetic source fixture\n")
 if e:=os.WriteFile(filepath.Join(root,"src","demo.txt"),data,0600);e!=nil{t.Fatal(e)}
 digest:=sha256.Sum256(data)
 m:=ProjectionManifest{Schema:publicProjectionSchema,PolicyDigest:strings.Repeat("a",64),
  CapsuleDigest:strings.Repeat("b",64),Files:[]ProjectionFile{{Path:"src/demo.txt",Class:"V1",SHA256:hex.EncodeToString(digest[:]),Size:int64(len(data))}}}
 b,e:=json.Marshal(m);if e!=nil{t.Fatal(e)}
 seed:=sha256.Sum256([]byte("PUBLIC SYNTHETIC NON-PRODUCTION SIGNER ONLY"))
 priv:=ed25519.NewKeyFromSeed(seed[:]);pub:=priv.Public().(ed25519.PublicKey)
 return root,b,ed25519.Sign(priv,b),pub,priv
}
func TestMembraneSyntheticSignedProjectionPass(t *testing.T){
 root,b,sig,pub,_:=projectionFixture(t)
 if e:=verifyProjection(root,b,sig,pub);e!=nil{t.Fatal(e)}
}
func TestMembraneRejectsTamperedSignatureAndOutput(t *testing.T){
 root,b,sig,pub,_:=projectionFixture(t)
 other:=append([]byte(nil),sig...);other[0]^=1
 if verifyProjection(root,b,other,pub)==nil{t.Fatal("forged signature accepted")}
 swapped:=append([]byte(nil),b...);swapped[4]^=1
 if verifyProjection(root,swapped,sig,pub)==nil{t.Fatal("tampered manifest accepted")}
 fakePub:=append([]byte(nil),pub...);fakePub[0]^=1
 if verifyProjection(root,b,sig,fakePub)==nil{t.Fatal("wrong trusted key accepted")}
 if e:=os.WriteFile(filepath.Join(root,"src","demo.txt"),[]byte("changed"),0600);e!=nil{t.Fatal(e)}
 if verifyProjection(root,b,sig,pub)==nil{t.Fatal("changed output accepted")}
}
func TestMembraneRejectsExtraMissingAndSymlink(t *testing.T){
 root,b,sig,pub,_:=projectionFixture(t)
 if e:=os.WriteFile(filepath.Join(root,"src","leak.txt"),[]byte("synthetic-restricted"),0600);e!=nil{t.Fatal(e)}
 if verifyProjection(root,b,sig,pub)==nil{t.Fatal("unmanifested output accepted")}
 if e:=os.Remove(filepath.Join(root,"src","leak.txt"));e!=nil{t.Fatal(e)}
 if e:=os.Symlink("demo.txt",filepath.Join(root,"src","link"));e!=nil{t.Fatal(e)}
 if verifyProjection(root,b,sig,pub)==nil{t.Fatal("symlink accepted")}
 if e:=os.Remove(filepath.Join(root,"src","link"));e!=nil{t.Fatal(e)}
 if e:=os.Remove(filepath.Join(root,"src","demo.txt"));e!=nil{t.Fatal(e)}
 if verifyProjection(root,b,sig,pub)==nil{t.Fatal("missing output accepted")}
}
func TestMembraneRejectsDeniedOrUnsafeClassesAndPaths(t *testing.T){
 root,_,_,pub,priv:=projectionFixture(t)
 original:=[]byte("public synthetic source fixture\n")
 hash:=sha256.Sum256(original)
 cases:=[]struct{name,path,class string}{
  {"denied-V2","src/demo.txt","V2"},
  {"denied-V3","src/demo.txt","V3"},
  {"unknown","src/demo.txt","UNKNOWN"},
  {"dotdot","../demo.txt","V1"},
  {"dot-segment","src/./demo.txt","V1"},
  {"metadata",".git/config","V1"},
  {"windows-escape","src\\demo.txt","V1"},
  {"absolute","/tmp/demo.txt","V1"},
  {"hidden",".hidden","V1"},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  m:=ProjectionManifest{Schema:publicProjectionSchema,PolicyDigest:strings.Repeat("a",64),
   CapsuleDigest:strings.Repeat("b",64),Files:[]ProjectionFile{{Path:tc.path,Class:tc.class,
    SHA256:hex.EncodeToString(hash[:]),Size:int64(len(original))}}}
  b,e:=json.Marshal(m);if e!=nil{t.Fatal(e)}
  if verifyProjection(root,b,ed25519.Sign(priv,b),pub)==nil{t.Fatal("unsafe signed manifest accepted")}
 })}
}
func TestMembraneRejectsDuplicateAndUnsorted(t *testing.T){
 root,b,_,pub,priv:=projectionFixture(t)
 var m ProjectionManifest
 if e:=json.Unmarshal(b,&m);e!=nil{t.Fatal(e)}
 for _,pair:=range [][]ProjectionFile{{m.Files[0],m.Files[0]},
 {{Path:"z.txt",Class:"V1",SHA256:strings.Repeat("0",64),Size:0},m.Files[0]}}{
  m.Files=pair;b,e:=json.Marshal(m);if e!=nil{t.Fatal(e)}
  if verifyProjection(root,b,ed25519.Sign(priv,b),pub)==nil{t.Fatal("duplicate/unsorted accepted")}
 }
}
func TestMembraneNoDeclassificationBySelfSignedCandidate(t *testing.T){
 root,b,_,_,_:=projectionFixture(t)
 // No trusted pinned key: candidate cannot authorize itself by bringing its own key.
 seed:=sha256.Sum256([]byte("ATTACKER SUPPLIED KEY"))
 priv:=ed25519.NewKeyFromSeed(seed[:])
 if verifyProjection(root,b,ed25519.Sign(priv,b),nil)==nil{t.Fatal("candidate key accepted")}
}
