package main

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "os"
 "path/filepath"
)

type PairStage struct {
 AssignmentID string
 RunID string
 State string
}
func hashRegularFile(path string)(string,error){
 f,info,err:=openPinnedRegular(path,maxCiphertext+32768)
 if err!=nil{return "",err}
 defer f.Close()
 h:=sha256.New()
 if _,err=copyPinnedBytes(h,f,info);err!=nil{return "",err}
 if err=pinnedFileUnchanged(path,f,info);err!=nil{return "",err}
 return hex.EncodeToString(h.Sum(nil)),nil
}
func exactStageLayout(root string)error{
 expected:=map[string]bool{"manifest.json":true,"reference":true,"cpe":true}
 entries,err:=os.ReadDir(root);if err!=nil{return err}
 if len(entries)!=len(expected){return errors.New("unexpected staged top-level files")}
 for _,e:=range entries{
  if !expected[e.Name()]{return errors.New("unrecognized staged file")}
 }
 for _,arm:=range []string{"reference","cpe"}{
  path:=filepath.Join(root,arm)
  stat,err:=os.Lstat(path);if err!=nil{return err}
  if !stat.IsDir()||stat.Mode()&os.ModeSymlink!=0{return errors.New("arm is not a real directory")}
  sub,err:=os.ReadDir(path);if err!=nil{return err}
  if len(sub)!=2{return errors.New("unexpected arm file count")}
  for _,e:=range sub{
   if e.Name()!="result.age"&&e.Name()!="receipt.json"{return errors.New("unexpected arm data")}
  }
 }
 return nil
}
func syncStageDir(dir string)error{
 d,err:=os.Open(dir);if err!=nil{return err}
 defer d.Close()
 return d.Sync()
}
func comparePairFiles(manifest,inbox,target string)(bool,error){
 if err:=exactStageLayout(target);err!=nil{return false,err}
 files:=[]string{"manifest.json","reference/result.age","reference/receipt.json","cpe/result.age","cpe/receipt.json"}
 for _,relative:=range files{
  input:=filepath.Join(inbox,relative)
  if relative=="manifest.json"{input=manifest}
  want,err:=hashRegularFile(input);if err!=nil{return false,err}
  got,err:=hashRegularFile(filepath.Join(target,relative));if err!=nil{return false,err}
  if want!=got{return false,nil}
 }
 return true,nil
}
func copyPairFile(src,dst string)error{
 input,info,err:=openPinnedRegular(src,maxCiphertext+32768)
 if err!=nil{return err}
 defer input.Close()
 output,err:=os.OpenFile(dst,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{return err}
 _,err=copyPinnedBytes(output,input,info)
 if err==nil{err=pinnedFileUnchanged(src,input,info)}
 if err==nil{err=output.Sync()}
 cerr:=output.Close()
 if err!=nil{return err}
 return cerr
}
func stagePair(manifest,inbox,destination string)(PairStage,error){
 var out PairStage
 if _,err:=pairPreflight(manifest,inbox);err!=nil{return out,err}
 plan,err:=readPairPlan(manifest);if err!=nil{return out,err}
 root,err:=filepath.Abs(destination);if err!=nil{return out,err}
 st,err:=os.Lstat(root);if err!=nil{return out,err}
 if !st.IsDir()||st.Mode().Perm()&0077!=0{return out,errors.New("staging root must be private directory")}
 if real,err:=filepath.EvalSymlinks(root);err!=nil||real!=root{return out,errors.New("symlinked staging root denied")}
 name:=plan.AssignmentID+"--"+plan.RunID+"--"+plan.RunAttempt
 target:=filepath.Join(root,name)
 out=PairStage{AssignmentID:plan.AssignmentID,RunID:plan.RunID,State:"CIPHERTEXT_ONLY_NOT_INGESTED"}
 if targetInfo,err:=os.Lstat(target);err==nil{
  if !targetInfo.IsDir()||targetInfo.Mode()&os.ModeSymlink!=0{
   return PairStage{},errors.New("staging target is not a real directory")
  }
  same,err:=comparePairFiles(manifest,inbox,target)
  if err!=nil{return PairStage{},err}
  if !same{return PairStage{},errors.New("conflicting immutable replay")}
  out.State="IDEMPOTENT_CIPHERTEXT_ALREADY_STAGED"
  return out,nil
 }else if !os.IsNotExist(err){return PairStage{},err}
 tmp,err:=os.MkdirTemp(root,".pair-pending-");if err!=nil{return PairStage{},err}
 committed:=false
 defer func(){if !committed{_ =os.RemoveAll(tmp)}}()
 if err=os.Chmod(tmp,0700);err!=nil{return PairStage{},err}
 for _,arm:=range []string{"reference","cpe"}{
  if err=os.Mkdir(filepath.Join(tmp,arm),0700);err!=nil{return PairStage{},err}
 }
 files:=[]string{"manifest.json","reference/result.age","reference/receipt.json","cpe/result.age","cpe/receipt.json"}
 for _,rel:=range files {
  src:=filepath.Join(inbox,rel)
  if rel=="manifest.json"{src=manifest}
  if err=copyPairFile(src,filepath.Join(tmp,rel));err!=nil{return PairStage{},err}
 }
 same,err:=comparePairFiles(manifest,inbox,tmp)
 if err!=nil||!same{return PairStage{},errors.New("staged content mismatch")}
 if _,err=pairPreflight(filepath.Join(tmp,"manifest.json"),tmp);err!=nil{return PairStage{},err}
 for _,arm:=range []string{"reference","cpe"}{
  if err=syncStageDir(filepath.Join(tmp,arm));err!=nil{return PairStage{},err}
 }
 if err=syncStageDir(tmp);err!=nil{return PairStage{},err}
 if err=renameDirectoryNoReplace(tmp,target);err!=nil{
  // Concurrent identical requests converge on the first committed directory.
  // A conflicting target can never be silently overwritten.
  if st,statErr:=os.Lstat(target);statErr==nil&&st.IsDir()&&st.Mode()&os.ModeSymlink==0 {
   same,compareErr:=comparePairFiles(manifest,inbox,target)
   if compareErr==nil&&same {
    out.State="IDEMPOTENT_CIPHERTEXT_ALREADY_STAGED"
    return out,nil
   }
  }
  return PairStage{},err
 }
 committed=true
 if err=syncStageDir(root);err!=nil{
  return PairStage{},errors.New("rename committed but destination sync failed; reconcile before retry")
 }
 return out,nil
}
