package main

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "io"
 "os"
 "path/filepath"
)

type PairStage struct {
 AssignmentID string
 RunID string
 State string
}
func hashRegularFile(path string)(string,error){
 if err:=noSymlinkFile(path);err!=nil{return "",err}
 f,err:=os.Open(path);if err!=nil{return "",err}
 defer f.Close()
 h:=sha256.New()
 if _,err=io.Copy(h,io.LimitReader(f,maxCiphertext+32769));err!=nil{return "",err}
 return hex.EncodeToString(h.Sum(nil)),nil
}
func comparePairFiles(manifest,inbox,target string)(bool,error){
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
 if err:=noSymlinkFile(src);err!=nil{return err}
 input,err:=os.Open(src);if err!=nil{return err};defer input.Close()
 output,err:=os.OpenFile(dst,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{return err}
 _,err=io.Copy(output,io.LimitReader(input,maxCiphertext+32769))
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
 if _,err:=os.Lstat(target);err==nil{
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
 if err=os.Rename(tmp,target);err!=nil{return PairStage{},err}
 committed=true
 return out,nil
}
