package main

// Linux/GitHub-hosted and Linux/TrueNAS source-only custody qualification.
// File descriptors are opened O_NOFOLLOW + O_NONBLOCK and inspected before
// reading, so symlink and FIFO substitution cannot change what we consume.
import (
 "bytes"
 "errors"
 "io"
 "os"
 "syscall"
)

func openPinnedRegular(path string, limit int64)(*os.File,os.FileInfo,error){
 fd,err:=syscall.Open(path,syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC,0)
 if err!=nil{return nil,nil,err}
 file:=os.NewFile(uintptr(fd),path)
 info,err:=file.Stat()
 if err!=nil{file.Close();return nil,nil,err}
 st,ok:=info.Sys().(*syscall.Stat_t)
 if !ok||!info.Mode().IsRegular()||st.Nlink!=1||info.Size()<1||info.Size()>limit {
  file.Close();return nil,nil,errors.New("unsafe regular input or out-of-bounds file")
 }
 // The path must still name the inode opened. os.SameFile compares inode
 // identity, rather than separately trusting pre-open lstat().
 latest,err:=os.Lstat(path)
 if err!=nil||!latest.Mode().IsRegular()||!os.SameFile(info,latest){
  file.Close();return nil,nil,errors.New("input pathname replaced before read")
 }
 return file,info,nil
}

func pinnedFileUnchanged(path string,file *os.File,original os.FileInfo)error{
 after,err:=file.Stat();if err!=nil{return err}
 oldStat,ok1:=original.Sys().(*syscall.Stat_t)
 newStat,ok2:=after.Sys().(*syscall.Stat_t)
 if !ok1||!ok2||oldStat.Dev!=newStat.Dev||oldStat.Ino!=newStat.Ino||
  oldStat.Nlink!=newStat.Nlink||newStat.Nlink!=1||
  original.Size()!=after.Size()||!original.ModTime().Equal(after.ModTime())||
  oldStat.Ctim!=newStat.Ctim {
  return errors.New("input inode changed during read")
 }
 latest,err:=os.Lstat(path)
 if err!=nil||!latest.Mode().IsRegular()||!os.SameFile(after,latest){
  return errors.New("input pathname replaced during read")
 }
 return nil
}

// Consumers must read at most original size+1 and confirm exact byte count.
// Reading beyond that detects concurrent append/growth without unbounded IO.
func copyPinnedBytes(dst io.Writer,source *os.File,info os.FileInfo)(int64,error){
 n,err:=io.Copy(dst,io.LimitReader(source,info.Size()+1))
 if err!=nil{return 0,err}
 if n!=info.Size(){return 0,errors.New("input length changed during read")}
 return n,nil
}

func readPinnedRegular(path string,limit int64)([]byte,error){
 file,info,err:=openPinnedRegular(path,limit)
 if err!=nil{return nil,err}
 defer file.Close()
 var buffer bytes.Buffer
 if _,err=copyPinnedBytes(&buffer,file,info);err!=nil{return nil,err}
 if err=pinnedFileUnchanged(path,file,info);err!=nil{return nil,err}
 return buffer.Bytes(),nil
}
