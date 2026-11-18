package heldledger

import (
 "bytes"
 "os"
 "runtime"
 "path/filepath"
 "syscall"
 "time"
 "testing"
)

func TestR15LinuxJournalOpenNonblockingAgainstFIFOReplacement(t *testing.T){
 if runtime.GOOS!="linux"{t.Skip("Linux-only syscall open")}
 source,err:=os.ReadFile("ledger_open_linux.go")
 if err!=nil{t.Fatal(err)}
 if !bytes.Contains(source,[]byte("syscall.O_NONBLOCK")){
  t.Fatal("R15_RED_JOURNAL_OPEN_CAN_BLOCK_ON_FIFO_PATH_SWAP")
 }
 t.Log("R15_LINUX_JOURNAL_OPEN_NONBLOCK_SOURCE_GATE=PASS")
}

func TestR15LinuxAtomicOpenOfFIFOIsBounded(t *testing.T){
 if runtime.GOOS!="linux"{t.Skip("Linux-only")}
 path:=filepath.Join(t.TempDir(),"journal-fifo")
 if err:=syscall.Mkfifo(path,0600);err!=nil{t.Fatal(err)}
 done:=make(chan error,1)
 go func(){
  f,err:=openJournalNoFollow(path)
  if f!=nil{_ = f.Close()}
  done<-err
 }()
 select{
 case err:=<-done:
  if err!=nil{t.Fatalf("nonblocking open failed: %v",err)}
 case <-time.After(2*time.Second):
  t.Fatal("R15_RED_FIFO_OPEN_BLOCKED")
 }
 // Store.Read must reject FIFO regardless of whether the open helper can
 // return a nonblocking descriptor; never treat FIFO as clean journal.
 s:=Store{Path:path}
 if _,err:=s.Read();err!=ErrInvalid{t.Fatalf("FIFO journal admitted: %v",err)}
 t.Log("R15_FIFO_OPEN_BOUNDED_AND_JOURNAL_DENIED=PASS")
}
