package heldledger

import (
 "bytes"
 "os"
 "runtime"
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
