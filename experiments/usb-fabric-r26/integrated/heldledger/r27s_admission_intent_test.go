package heldledger

import (
 "bytes"
 "errors"
 "os"
 "path/filepath"
 "testing"
)

func TestR27SAdmissionIntentDurableBeforeKeyDown(t *testing.T){
 path:=filepath.Join(t.TempDir(),"journal.json")
 s:=Store{Path:path}
 if _,e:=s.BeginAdmission(0);!errors.Is(e,ErrConflict){t.Fatalf("missing clean journal admitted %v",e)}
 if _,e:=s.Transition(0,true);e!=nil{t.Fatal(e)}
 if _,e:=s.RequestRelease(1);e!=nil{t.Fatal(e)}
 if _,e:=s.AcknowledgeKernelIsolation(1,r27KernelWitness(1,11),r27KernelVerifier);e!=nil{t.Fatal(e)}
 if _,e:=s.ConfirmGuestKernelRelease(1,r27KernelWitness(1,11),r27KernelVerifier,claim(1,10,11),signed);e!=nil{t.Fatal(e)}
 st,e:=s.BeginAdmission(2)
 if e!=nil||!st.AdmissionIntent||st.Held{t.Fatalf("write ahead not fsynced %+v %v",st,e)}
 before,e:=os.ReadFile(path);if e!=nil{t.Fatal(e)}
 if _,e=s.BeginAdmission(2);!errors.Is(e,ErrConflict){t.Fatalf("repeated admission not rejected %v",e)}
 after,e:=os.ReadFile(path)
 if e!=nil||!bytes.Equal(before,after){t.Fatal("duplicate admission modified original journal")}
 read,e:=s.Read()
 if e!=nil||!read.AdmissionIntent||read.Sequence!=2||read.Held{t.Fatalf("crash-recovered intent missing %+v %v",read,e)}
 t.Log("R27_S_WRITE_AHEAD_ADMISSION_INTENT_FSYNC_RESTART=PASS")
 t.Log("R27_S_DUPLICATE_ADMISSION_BYTE_IDENTICAL=PASS")
 if _,e=s.Transition(2,true);e!=nil{t.Fatal(e)}
 active,e:=s.Read()
 if e!=nil||!active.Held||active.AdmissionIntent||active.Sequence!=3{
  t.Fatalf("key down did not atomically replace intent with durable HELD %+v %v",active,e)
 }
 t.Log("R27_S_KEY_DOWN_ATOMIC_REPLACES_ADMISSION_WITH_HELD=PASS")
}
