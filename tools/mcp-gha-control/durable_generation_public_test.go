package main

// Public-synthetic, standalone fault-model reference. This file contains no
// private source, workset IDs, policy material, credentials or real host paths.
import (
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "syscall"
    "testing"
)

type synthGeneration struct {
    Generation uint64 `json:"generation"`
}

func synthUpdate(path string) error {
    lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
    if err != nil { return err }
    defer lock.Close()
    if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil { return err }
    defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
    raw, err := os.ReadFile(path)
    if err != nil { return err } // Missing ledger must NOT reset generation.
    var state synthGeneration
    if err := json.Unmarshal(raw, &state); err != nil { return err }
    if state.Generation == 0 { return errors.New("invalid generation") }
    if state.Generation >= 1<<62 { return errors.New("out-of-bounds generation") }
    state.Generation++
    next, err := json.Marshal(state)
    if err != nil { return err }
    tmp, err := os.CreateTemp(filepath.Dir(path), ".synth-generation-*")
    if err != nil { return err }
    defer os.Remove(tmp.Name())
    if err := tmp.Chmod(0600); err != nil { tmp.Close(); return err }
    if _, err := tmp.Write(next); err != nil { tmp.Close(); return err }
    if err := tmp.Sync(); err != nil { tmp.Close(); return err }
    if err := tmp.Close(); err != nil { return err }
    if err := os.Rename(tmp.Name(), path); err != nil { return err }
    parent, err := os.Open(filepath.Dir(path))
    if err != nil { return err }
    defer parent.Close()
    return parent.Sync()
}

func TestPublicSyntheticGenerationWorker(t *testing.T) {
    if os.Getenv("SYNTHETIC_LEDGER_WORKER") != "1" { return }
    path := os.Getenv("SYNTHETIC_LEDGER_PATH")
    if path == "" { t.Fatal("missing fixture path") }
    if err := synthUpdate(path); err != nil { t.Fatal(err) }
}

func TestPublicSyntheticMultiprocessGenerationAndFailClosed(t *testing.T) {
    dir := t.TempDir()
    path := filepath.Join(dir, "generation.json")
    if err := os.WriteFile(path, []byte(`{"generation":1}`), 0600); err != nil { t.Fatal(err) }
    const workers = 5
    processes := make([]*exec.Cmd, 0, workers)
    for i:=0; i<workers; i++ {
        cmd := exec.Command(os.Args[0], "-test.run=^TestPublicSyntheticGenerationWorker$")
        cmd.Env = append(os.Environ(), "SYNTHETIC_LEDGER_WORKER=1", "SYNTHETIC_LEDGER_PATH="+path)
        processes = append(processes, cmd)
    }
    for _,p := range processes { if err:=p.Start(); err!=nil { t.Fatal(err) } }
    for _,p := range processes {
        if err:=p.Wait(); err!=nil { t.Fatalf("worker failed: %v",err) }
    }
    b,err:=os.ReadFile(path)
    if err!=nil { t.Fatal(err) }
    var s synthGeneration
    if err:=json.Unmarshal(b,&s); err!=nil { t.Fatal(err) }
    if s.Generation != 1+workers { t.Fatalf("lost update: got %d want %d",s.Generation,1+workers) }
    // A missing or malformed external ledger is not a license to reset to 1.
    if err:=os.Remove(path); err!=nil { t.Fatal(err) }
    if err:=synthUpdate(path); err==nil { t.Fatal("missing ledger silently initialized") }
    if err:=os.WriteFile(path, []byte(`{"generation":0}`), 0600); err!=nil { t.Fatal(err) }
    if err:=synthUpdate(path); err==nil { t.Fatal("zero generation accepted") }
    if err:=os.WriteFile(path, []byte("garbled"), 0600); err!=nil { t.Fatal(err) }
    if err:=synthUpdate(path); err==nil { t.Fatal("corrupt ledger accepted") }
}

func TestPublicSyntheticStaleAndMissingGenerationDenial(t *testing.T) {
    for _,fixture:=range []struct{generation string; denied bool}{
        {"0",true},{"1",false},{strconv.FormatUint(1<<62,10),true},
    } {
        t.Run(fmt.Sprintf("generation-%s",fixture.generation),func(t *testing.T){
            path:=filepath.Join(t.TempDir(),"ledger.json")
            err:=os.WriteFile(path,[]byte(`{"generation":`+fixture.generation+"}"),0600)
            if err!=nil { t.Fatal(err) }
            err=synthUpdate(path)
            if (err!=nil)!=fixture.denied { t.Fatalf("denied=%v error=%v",fixture.denied,err) }
        })
    }
}
