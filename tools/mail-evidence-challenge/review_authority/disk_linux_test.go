//go:build linux

package reviewauthority

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func diskFixture(t *testing.T)(*DiskStore,fixture,Trust,Trust,[]SignedEvent){
	t.Helper()
	f:=sample()
	old:=f;old.events=f.events[:4]
	before,after:=old.trust(),f.trust()
	s,err:=OpenDiskStore(t.TempDir());if err!=nil{t.Fatal(err)}
	r,err:=s.Initialize(before,old.events);if err!=nil||r.EventCount!=4||r.AlreadyPublished{t.Fatal(r,err)}
	return s,f,before,after,f.events[4:]
}
func TestDiskCommitRestartAndIdempotency(t *testing.T){
	s,f,prior,next,ext:=diskFixture(t)
	r,err:=s.Commit(prior,next.HeadSHA256,ext)
	if err!=nil||r.EventCount!=9||r.AlreadyPublished{t.Fatal(r,err)}
	reopened,err:=OpenDiskStore(s.dir);if err!=nil{t.Fatal(err)}
	got,err:=reopened.Load(next);if err!=nil{t.Fatal(err)}
	expected,err:=Replay(next,f.events);if err!=nil{t.Fatal(err)}
	a,err:=got.Project(scope(f,d5),[]string{"old","new","next"});if err!=nil{t.Fatal(err)}
	b,err:=expected.Project(scope(f,d5),[]string{"old","new","next"});if err!=nil||!reflect.DeepEqual(a,b){t.Fatal("restart projection drift",err)}
	if _,err=reopened.Load(prior);err==nil{t.Fatal("accepted stale independent pin")}
	r,err=reopened.Commit(prior,next.HeadSHA256,ext)
	if err!=nil||!r.AlreadyPublished||r.EventCount!=9{t.Fatal("retry",r,err)}
	// A different signed extension from the old prefix must not win.
	other:=f;other.events=append([]SignedEvent(nil),f.events[:4]...)
	other.add(Event{Kind:"seal",RecordedAt:d3})
	if _,err=reopened.Commit(prior,other.trust().HeadSHA256,other.events[4:]);err==nil||
		!strings.Contains(err.Error(),"STALE_HEAD"){t.Fatal("stale writer",err)}
	// A same-head retry cannot omit an extension event.
	if _,err=reopened.Commit(prior,next.HeadSHA256,ext[1:]);err==nil{t.Fatal("bad retry accepted")}
}
func TestDiskRejectsBusyTamperAndWrongPin(t *testing.T){
	s,_,prior,next,ext:=diskFixture(t)
	lock,err:=s.lock();if err!=nil{t.Fatal(err)}
	if _,err=s.Commit(prior,next.HeadSHA256,ext);err==nil||!strings.Contains(err.Error(),"WRITER_BUSY"){t.Fatal(err)}
	lock.Close()
	if _,err=s.Commit(prior,hash([]byte("wrong new pin")),ext);err==nil{t.Fatal("wrong pin")}
	if _,err=s.Load(prior);err!=nil{t.Fatal("failed candidate mutated prior",err)}
	path:=filepath.Join(s.dir,stateFile)
	original,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
	b:=append(append([]byte(nil),original...),byte('\n'))
	if err=os.WriteFile(path,b,0600);err!=nil{t.Fatal(err)}
	if _,err=s.Load(prior);err==nil{t.Fatal("noncanonical state accepted")}
	if err=os.WriteFile(path,original,0600);err!=nil{t.Fatal(err)}
	var events []SignedEvent
	if err=json.Unmarshal(original,&events);err!=nil{t.Fatal(err)}
	events[1].Event.Review.PayloadSHA256=hash([]byte("tamper"))
	b,err=encodeSnapshot(events);if err!=nil{t.Fatal(err)}
	if err=os.WriteFile(path,b,0600);err!=nil{t.Fatal(err)}
	if _,err=s.Load(prior);err==nil{t.Fatal("tampered state accepted")}
}
func TestDiskChildInterruptedPublication(t *testing.T){
	for _,stage:=range []string{"before-rename","after-rename"}{t.Run(stage,func(t *testing.T){
		s,_,prior,next,ext:=diskFixture(t)
		cmd:=exec.Command(os.Args[0],"-test.run=^TestDiskInterruptHelper$")
		cmd.Env=append(os.Environ(),"MAIL_CATALOG_TEST_CHILD=1","MAIL_CATALOG_TEST_DIR="+s.dir,"MAIL_CATALOG_TEST_STAGE="+stage)
		err:=cmd.Run()
		exit,ok:=err.(*exec.ExitError)
		if !ok||exit.ExitCode()!=93{t.Fatalf("child did not reach injection: %v",err)}
		if stage=="before-rename"{
			if _,err=s.Load(prior);err!=nil{t.Fatal("prior lost",err)}
			if _,err=s.Load(next);err==nil{t.Fatal("premature new state")}
		}else{
			if _,err=s.Load(next);err!=nil{t.Fatal("published state not readable",err)}
		}
		r,err:=s.Commit(prior,next.HeadSHA256,ext)
		if err!=nil||r.AlreadyPublished!=(stage=="after-rename"){t.Fatal("retry",r,err)}
		if _,err=s.Load(next);err!=nil{t.Fatal(err)}
	})}
}
func TestDiskInterruptHelper(t *testing.T){
	if os.Getenv("MAIL_CATALOG_TEST_CHILD")!="1"{return}
	s,err:=OpenDiskStore(os.Getenv("MAIL_CATALOG_TEST_DIR"));if err!=nil{t.Fatal(err)}
	f:=sample();old:=f;old.events=f.events[:4]
	_,err=s.commit(old.trust(),f.trust().HeadSHA256,f.events[4:],func(stage string){
		if stage==os.Getenv("MAIL_CATALOG_TEST_STAGE"){os.Exit(93)}
	})
	t.Fatalf("did not interrupt: %v",err)
}
func TestDiskInitializationAndPathControls(t *testing.T){
	s,f,prior,_,_:=diskFixture(t)
	r,err:=s.Initialize(prior,f.events[:4]);if err!=nil||!r.AlreadyPublished{t.Fatal(r,err)}
	if _,err=s.Initialize(f.trust(),f.events);err==nil{t.Fatal("overwrote initialized state")}
	path:=filepath.Join(s.dir,stateFile)
	renamed:=filepath.Join(s.dir,"retained")
	if err=os.Rename(path,renamed);err!=nil{t.Fatal(err)}
	if err=os.Symlink(renamed,path);err!=nil{t.Fatal(err)}
	if _,err=s.Load(prior);err==nil{t.Fatal("followed symlink")}
	if _,err=s.Initialize(prior,f.events[:4]);err==nil{t.Fatal("replaced unsafe state")}
}
