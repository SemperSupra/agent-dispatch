//go:build linux

package reviewauthority

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

const MaxSnapshotBytes = 64 << 20
const stateFile = "sealed-journal.json"

type DiskReceipt struct {
	PreviousSHA256, HeadSHA256 string
	EventCount int
	AlreadyPublished bool
}

// DiskStore is a bounded Linux reference using an owner-controlled, private
// directory on a local filesystem supporting flock, rename and directory sync.
// All writers must cooperate with this lock. External trusted head provisioning
// remains separate; a disk snapshot never supplies its own trust anchor.
type DiskStore struct{ dir string }

func OpenDiskStore(dir string)(*DiskStore,error){
	info,err:=os.Lstat(dir)
	if err!=nil{return nil,err}
	if !info.IsDir()||info.Mode().Perm()&0077!=0{return nil,errors.New("CATALOG_DIRECTORY_NOT_PRIVATE")}
	abs,err:=filepath.Abs(dir);if err!=nil{return nil,err}
	return &DiskStore{dir:abs},nil
}

func openRegular(path string, flags int)(*os.File,error){
	fd,err:=syscall.Open(path,flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK,0600)
	if err!=nil{return nil,err}
	f:=os.NewFile(uintptr(fd),path)
	st,err:=f.Stat()
	if err!=nil||!st.Mode().IsRegular()||st.Mode().Perm()&0077!=0{
		f.Close();return nil,errors.New("CATALOG_FILE_NOT_PRIVATE_REGULAR")
	}
	return f,nil
}
func (s *DiskStore) lock()(*os.File,error){
	f,err:=openRegular(filepath.Join(s.dir,"writer.lock"),syscall.O_CREAT|syscall.O_RDWR)
	if err!=nil{return nil,err}
	if err=syscall.Flock(int(f.Fd()),syscall.LOCK_EX|syscall.LOCK_NB);err!=nil{
		f.Close();return nil,errors.New("CATALOG_WRITER_BUSY")
	}
	return f,nil // close releases lock, including process death.
}
func encodeSnapshot(events []SignedEvent)([]byte,error){
	if len(events)==0||len(events)>MaxEvents{return nil,errors.New("CATALOG_EVENT_BOUND")}
	b,err:=json.Marshal(events);if err!=nil{return nil,err}
	if len(b)>MaxSnapshotBytes{return nil,errors.New("CATALOG_BYTE_BOUND")}
	return b,nil
}
func (s *DiskStore) read()([]SignedEvent,error){
	f,err:=openRegular(filepath.Join(s.dir,stateFile),syscall.O_RDONLY)
	if err!=nil{return nil,err};defer f.Close()
	b,err:=io.ReadAll(io.LimitReader(f,MaxSnapshotBytes+1))
	if err!=nil{return nil,err}
	if len(b)>MaxSnapshotBytes{return nil,errors.New("CATALOG_BYTE_BOUND")}
	var events []SignedEvent
	d:=json.NewDecoder(bytes.NewReader(b));d.DisallowUnknownFields()
	if err=d.Decode(&events);err!=nil{return nil,err}
	var trailing any
	if err=d.Decode(&trailing);err!=io.EOF{return nil,errors.New("CATALOG_TRAILING_JSON")}
	canonical,err:=encodeSnapshot(events)
	// Reject duplicate keys, lossy UTF-8, alternate or unknown encodings.
	if err!=nil||!bytes.Equal(canonical,b){return nil,errors.New("CATALOG_NONCANONICAL_SNAPSHOT")}
	return events,nil
}

func syncDirectory(dir string)error{
	d,err:=os.Open(dir);if err!=nil{return err};defer d.Close()
	return d.Sync()
}
// publish runs with the cooperative writer lock. A successful return means
// both the file and containing directory were synced. If rename succeeds but
// directory sync fails the outcome is ambiguous; the caller must re-read and
// retry using the exact old/new pins. Stage injection is private test plumbing.
func (s *DiskStore) publish(b []byte, stage func(string))error{
	f,err:=os.CreateTemp(s.dir,".journal-staging-");if err!=nil{return err}
	name:=f.Name()
	defer os.Remove(name)
	defer f.Close()
	n,err:=f.Write(b);if err!=nil{return err};if n!=len(b){return io.ErrShortWrite}
	if err=f.Sync();err!=nil{return err}
	if err=f.Close();err!=nil{return err}
	if stage!=nil{stage("before-rename")}
	if err=os.Rename(name,filepath.Join(s.dir,stateFile));err!=nil{return err}
	if stage!=nil{stage("after-rename")}
	if err=syncDirectory(s.dir);err!=nil{return errors.New("CATALOG_PUBLISH_OUTCOME_UNKNOWN")}
	return nil
}

// Load never trusts the stored head alone. An independently supplied exact
// pin is mandatory and Replay validates the entire sealed history.
func (s *DiskStore) Load(trust Trust)(*Catalog,error){
	events,err:=s.read();if err!=nil{return nil,err}
	return Replay(trust,events)
}

func (s *DiskStore) Initialize(trust Trust,events []SignedEvent)(DiskReceipt,error){
	var zero DiskReceipt
	if _,err:=Replay(trust,events);err!=nil{return zero,err}
	b,err:=encodeSnapshot(events);if err!=nil{return zero,err}
	lock,err:=s.lock();if err!=nil{return zero,err};defer lock.Close()
	existing,err:=s.read()
	if err==nil{
		old,_:=encodeSnapshot(existing)
		if !bytes.Equal(old,b){return zero,errors.New("CATALOG_ALREADY_INITIALIZED")}
		if _,err=Replay(trust,existing);err!=nil{return zero,err}
		if err=syncDirectory(s.dir);err!=nil{return zero,err}
		return DiskReceipt{HeadSHA256:trust.HeadSHA256,EventCount:len(events),AlreadyPublished:true},nil
	}
	if !os.IsNotExist(err){return zero,err}
	if err=s.publish(b,nil);err!=nil{return zero,err}
	return DiskReceipt{HeadSHA256:trust.HeadSHA256,EventCount:len(events)},nil
}

// Commit extends the exact independently pinned old sealed head to an exact
// independently approved new sealed head. It never replaces prior events.
// A concurrent winner with a different head yields a stale-head error.
// A retry of the identical published extension is idempotent.
func (s *DiskStore) Commit(prior Trust,nextHead string,extension []SignedEvent)(DiskReceipt,error){
	return s.commit(prior,nextHead,extension,nil)
}
func (s *DiskStore) commit(prior Trust,nextHead string,extension []SignedEvent,stage func(string))(DiskReceipt,error){
	var zero DiskReceipt
	if !isHash(prior.HeadSHA256)||!isHash(nextHead)||prior.HeadSHA256==nextHead||
		len(extension)==0||len(extension)>=MaxEvents{return zero,errors.New("CATALOG_EXTENSION_INVALID")}
	lock,err:=s.lock();if err!=nil{return zero,err};defer lock.Close()
	current,err:=s.read();if err!=nil{return zero,err}
	head,err:=EventDigest(current[len(current)-1]);if err!=nil{return zero,err}
	next:=prior;next.HeadSHA256=nextHead
	out:=DiskReceipt{PreviousSHA256:prior.HeadSHA256,HeadSHA256:nextHead}
	if head==nextHead{
		if len(current)<=len(extension){return zero,errors.New("CATALOG_RETRY_MISMATCH")}
		prefix:=current[:len(current)-len(extension)]
		if _,err=Replay(prior,prefix);err!=nil{return zero,errors.New("CATALOG_RETRY_MISMATCH")}
		a,err:=encodeSnapshot(current[len(prefix):]);if err!=nil{return zero,err}
		b,err:=encodeSnapshot(extension);if err!=nil{return zero,err}
		if !bytes.Equal(a,b){return zero,errors.New("CATALOG_RETRY_MISMATCH")}
		if _,err=Replay(next,current);err!=nil{return zero,err}
		if err=syncDirectory(s.dir);err!=nil{return zero,err}
		out.EventCount=len(current);out.AlreadyPublished=true;return out,nil
	}
	if head!=prior.HeadSHA256{return zero,errors.New("CATALOG_STALE_HEAD")}
	if _,err=Replay(prior,current);err!=nil{return zero,err}
	if len(current)+len(extension)>MaxEvents{return zero,errors.New("CATALOG_EVENT_BOUND")}
	proposed:=append(slices.Clone(current),extension...)
	if _,err=Replay(next,proposed);err!=nil{return zero,err}
	b,err:=encodeSnapshot(proposed);if err!=nil{return zero,err}
	if err=s.publish(b,stage);err!=nil{return zero,err}
	out.EventCount=len(proposed);return out,nil
}
