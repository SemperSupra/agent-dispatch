// Package provisioner qualifies a synthetic host/guest install sequence.
// It has no physical-device or firmware actuator and never accepts disk paths.
package provisioner

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strings"
)

const maxFixtureBytes = 4 << 20

type Plan struct {
 DeviceID string
 Revision uint64
 ExpectedRevision uint64
 SSDIdentity string
 EMMCIdentity string
 HostImage []byte
 HostSHA256 string
 GuestImage []byte
 GuestSHA256 string
 HostSigned bool
 GuestSigned bool
 InstallRights bool
 BackupCustody bool
 IndependentRecovery bool
 ApprovedChangeID string
 SignedGate bool // synthetic assertion only; NOT cryptographic proof
 HostHealthProof bool
 GuestHealthProof bool
 GuestIsolatedStorage bool
 GuestIsolatedNetwork bool
 GuestNoPhysicalTPM bool
 GuestNoRecoveryDisk bool
 GuestVTPM bool
 RequiresNested bool
 NestedQualified bool
 GARMHold bool
 FailAfter string // fault injection: write, verify, boot, guest
}

type Receipt struct {
 Verdict string `json:"verdict"`
 Phases []string `json:"phases"`
 HostSHA256 string `json:"host_sha256"`
 GuestSHA256 string `json:"guest_sha256"`
 EMMCBefore string `json:"emmc_before"`
 EMMCAfter string `json:"emmc_after"`
 EMMCPreserved bool `json:"emmc_preserved"`
 CleanupVerified bool `json:"cleanup_verified"`
 SandboxPath string `json:"sandbox_path"`
 GARMAdmission string `json:"garm_admission"`
}

func digest(b []byte) string { sum:=sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func validFixture(b []byte,want string) bool { return len(b)>0 && len(b)<=maxFixtureBytes && len(want)==64 && digest(b)==want }
func Preflight(p Plan) error {
 if p.DeviceID==""||p.ExpectedRevision!=p.Revision { return errors.New("missing identity or stale revision") }
 if !strings.HasPrefix(p.SSDIdentity,"synthetic-sata-")||!strings.HasPrefix(p.EMMCIdentity,"synthetic-emmc-")||p.SSDIdentity==p.EMMCIdentity { return errors.New("non-synthetic or ambiguous disk identity") }
 if !validFixture(p.HostImage,p.HostSHA256)||!validFixture(p.GuestImage,p.GuestSHA256) { return errors.New("artifact digest or size mismatch") }
 if !p.HostSigned||!p.GuestSigned||!p.InstallRights||!p.BackupCustody||!p.IndependentRecovery { return errors.New("signing, rights, custody or recovery missing") }
 if p.ApprovedChangeID==""||!p.SignedGate { return errors.New("synthetic approval assertion missing") }
 if p.RequiresNested&&!p.NestedQualified { return errors.New("nested qualification missing") }
 if !p.GuestIsolatedStorage||!p.GuestIsolatedNetwork||!p.GuestNoPhysicalTPM||!p.GuestNoRecoveryDisk||!p.GuestVTPM {return errors.New("guest isolation or vTPM missing")}
 if !p.GARMHold {return errors.New("this experiment must retain live GARM HOLD")}
 return nil
}

// Run copies and independently reads back fake SSD and guest images. It never
// invokes QEMU, BootNext, TPM, network APIs or privileged storage interfaces.
func Run(ctx context.Context,p Plan)(r Receipt,err error){
 r.Verdict="INCONCLUSIVE";r.GARMAdmission="HOLD"
 if err=Preflight(p);err!=nil {r.Verdict="REFUSED_PREFLIGHT";return}
 var root string
 root,err=os.MkdirTemp("","wyse-synthetic-r19-")
 if err!=nil {return}
 r.SandboxPath=root
 defer func(){
  cleanupErr:=os.RemoveAll(root)
  _,statErr:=os.Stat(root)
  r.CleanupVerified=cleanupErr==nil&&errors.Is(statErr,os.ErrNotExist)
  if !r.CleanupVerified {r.Verdict="CLEANUP_FAILURE";if err==nil{err=fmt.Errorf("sandbox cleanup failed: %v",cleanupErr)}}
 }()
 if err=ctx.Err();err!=nil{return}
 emmc:=filepath.Join(root,"emmc.img")
 if err=os.WriteFile(emmc,[]byte("synthetic recovery: immutable fixture"),0600);err!=nil{return}
 var emmcData []byte
 emmcData,err=os.ReadFile(emmc);if err!=nil{return}
 r.EMMCBefore=digest(emmcData)
 // O_EXCL prevents accidental adoption of stale files; sandbox is created by MkdirTemp.
 if err=writeAndReadback(filepath.Join(root,"ssd.img"),p.HostImage,p.HostSHA256);err!=nil{r.Verdict="STAGE_OR_READBACK_FAILURE";return}
 r.Phases=append(r.Phases,"HOST_IMAGE_STAGED_AND_READBACK_VERIFIED")
 if p.FailAfter=="write"||p.FailAfter=="verify" {err=errors.New("injected stage failure");r.Verdict="FAULT_INJECTED";return}
 if err=ctx.Err();err!=nil{return}
 // This is an inert BootNext plan, NOT a firmware write or actual boot.
 r.Phases=append(r.Phases,"SYNTHETIC_BOOTNEXT_PLAN")
 if p.FailAfter=="boot" {err=errors.New("injected synthetic boot failure");r.Verdict="FAULT_INJECTED";return}
 if !p.HostHealthProof {err=errors.New("synthetic host health missing");r.Verdict="HOST_HEALTH_MISSING";return}
 r.Phases=append(r.Phases,"HOST_HEALTH_ASSERTION")
 if err=writeAndReadback(filepath.Join(root,"guest.img"),p.GuestImage,p.GuestSHA256);err!=nil{r.Verdict="GUEST_STAGE_OR_READBACK_FAILURE";return}
 r.Phases=append(r.Phases,"GUEST_IMAGE_STAGED_AND_READBACK_VERIFIED")
 if p.FailAfter=="guest" {err=errors.New("injected synthetic guest failure");r.Verdict="FAULT_INJECTED";return}
 if !p.GuestHealthProof {err=errors.New("synthetic guest health missing");r.Verdict="GUEST_HEALTH_MISSING";return}
 r.Phases=append(r.Phases,"GUEST_HEALTH_ASSERTION")
 emmcData,err=os.ReadFile(emmc);if err!=nil{return}
 r.EMMCAfter=digest(emmcData);r.EMMCPreserved=r.EMMCBefore==r.EMMCAfter
 if !r.EMMCPreserved {err=errors.New("recovery fixture changed");r.Verdict="EMMC_CHANGED";return}
 r.HostSHA256=p.HostSHA256;r.GuestSHA256=p.GuestSHA256
 r.Verdict="SYNTHETIC_PASS"
 return
}
func writeAndReadback(path string,image []byte,want string)error{
 f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if err!=nil{return err}
 _,writeErr:=f.Write(image)
 if writeErr==nil {writeErr=f.Sync()}
 closeErr:=f.Close()
 if writeErr!=nil{return writeErr};if closeErr!=nil{return closeErr}
 got,err:=os.ReadFile(path);if err!=nil{return err}
 if digest(got)!=want {return errors.New("readback digest mismatch")}
 return nil
}
