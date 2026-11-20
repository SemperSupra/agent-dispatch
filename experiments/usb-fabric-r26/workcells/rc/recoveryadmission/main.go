package main

import(
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "regexp"
 "sort"
)

// R27-E12 is a read-only release admission critic. A witnessed guest UP
// alone NEVER authorizes HELD clearance or lease admission. These fields
// are declarations requiring independent source/run/job corroboration;
// they are not evidence of actual QEMU behavior.
type Evidence struct{
 Cell string `json:"cell"`
 Commit string `json:"commit"`
 RunID int64 `json:"run_id"`
 JobID int64 `json:"job_id"`
 Verified bool `json:"verified"`
}
type Gate struct{
 Schema int `json:"schema"`
 GuestSignedUp Evidence `json:"guest_signed_up"`
 SameVMOwnerVerified bool `json:"same_vm_owner_verified"`
 NoHostileRawQMP bool `json:"no_hostile_raw_qmp"`
 EpochReconciled bool `json:"epoch_reconciled"`
 TopologyAbsent bool `json:"topology_absent"`
 ControllerExclusive bool `json:"controller_exclusive"`
 JournalFsyncedClear bool `json:"journal_fsynced_clear"`
 NewLeaseObserved bool `json:"new_lease_observed"`
 ProductionGuestTrust bool `json:"production_guest_trust"`
 OwnerReleaseApproval bool `json:"owner_release_approval"`
}
var fullSHA=regexp.MustCompile(`^[0-9a-f]{40}$`)
func assess(g Gate)([]string,error){
 if g.Schema!=1{return nil,errors.New("unknown admission evidence schema")}
 blockers:=[]string{}
 if g.GuestSignedUp.Cell!="R27H20"||!fullSHA.MatchString(g.GuestSignedUp.Commit)||
  g.GuestSignedUp.RunID<=0||g.GuestSignedUp.JobID<=0||!g.GuestSignedUp.Verified{
  blockers=append(blockers,"fresh-signed-guest-up")
 }
 if !g.SameVMOwnerVerified{blockers=append(blockers,"surviving-vm-owner-incarnation")}
 if !g.NoHostileRawQMP{blockers=append(blockers,"hostile-raw-qmp-red")}
 if !g.EpochReconciled{blockers=append(blockers,"host-guest-lease-epoch")}
 if !g.TopologyAbsent{blockers=append(blockers,"usb-topology")}
 if !g.ControllerExclusive{blockers=append(blockers,"exclusive-controller")}
 if !g.JournalFsyncedClear{blockers=append(blockers,"fsynced-held-clear")}
 if !g.NewLeaseObserved{blockers=append(blockers,"post-recovery-safe-new-lease")}
 if !g.ProductionGuestTrust{blockers=append(blockers,"production-guest-key-attestation")}
 if !g.OwnerReleaseApproval{blockers=append(blockers,"owner-release-approval")}
 sort.Strings(blockers)
 return blockers,nil
}
func main(){
 if len(os.Args)!=2{fmt.Fprintln(os.Stderr,"usage: recoveryadmission manifest.json");os.Exit(2)}
 raw,e:=os.ReadFile(os.Args[1]);if e!=nil{panic(e)}
 var g Gate;if e=json.Unmarshal(raw,&g);e!=nil{panic(e)}
 b,e:=assess(g);if e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}
 if len(b)!=0{
  fmt.Printf("R27_E12_RELEASE_ADMISSION=BLOCKED blockers=%d\n",len(b))
  for _,x:=range b{fmt.Println("BLOCKED:",x)}
  return
 }
 // A static evidence declaration alone does not authorize a release:
 // live authenticated refetch and explicit owner action remain external.
 fmt.Println("R27_E12_OFFLINE_CANDIDATE_ELIGIBLE=PASS")
 fmt.Println("R27_E12_ACTUAL_RELEASE_ADMISSION=NOT_TESTED")
}
