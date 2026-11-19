// r25-release-manifest validates a *snapshot* of immutable DLE receipts.
// It never mutates GitHub, starts a scheduler, or promotes a test-only PASS
// to production acceptance. Current PR heads MUST be independently re-read.
package main

import (
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "os"
    "regexp"
    "sort"
)

type Receipt struct {
    ID string `json:"id"`
    PR int `json:"pr"`
    Head string `json:"head"`
    Run int64 `json:"run"`
    Job int64 `json:"job"`
    Kind string `json:"kind"` // contract, real-qemu, real-usbip, software-tpm
    Outcome string `json:"outcome"` // PASS, RED
    Marker string `json:"marker"`
    ParentHead string `json:"parent_head,omitempty"`
    ArtifactID int64 `json:"artifact_id"`
    ArtifactSHA256 string `json:"artifact_sha256"`
    ChangedPaths []string `json:"changed_paths"`
}
type Gate struct {
    ID string `json:"id"`
    Priority string `json:"priority"` // P0, P1
    State string `json:"state"` // PASS, RED, NOT_TESTED, BLOCKED
    RequiredKind string `json:"required_kind"`
    ReceiptID string `json:"receipt_id,omitempty"`
}
type Manifest struct {
    Schema string `json:"schema"`
    EvidenceRepository string `json:"evidence_repository"`
    Authority string `json:"authority"`
    ObservationDate string `json:"observation_date"`
    OwnerApproved bool `json:"owner_approved"`
    ReleaseRequested bool `json:"release_requested"`
    Receipts []Receipt `json:"receipts"`
    Gates []Gate `json:"gates"`
}
type Result struct {
    Valid bool `json:"valid"`
    ReleaseEligible bool `json:"release_eligible"`
    CriticalRemaining []string `json:"critical_remaining"`
    Errors []string `json:"errors"`
}
var sha40 = regexp.MustCompile(`^[a-f0-9]{40}$`)
var sha64 = regexp.MustCompile(`^[a-f0-9]{64}$`)
var kinds = map[string]bool{"contract":true,"real-qemu":true,"real-usbip":true,"software-tpm":true}
var states = map[string]bool{"PASS":true,"RED":true,"NOT_TESTED":true,"BLOCKED":true}

func Validate(m Manifest) Result {
    v:=Result{Valid:true}
    fail:=func(s string){v.Valid=false;v.Errors=append(v.Errors,s)}
    if m.Schema!="usb-fabric-r25/1" {fail("unknown schema")}
    if m.EvidenceRepository!="SemperSupra/agent-dispatch" || m.Authority!="mark-e-deyoung/infrastructure-as-code-private" {
        fail("unrecognized repository or DLE authority")
    }
    if m.ObservationDate=="" {fail("missing explicit observation date")}
    known:=map[string]Receipt{}
    owners:=map[string]string{}
    for _,r:=range m.Receipts {
        if r.ID=="" {fail("receipt without id");continue}
        if _,ok:=known[r.ID];ok{fail("duplicate receipt "+r.ID)}
        known[r.ID]=r
        if r.PR<1||!sha40.MatchString(r.Head)||r.Run<1||r.Job<1 {
            fail("receipt lacks exact PR/head/run/job: "+r.ID)
        }
        if !kinds[r.Kind] || (r.Outcome!="PASS"&&r.Outcome!="RED") {
            fail("unsupported evidence kind/outcome: "+r.ID)
        }
        if r.Marker=="" {fail("missing first-hand CI marker: "+r.ID)}
        if r.ArtifactID<1 || !sha64.MatchString(r.ArtifactSHA256) {
            fail("missing exact evidence artifact ID and sha256: "+r.ID)
        }
        if len(r.ChangedPaths)==0 {fail("no scoped changed paths: "+r.ID)}
        for _,p:=range r.ChangedPaths {
            if p=="" {fail("empty changed path: "+r.ID);continue}
            if old,ok:=owners[p];ok {fail("path ownership collision "+p+" "+old+" "+r.ID)}
            owners[p]=r.ID
        }
    }
    gates:=map[string]bool{}
    p0pass:=0
    for _,g:=range m.Gates {
        if g.ID==""||gates[g.ID] {fail("empty or duplicate gate "+g.ID)}
        gates[g.ID]=true
        if (g.Priority!="P0"&&g.Priority!="P1") || !states[g.State] || !kinds[g.RequiredKind] {
            fail("invalid gate fields: "+g.ID)
        }
        if g.State=="PASS" {
            r,found:=known[g.ReceiptID]
            if !found || r.Outcome!="PASS" || r.Kind!=g.RequiredKind {
                fail("unproved gate PASS (wrong/missing evidence class): "+g.ID)
            }
            if g.Priority=="P0" {p0pass++}
        } else if g.Priority=="P0" {
            v.CriticalRemaining=append(v.CriticalRemaining,g.ID)
        }
        if g.State!="PASS" && g.ReceiptID!="" {
            fail("non-PASS gate cannot claim a passing source: "+g.ID)
        }
    }
    if len(gates)==0{fail("missing release gates")}
    sort.Strings(v.CriticalRemaining)
    if m.ReleaseRequested {
        if !m.OwnerApproved {fail("unapproved release requested")}
        if len(v.CriticalRemaining)!=0 {fail("P0 gate still unqualified")}
        if p0pass==0 {fail("no P0 release acceptance")}
    }
    v.ReleaseEligible=v.Valid && m.ReleaseRequested && m.OwnerApproved && len(v.CriticalRemaining)==0
    sort.Strings(v.Errors)
    return v
}
func main() {
    path:=flag.String("manifest","manifest.json","immutable evidence snapshot manifest path")
    mode:=flag.String("format","human","human or json")
    flag.Parse()
    bytes,err:=os.ReadFile(*path);if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(2)}
    var m Manifest
    if err=json.Unmarshal(bytes,&m);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(2)}
    out:=Validate(m)
    switch *mode {
    case "json":
        encoder:=json.NewEncoder(os.Stdout);encoder.SetIndent("","  ")
        if err=encoder.Encode(out);err!=nil{panic(err)}
    case "human":
        fmt.Printf("USB Fabric R25 release snapshot (%s): valid=%t release_eligible=%t\n",m.ObservationDate,out.Valid,out.ReleaseEligible)
        fmt.Printf("Receipts=%d gates=%d P0 remaining=%d\n",len(m.Receipts),len(m.Gates),len(out.CriticalRemaining))
        for _,g:=range out.CriticalRemaining{fmt.Println("P0 NOT QUALIFIED: "+g)}
        for _,msg:=range out.Errors{fmt.Println("ERROR: "+msg)}
        fmt.Println("Scope: offline snapshot only; PR SHA and Actions evidence need separate live revalidation")
    default:
        fmt.Fprintln(os.Stderr,errors.New("format must be human or json"));os.Exit(2)
    }
    if !out.Valid {os.Exit(1)}
}
