package policy

import (
 "encoding/json"
 "fmt"
 "io"
 "strings"
)

// Manifest validates one proposed workload's declared execution boundary.
// It is not a witness of actual runtime execution or host disposal.
type Manifest struct {
 Schema string `json:"schema"`
 ID string `json:"id"`
 Phase string `json:"phase"`
 Tooling Tooling `json:"tooling"`
 Runtime *Runtime `json:"runtime,omitempty"`
}
type Tooling struct {
 Mode string `json:"mode"`
 InstallScope string `json:"install_scope"`
 CacheScope string `json:"cache_scope"`
 CleanupDeclared bool `json:"cleanup_declared"`
 GlobalInstall bool `json:"global_install"`
 UnmanagedHostWrites bool `json:"unmanaged_host_writes"`
}
type Runtime struct {
 Kind string `json:"kind"`
 Replaceable bool `json:"replaceable"`
 Privileged bool `json:"privileged"`
 HostRuntimeSocket bool `json:"host_runtime_socket"`
 WritableHostMount bool `json:"writable_host_mount"`
 State string `json:"state"`
 DurableStateRequired bool `json:"durable_state_required"`
}
type Receipt struct {
 Schema string `json:"schema"`
 ManifestID string `json:"manifest_id"`
 Level string `json:"evidence_level"`
 Accepted bool `json:"accepted"`
 Preferred bool `json:"preferred"`
 Rejections []string `json:"rejections"`
 Limitations []string `json:"limitations"`
}

func Parse(data []byte) (Manifest,error) {
 var m Manifest
 d:=json.NewDecoder(strings.NewReader(string(data)))
 d.DisallowUnknownFields()
 if err:=d.Decode(&m);err!=nil {return m,fmt.Errorf("invalid manifest: %w",err)}
 var extra any
 if err:=d.Decode(&extra); err!=io.EOF {
  if err==nil{return m,fmt.Errorf("trailing JSON document")}
  return m,fmt.Errorf("trailing data: %w",err)
 }
 return m,nil
}
func Evaluate(m Manifest) Receipt {
 r:=Receipt{
  Schema:"m1.disposable.policy.receipt/v1",ManifestID:m.ID,
  Level:"declaration_only",Rejections:[]string{},
  Limitations:[]string{
   "Static validation does not prove tool installation confinement, runner disposability, namespace isolation or cleanup.",
   "Runtime replacement, off-node durability, identity, audit, native workset admission and security require independent executable tests.",
  },
 }
 reject:=func(code string){r.Rejections=append(r.Rejections,code)}
 if m.Schema!="m1.disposable.execution/v1" {reject("schema.unsupported")}
 if m.ID=="" || len(m.ID)>128 {reject("id.invalid")}
 switch m.Phase {case "development","build","test","deployment":default:reject("phase.unknown")}
 switch m.Tooling.Mode {
 case "preferred_cell":
  r.Preferred=true
  if m.Tooling.InstallScope!="cell" || m.Tooling.CacheScope!="cell" {reject("tooling.preferred_outside_cell")}
 case "local_disposable_fallback":
  if m.Tooling.InstallScope!="~/.local" && m.Tooling.InstallScope!="project/.local" {
   reject("tooling.fallback_scope_invalid")
  }
  if m.Tooling.CacheScope!=m.Tooling.InstallScope {reject("tooling.fallback_cache_escapes_scope")}
 default:reject("tooling.mode_unknown")
 }
 if m.Tooling.GlobalInstall {reject("tooling.global_install")}
 if m.Tooling.UnmanagedHostWrites {reject("tooling.unmanaged_host_writes")}
 if !m.Tooling.CleanupDeclared {reject("tooling.cleanup_not_declared")}
 if m.Phase=="deployment" && m.Runtime==nil {reject("runtime.required_for_deployment")}
 if rt:=m.Runtime;rt!=nil {
  switch rt.Kind {
  case "ephemeral_container","ephemeral_vm","ephemeral_microvm","ephemeral_pod","hosted_free_gha":
  default:reject("runtime.not_disposable")
  }
  if !rt.Replaceable {reject("runtime.not_replaceable")}
  if rt.Privileged {reject("runtime.privileged")}
  if rt.HostRuntimeSocket {reject("runtime.host_socket")}
  if rt.WritableHostMount {reject("runtime.writable_host_mount")}
  switch rt.State {
  case "external_durable","intentional_discard","none":
  case "local_named_volume":
   if rt.DurableStateRequired {reject("runtime.local_volume_not_off_node")}
  default:reject("runtime.state_unknown")
  }
  if rt.DurableStateRequired && rt.State!="external_durable" {reject("runtime.durability_requires_external_state")}
 }
 r.Accepted=len(r.Rejections)==0
 return r
}
