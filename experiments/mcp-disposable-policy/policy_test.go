package policy

import (
 "encoding/json"
 "slices"
 "strings"
 "testing"
)

func base() Manifest {return Manifest{Schema:"m1.disposable.execution/v1",ID:"test-001",Phase:"build",Tooling:Tooling{Mode:"preferred_cell",InstallScope:"cell",CacheScope:"cell",CleanupDeclared:true}}}
func TestToolingPreferenceAndPermittedFallback(t *testing.T){
 p:=base()
 if r:=Evaluate(p);!r.Accepted||!r.Preferred{t.Fatalf("preferred rejected %+v",r)}
 for _,scope:=range []string{"~/.local","project/.local"}{
  p=base();p.Tooling.Mode="local_disposable_fallback";p.Tooling.InstallScope=scope;p.Tooling.CacheScope=scope
  if r:=Evaluate(p);!r.Accepted||r.Preferred{t.Fatalf("allowed fallback rejected %+v",r)}
 }
}
func TestFallbackEscapesDenied(t *testing.T){
 cases:=[]struct{name string; change func(*Manifest); reason string}{
  {"global",func(m *Manifest){m.Tooling.GlobalInstall=true},"tooling.global_install"},
  {"wrong-install",func(m *Manifest){m.Tooling.InstallScope="/usr/local"},"tooling.fallback_scope_invalid"},
  {"cache-spill",func(m *Manifest){m.Tooling.CacheScope="~/.cache"},"tooling.fallback_cache_escapes_scope"},
  {"unmanaged",func(m *Manifest){m.Tooling.UnmanagedHostWrites=true},"tooling.unmanaged_host_writes"},
  {"cleanup-missing",func(m *Manifest){m.Tooling.CleanupDeclared=false},"tooling.cleanup_not_declared"},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){m:=base();m.Tooling.Mode="local_disposable_fallback";m.Tooling.InstallScope="project/.local";m.Tooling.CacheScope="project/.local";tc.change(&m);r:=Evaluate(m);if r.Accepted||!slices.Contains(r.Rejections,tc.reason){t.Fatalf("bad rejection %+v",r)}})}
}
func TestServiceRuntimeMustBeDisposable(t *testing.T){
 m:=base();m.Phase="deployment";m.Runtime=&Runtime{Kind:"ephemeral_vm",Replaceable:true,State:"external_durable",DurableStateRequired:true}
 if r:=Evaluate(m);!r.Accepted{t.Fatalf("external state rejected %+v",r)}
 m.Runtime.State="local_named_volume"
 if r:=Evaluate(m);r.Accepted || !slices.Contains(r.Rejections,"runtime.durability_requires_external_state"){t.Fatalf("same-node volume accepted %+v",r)}
 m.Runtime.State="external_durable"
 m.Runtime.Kind="persistent_host"
 if r:=Evaluate(m);r.Accepted||!slices.Contains(r.Rejections,"runtime.not_disposable"){t.Fatalf("persistent host accepted %+v",r)}
 m.Runtime.Kind="ephemeral_container";m.Runtime.HostRuntimeSocket=true
 if r:=Evaluate(m);r.Accepted||!slices.Contains(r.Rejections,"runtime.host_socket"){t.Fatalf("socket accepted %+v",r)}
 m.Runtime.HostRuntimeSocket=false;m.Runtime.WritableHostMount=true
 if r:=Evaluate(m);r.Accepted||!slices.Contains(r.Rejections,"runtime.writable_host_mount"){t.Fatalf("host write accepted %+v",r)}
 m.Runtime=nil
 if r:=Evaluate(m);r.Accepted||!slices.Contains(r.Rejections,"runtime.required_for_deployment"){t.Fatalf("empty runtime accepted %+v",r)}
}
func TestStatelessExplicitLoss(t *testing.T){m:=base();m.Phase="deployment";m.Runtime=&Runtime{Kind:"ephemeral_container",Replaceable:true,State:"intentional_discard"};if r:=Evaluate(m);!r.Accepted{t.Fatal(r)}}
func TestStrictParsing(t *testing.T){m:=base();b,_:=json.Marshal(m);if _,e:=Parse(b);e!=nil{t.Fatal(e)};if _,e:=Parse([]byte(string(b)+" {}"));e==nil{t.Fatal("trailing document accepted")};if _,e:=Parse([]byte(strings.Replace(string(b),`"id":"test-001"`,`"id":"test-001","surprise":true`,1)));e==nil{t.Fatal("unknown field accepted")}}
func TestReceiptsHaveLimitations(t *testing.T){r:=Evaluate(base());if r.Level!="declaration_only"||len(r.Limitations)<2{t.Fatal(r)}}
