package main
import "testing"
func TestPartialMitigationDoesNotClearRED(t *testing.T){
 m:=mitigated();m.Candidates[1].ThreatScope="same-uid-any-qmp";
 m.Candidates[1].MitigationScope="postseal-new-qmp-session"
 ready,err:=assess(m);if err!=nil||ready{t.Fatal("partial security mitigation promoted",ready,err)}
}
func TestResidualFDThreatBlocksAfterMatchingScope(t *testing.T){
 m:=mitigated();m.Candidates[1].ResidualRisks=[]string{"existing-raw-qmp-fd"}
 ready,err:=assess(m);if err!=nil||ready{t.Fatal("existing FDs ignored",ready,err)}
}
func TestResidualCompromisedServiceBlocks(t *testing.T){
 m:=mitigated();m.Candidates[1].ResidualRisks=[]string{"compromised-service-uid","ptrace"}
 ready,err:=assess(m);if err!=nil||ready{t.Fatal("service actor compromise ignored",ready,err)}
}
func TestMissingThreatScopeBlocks(t *testing.T){
 m:=mitigated();m.Candidates[1].ThreatScope=""
 ready,err:=assess(m);if err!=nil||ready{t.Fatal("missing threat bounds accepted",ready,err)}
}
func TestMissingMitigationScopeBlocks(t *testing.T){
 m:=mitigated();m.Candidates[1].MitigationScope=""
 ready,err:=assess(m);if err!=nil||ready{t.Fatal("missing mitigation coverage accepted",ready,err)}
}
func TestExactScopeNoResidualPermitsReadiness(t *testing.T){
 m:=mitigated();ready,err:=assess(m);if err!=nil||!ready{t.Fatal("qualified exact coverage wrongly blocked",ready,err)}
}
func TestManifestStillBlockedForKnownResidual(t *testing.T){
 m:=mitigated();m.Candidates[1].ResidualRisks=[]string{"service-uid-existing-fd"}
 m.Blockers=nil
 ready,err:=assess(m);if err!=nil||ready{t.Fatal("unknown critical exploit promoted",ready,err)}
}
