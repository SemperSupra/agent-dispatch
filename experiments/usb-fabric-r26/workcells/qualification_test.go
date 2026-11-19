package main
import "testing"
func TestQualificationReleaseAlwaysFull(t *testing.T){
 mode,_:=qualificationMode([]string{"experiments/usb-fabric-r26/workcells/README.md"},true)
 if mode!="FULL"{t.Fatal("RC bypassed")}
}
func TestQualificationCriticalRuntimeFull(t *testing.T){
 paths:=[]string{"experiments/usb-fabric-r26/integrated/cmd/actuator/main.go",
 "experiments/usb-fabric-r26/releasegate/runtimeproof/verify.go",
 ".github/workflows/public-usbfabric-r27h5-qmp-service.yml",
 "../bad.go","experiments/usb-fabric-r26/workcells/../integrated/evil.go",
 "README.md"}
 for _,p:=range paths{m,_:=qualificationMode([]string{p},false);if m!="FULL"{t.Fatalf("critical path fast: %s",p)}}
}
func TestQualificationUnclassifiedMixedFull(t *testing.T){
 m,_:=qualificationMode([]string{"experiments/usb-fabric-r26/workcells/notes.md","unclassified/src.go"},false)
 if m!="FULL"{t.Fatal("mixed unknown path fast")}
}
func TestQualificationEmptyFailClosed(t *testing.T){
 m,_:=qualificationMode(nil,false)
 if m!="FULL"{t.Fatal("empty diff fast")}
}
func TestQualificationResearchOnlyCandidate(t *testing.T){
 m,_:=qualificationMode([]string{"experiments/usb-fabric-r26/workcells/validate_test.go","experiments/usb-fabric-r26/r27h/qmp_private_socket_dac.py"},false)
 if m!="TARGETED_CANDIDATE"{t.Fatalf("research change qualified as %s",m)}
}
func TestQualificationConfusableTraversalRejected(t *testing.T){
 paths:=[]string{"experiments/usb-fabric-r26/workcells/./x.go",
 "experiments/usb-fabric-r26/workcells//x.go",
 "experiments/usb-fabric-r26/workcells/../../integrated/foo.go",
 "experiments/usb-fabric-r26/workcells\\\\x.go"}
 for _,p:=range paths{m,_:=qualificationMode([]string{p},false);if m!="FULL"{t.Fatalf("path ambiguity admitted: %s",p)}}
}
