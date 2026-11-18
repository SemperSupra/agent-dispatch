package main

import (
 "errors"
 "testing"
)

func TestReadOnlyCapabilitiesDenyEveryMutation(t *testing.T){
 p,err:=parseOperationPolicy("status,ports")
 if err!=nil{t.Fatal(err)}
 for _,op:=range []string{"status","ports"}{
  if !p.may(op){t.Fatalf("read-only %s denied",op)}
 }
 for _,op:=range []string{"reserve","attach","start","input","revoke","detach",
  "device_del","qmp","release_without_ack"}{
  if p.may(op){t.Fatalf("read-only role allowed %s",op)}
 }
 t.Log("R27D_READ_ONLY_PEER_CAPABILITIES_ENFORCED=PASS")
}
func TestExplicitInputCapabilityDoesNotImplyReserveOrStatus(t *testing.T){
 p,err:=parseOperationPolicy("input")
 if err!=nil{t.Fatal(err)}
 if !p.may("input"){t.Fatal("explicit grant ignored")}
 for _,op:=range []string{"reserve","attach","detach","status","ports"}{
  if p.may(op){t.Fatal("capability escalated into "+op)}
 }
}
func TestMalformedOrWildcardPolicyRejected(t *testing.T){
 for _,raw:=range []string{"*","all","status,","status,,ports",
 "status, status","status,status","STATUS","qmp","device_del","input\n"}{
  _,err:=parseOperationPolicy(raw)
  if !errors.Is(err,ErrCapabilityDenied){t.Fatalf("invalid policy accepted: %q -> %v",raw,err)}
 }
 t.Log("R27D_NO_WILDCARD_OR_POLICY_ESCALATION=PASS")
}
func TestLegacySyntheticCompatibilityNotProductionAuthorization(t *testing.T){
 p,err:=parseOperationPolicy("")
 if err!=nil{t.Fatal(err)}
 if p.configured{t.Fatal("legacy flag unexpectedly enabled")}
 if !p.may("input"){t.Fatal("previous standalone L9E test suite would break")}
 // This intentionally retains backward compatibility, not a production
 // default. --permitted-operations requires --authorized-peer-uid.
 t.Log("R27D_LEGACY_FULL_GRANT_IS_TEST_ONLY=NOT_PRODUCTION_AUTH")
}
