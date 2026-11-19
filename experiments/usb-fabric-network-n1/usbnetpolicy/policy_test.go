// SPDX-License-Identifier: MIT
package usbnetpolicy
import (
 "net/netip"
 "testing"
)
func TestDenyByDefaultAndAdversarialPaths(t *testing.T) {
 sources:=[]netip.Prefix{netip.MustParsePrefix("10.77.20.0/24")}
 destinations:=[]netip.Prefix{netip.MustParsePrefix("10.77.30.0/24")}
 valid:=DecisionInput{SourceIP:"10.77.20.2",DestinationIP:"10.77.30.3",DestinationPort:3240,Transport:"usbip-tcp",DeviceID:"d1",PrincipalID:"p1",LeaseDeviceID:"d1",LeasePrincipalID:"p1",LeaseEpoch:7,ActiveEpoch:7,LeaseActive:true,Authenticated:true,PathAuthenticated:true}
 if err:=Allowed(valid,sources,destinations);err!=nil {t.Fatalf("valid authenticated lease denied: %v",err)}
 cases:=map[string]func(*DecisionInput){
  "missing identity":func(x *DecisionInput){x.Authenticated=false},
  "untrusted path":func(x *DecisionInput){x.PathAuthenticated=false},
  "inactive lease":func(x *DecisionInput){x.LeaseActive=false},
  "stale epoch":func(x *DecisionInput){x.LeaseEpoch=6},
  "zero epoch":func(x *DecisionInput){x.ActiveEpoch=0;x.LeaseEpoch=0},
  "wrong device":func(x *DecisionInput){x.LeaseDeviceID="d2"},
  "wrong principal":func(x *DecisionInput){x.LeasePrincipalID="p2"},
  "bad port":func(x *DecisionInput){x.DestinationPort=7575},
  "unexpected protocol":func(x *DecisionInput){x.Transport="udp"},
  "source outside prefix":func(x *DecisionInput){x.SourceIP="10.77.21.2"},
  "destination outside prefix":func(x *DecisionInput){x.DestinationIP="10.77.40.3"},
  "invalid source":func(x *DecisionInput){x.SourceIP="bad"},
  "mapped IPv4":func(x *DecisionInput){x.SourceIP="::ffff:10.77.20.2"},
  "link local zone":func(x *DecisionInput){x.SourceIP="fe80::1%eth0"},
  "multicast":func(x *DecisionInput){x.SourceIP="224.0.0.1"},
 }
 for name,mutate:=range cases {t.Run(name,func(t *testing.T){x:=valid;mutate(&x);if Allowed(x,sources,destinations)==nil {t.Fatal("fail-open")}})}
 t.Run("no prefix allowlist",func(t *testing.T){if Allowed(valid,nil,destinations)==nil{t.Fatal("fail-open")}})
 t.Run("unmasked prefix denied",func(t *testing.T){if Allowed(valid,[]netip.Prefix{netip.MustParsePrefix("10.77.20.6/24")},destinations)==nil{t.Fatal("fail-open")}})
}
