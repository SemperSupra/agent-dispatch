// SPDX-License-Identifier: MIT
// usbnetpolicy is a fail-closed, source-only decision model.
// It does NOT change host firewall or grant a USB lease.
package usbnetpolicy

import (
 "errors"
 "net/netip"
)

type DecisionInput struct {
 SourceIP string
 DestinationIP string
 DestinationPort uint16
 Transport string
 DeviceID string
 PrincipalID string
 LeaseDeviceID string
 LeasePrincipalID string
 LeaseEpoch uint64
 ActiveEpoch uint64
 LeaseActive bool
 Authenticated bool
 PathAuthenticated bool
}
var ErrDenied = errors.New("network USB attachment denied")

// Allowed only evaluates whether an already-authorized lease may use an
// authenticated and explicitly bounded network path. The broker grants leases.
func Allowed(x DecisionInput, allowedSources, allowedDestinations []netip.Prefix) error {
 if !x.Authenticated || !x.PathAuthenticated || !x.LeaseActive ||
   x.DeviceID == "" || x.PrincipalID == "" ||
   x.DeviceID != x.LeaseDeviceID || x.PrincipalID != x.LeasePrincipalID ||
   x.ActiveEpoch == 0 || x.LeaseEpoch != x.ActiveEpoch {
  return ErrDenied
 }
 if x.Transport != "usbip-tcp" || x.DestinationPort != 3240 { return ErrDenied }
 src, err1 := netip.ParseAddr(x.SourceIP)
 dst, err2 := netip.ParseAddr(x.DestinationIP)
 if err1 != nil || err2 != nil || !src.IsValid() || !dst.IsValid() ||
    src.Is4In6() || dst.Is4In6() || src.Zone() != "" || dst.Zone() != "" ||
    src.IsMulticast() || dst.IsMulticast() || src.IsUnspecified() || dst.IsUnspecified() {
  return ErrDenied
 }
 in := func(ip netip.Addr, prefixes []netip.Prefix) bool {
  for _, p := range prefixes {
   if p.IsValid() && p.Masked() == p && p.Contains(ip) { return true }
  }
  return false
 }
 if !in(src, allowedSources) || !in(dst, allowedDestinations) { return ErrDenied }
 return nil
}
