// SPDX-License-Identifier: MIT
// Package socketgate exercises a disposable, test-only TCP transport gate.
// It is not a firewall and it is NOT a USB broker.
package socketgate

import (
 "context"
 "errors"
 "net"
 "net/netip"
 "sync"
 "time"

 "github.com/SemperSupra/agent-dispatch/experiments/usb-fabric-network-n1/usbnetpolicy"
)

var ErrRevoked = errors.New("network gate revoked")
var ErrAlreadyActive = errors.New("network gate already has an active connection")

// Gate holds one active network connection. A generation must be new for each
// admission; an expired/revoked generation is never automatically replayed.
// All input decision identity fields must originate from a trusted broker.
type Gate struct {
 mu sync.Mutex
 conn net.Conn
 generation uint64
 revoked bool
}

// Connect evaluates policy before dialing; the TCP endpoint address must match
// the evaluated destination. For test purposes only, the peer is not mutually
// authenticated by this code. Deployments MUST supply identity-bound mTLS or
// a similarly authenticated overlay plus an independent network enforcer.
func (g *Gate) Connect(ctx context.Context, d usbnetpolicy.DecisionInput, sources, destinations []netip.Prefix, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
 if err := usbnetpolicy.Allowed(d, sources, destinations); err != nil { return nil, err }
 address := net.JoinHostPort(d.DestinationIP, "3240")
 g.mu.Lock()
 defer g.mu.Unlock()
 if g.revoked { return nil, ErrRevoked }
 if g.conn != nil { return nil, ErrAlreadyActive }
 if d.ActiveEpoch <= g.generation { return nil, ErrRevoked }
 // Bound dial under the lock to prevent an attach-vs-revoke race.
 bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
 defer cancel()
 conn, err := dial(bounded, "tcp", address)
 if err != nil { return nil, err }
 g.conn = conn
 g.generation = d.ActiveEpoch
 return conn, nil
}

func (g *Gate) Revoke() error {
 g.mu.Lock()
 defer g.mu.Unlock()
 g.revoked = true
 if g.conn == nil { return nil }
 err := g.conn.Close()
 g.conn = nil
 return err
}

// ResetForNewLease can be invoked only by the sole broker after it has
// independently verified release and advanced the epoch. This is not a grant.
func (g *Gate) ResetForNewLease(newEpoch uint64) error {
 g.mu.Lock()
 defer g.mu.Unlock()
 if g.conn != nil || !g.revoked || newEpoch <= g.generation {
  return ErrRevoked
 }
 g.revoked = false
 return nil
}
