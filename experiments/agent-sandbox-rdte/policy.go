// Package sandboxrdte contains a PUBLIC SYNTHETIC test fixture, not a production
// authorization engine. It cannot attest actors, sign grants, or isolate hosts.
// Real authority remains with independently governed Agent Dispatch controls.
package sandboxrdte

import (
    "errors"
    "time"
)

type Resource string

const (
    GuestRoot      Resource = "guest.root"
    GuestTools     Resource = "guest.tools"
    GuestUSB       Resource = "guest.virtual_usb"
    MockNetwork    Resource = "guest.mock_network"
    HostRecovery   Resource = "host.recovery"
    HostQMP        Resource = "host.raw_qmp"
    HostTPM        Resource = "host.physical_tpm"
    RealCredential Resource = "external.real_credential"
    RealCAC        Resource = "external.real_cac"
    RealNetwork    Resource = "external.real_network"
    RealActuation  Resource = "external.real_actuation"
)

type Request struct {
    Actor   string
    Sandbox string
    Target  Resource
}

type FixtureGrant struct {
    Actor      string
    Sandbox    string
    ValidUntil time.Time
    Revoked    bool
    Allowed    map[Resource]bool
}

// Evaluate models ONLY the deterministic policy decision to authorize simulated
// guest-local capabilities. An actual broker must independently authenticate
// actor/session, verify signed delegation, enforce host/network/device boundaries,
// reserve a one-use lease and observe effects; none exist in this fixture.
func Evaluate(now time.Time, grant FixtureGrant, req Request) error {
    if req.Actor == "" || req.Sandbox == "" || req.Actor != grant.Actor || req.Sandbox != grant.Sandbox {
        return errors.New("actor or sandbox mismatch")
    }
    if grant.Revoked || grant.ValidUntil.IsZero() || !now.Before(grant.ValidUntil) {
        return errors.New("invalid or expired simulated lease")
    }
    switch req.Target {
    case GuestRoot, GuestTools, GuestUSB, MockNetwork:
        if !grant.Allowed[req.Target] {
            return errors.New("guest capability not granted")
        }
        return nil
    case HostRecovery, HostQMP, HostTPM, RealCredential, RealCAC, RealNetwork, RealActuation:
        return errors.New("outside synthetic sandbox boundary")
    default:
        return errors.New("unknown capability denied")
    }
}
