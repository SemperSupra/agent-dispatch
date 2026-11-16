package sandboxrdte

import (
    "testing"
    "time"
)

func TestHighFreedomUnknownActorInsideSyntheticGuest(t *testing.T) {
    now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
    grant := FixtureGrant{
        Actor: "unqualified-agent",
        Sandbox: "disposable-test-vm-01",
        ValidUntil: now.Add(time.Minute),
        Allowed: map[Resource]bool{
            GuestRoot: true, GuestTools: true, GuestUSB: true, MockNetwork: true,
            // Even an erroneously broad incoming grant never authorizes a host resource.
            HostRecovery: true, HostQMP: true, HostTPM: true, RealCredential: true,
            RealCAC: true, RealNetwork: true, RealActuation: true,
        },
    }
    permitted := []Resource{GuestRoot, GuestTools, GuestUSB, MockNetwork}
    for _, cap := range permitted {
        if err := Evaluate(now, grant, Request{grant.Actor, grant.Sandbox, cap}); err != nil {
            t.Errorf("synthetic freedom for %q should be permitted: %v", cap, err)
        }
    }
    forbidden := []Resource{HostRecovery, HostQMP, HostTPM, RealCredential, RealCAC, RealNetwork, RealActuation, "external.unknown"}
    for _, cap := range forbidden {
        if err := Evaluate(now, grant, Request{grant.Actor, grant.Sandbox, cap}); err == nil {
            t.Errorf("external authority %q must fail closed even with malicious broad grant", cap)
        }
    }
}

func TestScopeLeaseAndRevocation(t *testing.T) {
    now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
    grant := FixtureGrant{
        Actor: "actor-1", Sandbox: "vm-1", ValidUntil: now.Add(time.Second),
        Allowed: map[Resource]bool{GuestRoot: true},
    }
    tests := []struct {
        name string
        when time.Time
        change func(*FixtureGrant, *Request)
        allow bool
    }{
        {"in-scope", now, func(*FixtureGrant, *Request) {}, true},
        {"expired", now.Add(time.Second), func(*FixtureGrant, *Request) {}, false},
        {"other-actor", now, func(_ *FixtureGrant, r *Request) { r.Actor = "actor-2" }, false},
        {"other-sandbox", now, func(_ *FixtureGrant, r *Request) { r.Sandbox = "vm-2" }, false},
        {"revoked", now, func(g *FixtureGrant, _ *Request) { g.Revoked = true }, false},
        {"missing-scope", now, func(_ *FixtureGrant, r *Request) { r.Target = GuestUSB }, false},
        {"unknown", now, func(_ *FixtureGrant, r *Request) { r.Target = "guest.unknown" }, false},
    }
    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            g := grant
            req := Request{Actor: grant.Actor, Sandbox: grant.Sandbox, Target: GuestRoot}
            tc.change(&g, &req)
            got := Evaluate(tc.when, g, req) == nil
            if got != tc.allow {
                t.Fatalf("allow=%v want=%v", got, tc.allow)
            }
        })
    }
}

func TestZeroGrantCannotSelfAuthorize(t *testing.T) {
    if err := Evaluate(time.Now(), FixtureGrant{}, Request{Actor: "attacker", Sandbox: "vm", Target: GuestRoot}); err == nil {
        t.Fatal("zero-value or forged actor grant unexpectedly permitted")
    }
}
