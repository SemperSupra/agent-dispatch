// Package evidence is a deliberately narrow, fail-closed adapter between
// guest key events and the R26-L4 releasegate. It is NOT a guest sensor,
// transport, key manager, or production authentication mechanism.
package evidence

import (
    "errors"
    "sync"

    releasegate "example.org/usb-fabric-r26-releasegate"
)

var ErrUntrusted = errors.New("evidence: missing, stale, or untrusted guest event")

// Event is a testable carrier for an independently authenticated guest evdev
// event. Source and Proof MUST be attested by a separate real guest boundary;
// console output or the caller's assertion alone is insufficient.
type Event struct {
    Scope releasegate.Scope
    Source string
    KeyCode string
    Down bool
    EventSequence uint64
    Proof string
}

type Verifier func(Event) bool

type Bridge struct {
    mu sync.Mutex
    gate *releasegate.Gate
    scope releasegate.Scope
    verifier Verifier
    downSequence uint64
    lastSequence uint64
}

// New is intentionally fail-closed when no trusted event verifier is wired.
// The verifier MUST reject proofs outside the supplied guest+lease scope.
// A test-only MAC verifier is provided only in bridge_test.go.
func New(g *releasegate.Gate, scope releasegate.Scope, verifier Verifier) (*Bridge,error) {
    if g==nil || verifier==nil || scope!=g.Snapshot().Scope {
        return nil,ErrUntrusted
    }
    return &Bridge{gate:g,scope:scope,verifier:verifier},nil
}

func (b *Bridge) permitted(e Event,down bool) bool {
    return e.Scope==b.scope && e.Source=="guest.evdev" &&
        e.KeyCode=="key-a" && e.Down==down &&
        e.EventSequence>0 && e.Proof!="" &&
        b.verifier!=nil && b.verifier(e)
}

// ObserveDown must come from a signed guest event, not the actuator's
// successful QMP keydown ACK. It anchors the event sequence for key-up.
func (b *Bridge) ObserveDown(e Event)error {
    if b==nil{return ErrUntrusted}
    b.mu.Lock();defer b.mu.Unlock()
    if b.downSequence!=0 || !b.permitted(e,true) ||
        e.EventSequence<=b.lastSequence ||
        b.gate.Snapshot().Phase!=releasegate.Held {
        return ErrUntrusted
    }
    b.downSequence=e.EventSequence
    b.lastSequence=e.EventSequence
    return nil
}

// ConfirmUp refuses reuse until: authenticated down; QMP release ack already
// recorded by gate; independently authenticated guest evdev UP with a strictly
// increasing sequence; identical device and incarnation scope.
func (b *Bridge) ConfirmUp(e Event)error {
    if b==nil{return ErrUntrusted}
    b.mu.Lock();defer b.mu.Unlock()
    if b.downSequence==0 || e.EventSequence<=b.lastSequence ||
        !b.permitted(e,false) {
        return ErrUntrusted
    }
    receipt:=releasegate.Receipt{
        Scope:e.Scope,Source:e.Source,EventSequence:e.EventSequence,
        KeyReleased:true,Proof:e.Proof,
    }
    // Proof already verified over the exact full Event including Down=false.
    // Never treat a free-form QMP ACK or serial text as trusted evidence.
    if err:=b.gate.ConfirmGuest(receipt,func(r releasegate.Receipt)bool {
        return r.Scope==e.Scope && r.Source==e.Source &&
            r.EventSequence==e.EventSequence && r.Proof==e.Proof &&
            r.KeyReleased && b.verifier(e)
    });err!=nil{return ErrUntrusted}
    b.lastSequence=e.EventSequence
    return nil
}

func (b *Bridge) Reclaimable() bool {
    return b!=nil && b.gate!=nil && b.gate.Reclaimable()
}
