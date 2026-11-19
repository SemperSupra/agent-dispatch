package identity

// R25-A is a TEST-ONLY composition seam, not a second QMP controller,
// USB/IP implementation, exporter, or authoritative guest identity service.
// Its two inputs MUST be independently qualified by the actual R26 QMP
// actuator and the actual signed USBIP VHCI evdev observation in a later
// integrated experiment. A fixture callback is not production authority.

import (
    "errors"

    "example.org/usb-fabric-r26-integrated/blue"
    "example.org/usb-fabric-r26-releasegate/evidence"
    samelease "example.org/usb-fabric-r23-same-lease-qmp"
)

var ErrHandoff = errors.New("r25: independently matched QMP/USBIP lease release required")

type Handoff struct {
    pair *Pair
    guard *samelease.Guard
}

// NewHandoff refuses to join distinct managers/scopes; callers cannot
// borrow a verified QMP receipt from a different active lease generation.
func NewHandoff(pair *Pair, guard *samelease.Guard) (*Handoff, error) {
    if pair == nil || guard == nil || pair.Lease != guard.Lease ||
        pair.Scope != guard.Scope || guard.Gate == nil ||
        guard.Bridge == nil || guard.Export == nil {
        return nil, ErrHandoff
    }
    return &Handoff{pair:pair,guard:guard},nil
}

// Commit requires the existing R24 one-use cross-device witness before the
// R23 bridge can clear R22 durable HELD state and authorize exporter binding.
// A partially accepted pair is deliberately NOT retryable. The surrounding
// owner must quarantine and create a new verified epoch on failure.
func (h *Handoff) Commit(q QMPWitness, u USBIPWitness, up evidence.Event) error {
    if h == nil {return ErrHandoff}
    // R25-C: a verified VHCI guest-UP receipt and a separately verified
    // signed guest-UP must reference the SAME actual event, not just the
    // same VM and lease. Reject *before* consuming the one-use QMP pair
    // or changing the durable held journal / physical exporter.
    if up.Scope != h.pair.Scope || up.Down ||
        up.Source != "guest.evdev" || up.KeyCode != "key-a" ||
        up.EventSequence == 0 || up.EventSequence != u.EventSequence ||
        !u.GuestUP {
        return ErrHandoff
    }
    if err:=h.pair.Authorize(q,u);err!=nil {return err}
    if err:=h.guard.ConfirmAndBind(up);err!=nil{return err}
    return nil
}

// ReserveNext exposes the preexisting R22 exporter admission gate. It
// remains closed while the original manager has not verified and bound UDC.
func (h *Handoff) ReserveNext(actor string) (blue.Lease,error) {
    if h==nil{return blue.Lease{},ErrHandoff}
    return h.guard.ReserveNext(actor)
}
