// Package audiences defines a policy-neutral, three-audience USB fabric
// operation contract. This is schema qualification, NOT a network service,
// credential issuer, USB actuator, or trusted authentication system.
package audiences

import (
 "errors"
 "strings"
)

type Audience string
const (
 Human Audience = "human"
 Automation Audience = "automation"
 Agent Audience = "agent"
)

type Operation string
const (
 Discover Operation = "discover"
 Reserve Operation = "reserve"
 Attach Operation = "attach"
 Unplug Operation = "unplug"
 Detach Operation = "detach"
 Remap Operation = "remap"
 Input Operation = "input"
 Revoke Operation = "revoke"
 StartCapture Operation = "capture.start"
 StopCapture Operation = "capture.stop"
 Watch Operation = "operation.watch"
)

type ReceiptState string
const (
 Requested ReceiptState = "requested"
 Admitted ReceiptState = "admitted"
 Actuating ReceiptState = "actuating"
 GuestConfirmed ReceiptState = "guest-confirmed"
 Failed ReceiptState = "failed"
 Quarantined ReceiptState = "quarantined"
 Completed ReceiptState = "completed"
)

type Principal struct {
 Subject string `json:"subject"`
 Audience Audience `json:"audience"`
 Permissions map[Operation]bool `json:"permissions"`
 GuestScopes map[string]bool `json:"guest_scopes"`
}

type Request struct {
 Action Operation `json:"action"`
 GuestID string `json:"guest_id"`
 DeviceID string `json:"device_id,omitempty"`
 PortID string `json:"port_id,omitempty"`
 LeaseEpoch string `json:"lease_epoch,omitempty"`
 LeaseGeneration uint64 `json:"lease_generation,omitempty"`
 IdempotencyKey string `json:"idempotency_key,omitempty"`
 InputKind string `json:"input_kind,omitempty"`
 CaptureMode string `json:"capture_mode,omitempty"`
}

type Receipt struct {
 OperationID string `json:"operation_id"`
 State ReceiptState `json:"state"`
 PolicyDecision string `json:"policy_decision"`
 DesiredState string `json:"desired_state,omitempty"`
 ObservedState string `json:"observed_state,omitempty"`
 EvidenceRefs []string `json:"evidence_refs,omitempty"`
 ErrorCode string `json:"error_code,omitempty"`
}

var ErrDenied=errors.New("usb fabric: denied contract")

func Validate(p Principal, r Request)error {
 if p.Subject=="" || (p.Audience!=Human && p.Audience!=Automation && p.Audience!=Agent) || !p.Permissions[r.Action] {
  return ErrDenied
 }
 if strings.TrimSpace(r.GuestID)=="" || !p.GuestScopes[r.GuestID] {
  return ErrDenied
 }
 switch r.Action {
 case Discover,Watch:
  return nil
 case Reserve,Attach,Unplug,Detach,Remap,Input,Revoke,StartCapture,StopCapture:
  if r.DeviceID=="" || r.PortID=="" || r.IdempotencyKey=="" || len(r.IdempotencyKey)>128 {
   return ErrDenied
  }
  // Lease creation starts without a lease generation; the broker must
  // independently allocate an authenticated generation and fresh epoch.
  if r.Action!=Reserve && (r.LeaseEpoch=="" || r.LeaseGeneration==0) {
   return ErrDenied
  }
  if r.Action==Input {
   switch r.InputKind {
   case "key-a-down","key-a-up","mouse-left-down","mouse-left-up":
   default:return ErrDenied
   }
  }
  if r.Action==StartCapture {
   // Explicitly permit metadata-only in this contract. Raw USB payload
   // requires a separate future policy and per-session authorization.
   if r.CaptureMode!="metadata" {return ErrDenied}
  }
  return nil
 default:
  return ErrDenied
 }
}
