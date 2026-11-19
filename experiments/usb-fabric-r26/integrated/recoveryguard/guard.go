package recoveryguard
import(
 "errors"
 "example.org/usb-fabric-r26-integrated/heldledger"
)
// VerifyEmergencyHold must run after a *QMP-only* emergency key-up.
// The QMP ACK is never an independent guest UP and cannot clear the ledger.
func VerifyEmergencyHold(before,after heldledger.State)error{
 if !before.Held{return errors.New("emergency release without original HELD proof")}
 if !after.Held{return errors.New("QMP-only emergency released HELD without signed guest evidence")}
 if after.Sequence!=before.Sequence{return errors.New("journal sequence changed before guest release")}
 if after.ReleasePhase!=before.ReleasePhase{return errors.New("journal release phase mutated without guest release")}
 return nil
}
