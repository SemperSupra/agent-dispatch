package main
import ("errors";"fmt";"strings")

// TrustClaim is a verification input, not an attestation primitive.
// A software image's extractable test signing key must never be promoted to
// production measured-boot/guest-key custody.
type TrustClaim struct {
 Mode string
 HostPrePinned bool
 FreshChallenge bool
 ScopeBound bool
 SigningKeyExtractable bool
 MeasuredBootVerified bool
 QuoteBoundToBoot bool
 TrustedAKChain bool
}
func qualifyClaim(c TrustClaim)error{
 if !c.HostPrePinned||!c.FreshChallenge||!c.ScopeBound{
  return errors.New("host/epoch/lease challenge not verified")
 }
 switch strings.ToLower(c.Mode){
 case "synthetic":
  return nil
 case "production":
  if c.SigningKeyExtractable{return errors.New("extractable guest signing key forbidden")}
  if !c.MeasuredBootVerified||!c.QuoteBoundToBoot||!c.TrustedAKChain{
   return errors.New("untrusted TPM/measured-boot lineage")
  }
  return nil
 default:
  return fmt.Errorf("unknown trust mode %q",c.Mode)
 }
}
