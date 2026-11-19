package main
import "testing"
func synthetic()TrustClaim{return TrustClaim{Mode:"synthetic",HostPrePinned:true,FreshChallenge:true,ScopeBound:true,SigningKeyExtractable:true}}
func TestExtractableTestOnlySyntheticAccepted(t *testing.T){if e:=qualifyClaim(synthetic());e!=nil{t.Fatal(e)}}
func TestExtractableCannotBecomeProduction(t *testing.T){c:=synthetic();c.Mode="production";c.MeasuredBootVerified=true;c.QuoteBoundToBoot=true;c.TrustedAKChain=true;if qualifyClaim(c)==nil{t.Fatal("extractable test key promoted")}}
func TestSoftwareQuoteWithoutChainRejected(t *testing.T){c:=synthetic();c.Mode="production";c.SigningKeyExtractable=false;c.MeasuredBootVerified=true;c.QuoteBoundToBoot=true;if qualifyClaim(c)==nil{t.Fatal("software TPM quote without trusted AK chain promoted")}}
func TestUnboundQuoteRejected(t *testing.T){c:=synthetic();c.Mode="production";c.SigningKeyExtractable=false;c.MeasuredBootVerified=true;c.TrustedAKChain=true;if qualifyClaim(c)==nil{t.Fatal("unbound quote promoted")}}
func TestUnmeasuredBootRejected(t *testing.T){c:=synthetic();c.Mode="production";c.SigningKeyExtractable=false;c.QuoteBoundToBoot=true;c.TrustedAKChain=true;if qualifyClaim(c)==nil{t.Fatal("unmeasured guest promoted")}}
func TestHostTOFURejected(t *testing.T){c:=synthetic();c.HostPrePinned=false;if qualifyClaim(c)==nil{t.Fatal("guest-supplied key accepted as trust authority")}}
func TestStaleChallengeRejected(t *testing.T){c:=synthetic();c.FreshChallenge=false;if qualifyClaim(c)==nil{t.Fatal("stale challenge accepted")}}
func TestScopeNotBoundRejected(t *testing.T){c:=synthetic();c.ScopeBound=false;if qualifyClaim(c)==nil{t.Fatal("unscoped guest event accepted")}}
func TestUnknownModeRejected(t *testing.T){c:=synthetic();c.Mode="enterprise-ish";if qualifyClaim(c)==nil{t.Fatal("ambiguous trust mode accepted")}}
func TestProductionFormalPositiveControl(t *testing.T){c:=synthetic();c.Mode="production";c.SigningKeyExtractable=false;c.MeasuredBootVerified=true;c.QuoteBoundToBoot=true;c.TrustedAKChain=true;if e:=qualifyClaim(c);e!=nil{t.Fatal(e)}}
