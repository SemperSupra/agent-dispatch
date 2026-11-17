package testcac
import(
 "crypto/rand"
 "errors"
 "testing"
)
func card(t *testing.T)*Card{
 t.Helper();c,e:=NewTestCard([]byte("TEST_ONLY_246813"))
 if e!=nil{t.Fatal(e)}
 return c
}
func prompt(pin string)Prompt{return func()([]byte,error){return []byte(pin),nil}}
func TestFullSyntheticInsertPINCertificateChallengeSignatureLogoutRemoval(t *testing.T){
 c:=card(t)
 if _,e:=c.Certificate();!errors.Is(e,ErrNoCard){t.Fatal("certificate before insertion")}
 c.Insert()
 cert,e:=c.Certificate();if e!=nil{t.Fatal(e)}
 challenge:=make([]byte,32)
 if _,e=rand.Read(challenge);e!=nil{t.Fatal(e)}
 if _,e=c.Sign(challenge);!errors.Is(e,ErrNoSession){t.Fatal("sign without PIN")}
 entered:=[]byte("TEST_ONLY_246813")
 if e=c.EnterPIN(func()([]byte,error){return entered,nil});e!=nil{t.Fatal(e)}
 for _,v:=range entered{if v!=0{t.Fatal("test PIN not wiped after entry")}}
 sig,e:=c.Sign(challenge);if e!=nil{t.Fatal(e)}
 if e=c.VerifyChallenge(challenge,sig,cert);e!=nil{t.Fatal(e)}
 tampered:=append([]byte(nil),challenge...);tampered[0]^=1
 if e=c.VerifyChallenge(tampered,sig,cert);!errors.Is(e,ErrUntrusted){t.Fatal("tampered challenge validated")}
 c.Logout()
 if _,e=c.Sign(challenge);!errors.Is(e,ErrNoSession){t.Fatal("sign after logout")}
 if e=c.EnterPIN(prompt("TEST_ONLY_246813"));e!=nil{t.Fatal(e)}
 c.Remove()
 if _,e=c.Sign(challenge);!errors.Is(e,ErrNoCard){t.Fatal("sign after card removal")}
 c.Insert()
 if _,e=c.Sign(challenge);!errors.Is(e,ErrNoSession){t.Fatal("stale session after reinsertion")}
 t.Log("R26_P1_SYNTHETIC_CAC_INSERT_PIN_SIGN_VERIFY_LOGOUT_REMOVE_REINSERT=PASS")
}
func TestWrongPINRetriesAndSyntheticCardLockout(t *testing.T){
 c:=card(t);c.Insert()
 for i:=2;i>=0;i--{
  e:=c.EnterPIN(prompt("WRONG_TEST_ONLY"))
  if i==0 && !errors.Is(e,ErrBlocked){t.Fatal("third wrong synthetic PIN did not block")}
  if i>0 && !errors.Is(e,ErrPIN){t.Fatal("wrong test PIN not rejected")}
  if c.RetryLeft()!=i{t.Fatal("retry counter incorrect")}
 }
 if e:=c.EnterPIN(prompt("TEST_ONLY_246813"));!errors.Is(e,ErrBlocked){t.Fatal("lockout circumvented")}
 t.Log("R26_P1_SYNTHETIC_PIN_WRONG_RETRY_LOCKOUT=PASS")
}
func TestPINEntryAndSigningWithoutCardDenied(t *testing.T){
 c:=card(t)
 if e:=c.EnterPIN(prompt("TEST_ONLY_246813"));!errors.Is(e,ErrNoCard){t.Fatal("PIN entered without card")}
 if _,e:=c.Sign(make([]byte,32));!errors.Is(e,ErrNoCard){t.Fatal("signed without card")}
 c.Insert()
 if e:=c.EnterPIN(prompt("TEST_ONLY_246813"));e!=nil{t.Fatal(e)}
 if _,e:=c.Sign([]byte("short"));!errors.Is(e,ErrUntrusted){t.Fatal("malformed challenge allowed")}
 t.Log("R26_P1_SYNTHETIC_MISSING_CARD_MALFORMED_CHALLENGE_DENIED=PASS")
}
