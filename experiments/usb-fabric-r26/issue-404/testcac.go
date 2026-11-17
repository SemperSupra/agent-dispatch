// Package testcac models a synthetic test-only CAC PIN and signing lifecycle.
// It is not an issued CAC, an OS credential provider or a PC/SC transport.
// The PIN is entered via an injected one-use prompt callback; real products
// must use approved protected PIN entry paths, never keyboard replay.
package testcac
import (
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "crypto/subtle"
 "errors"
 "sync"
 "time"
)
var(
 ErrNoCard=errors.New("testcac: no card")
 ErrPIN=errors.New("testcac: wrong synthetic test PIN")
 ErrBlocked=errors.New("testcac: synthetic card PIN blocked")
 ErrNoSession=errors.New("testcac: not authenticated")
 ErrUntrusted=errors.New("testcac: untrusted reader or card incarnation")
)
type Result struct{
 RetryLeft int
 Signed bool
}
type Certificate struct{
 Subject string
 Serial string
 PublicKey ed25519.PublicKey
}
type Prompt func()([]byte,error)
type Card struct{
 mu sync.Mutex
 inserted bool
 blocked bool
 retries int
 incarnation uint64
 secretDigest [32]byte
 priv ed25519.PrivateKey
 pub ed25519.PublicKey
 authenticated bool
 boundIncarnation uint64
 expire time.Time
}
func NewTestCard(pin []byte)(*Card,error){
 pub,priv,e:=ed25519.GenerateKey(rand.Reader)
 if e!=nil{return nil,e}
 c:=&Card{secretDigest:sha256.Sum256(pin),priv:priv,pub:pub,retries:3}
 return c,nil
}
func wipe(pin []byte){for i:=range pin{pin[i]=0}}
func(c *Card) Insert(){c.mu.Lock();defer c.mu.Unlock();c.inserted=true;c.incarnation++;c.authenticated=false;c.boundIncarnation=0}
func(c *Card) Remove(){c.mu.Lock();defer c.mu.Unlock();c.inserted=false;c.incarnation++;c.authenticated=false;c.boundIncarnation=0}
func(c *Card) Certificate()(Certificate,error){
 c.mu.Lock();defer c.mu.Unlock()
 if !c.inserted{return Certificate{},ErrNoCard}
 return Certificate{Subject:"CN=R26 SYNTHETIC TEST CARD ONLY",
  Serial:"TEST-ONLY-0001",PublicKey:append([]byte(nil),c.pub...)},nil
}
func(c *Card) EnterPIN(prompt Prompt)error{
 if prompt==nil{return ErrPIN}
 pin,e:=prompt()
 if e!=nil{return e}
 defer wipe(pin)
 supplied:=sha256.Sum256(pin)
 c.mu.Lock();defer c.mu.Unlock()
 if !c.inserted{return ErrNoCard}
 if c.blocked{return ErrBlocked}
 // There must be a real attempted test PIN check, not a fake success token.
 if subtle.ConstantTimeCompare(supplied[:],c.secretDigest[:])!=1{
  c.retries--
  c.authenticated=false
  if c.retries<=0{c.blocked=true;return ErrBlocked}
  return ErrPIN
 }
 c.retries=3
 c.authenticated=true
 c.boundIncarnation=c.incarnation
 c.expire=time.Now().Add(2*time.Second)
 return nil
}
func(c *Card) Sign(challenge []byte)([]byte,error){
 c.mu.Lock();defer c.mu.Unlock()
 if !c.inserted{return nil,ErrNoCard}
 if !c.authenticated||c.boundIncarnation!=c.incarnation||time.Now().After(c.expire){return nil,ErrNoSession}
 if len(challenge)!=32{return nil,ErrUntrusted}
 return ed25519.Sign(c.priv,challenge),nil
}
func(c *Card) Logout(){c.mu.Lock();defer c.mu.Unlock();c.authenticated=false}
func(c *Card) RetryLeft()int{c.mu.Lock();defer c.mu.Unlock();return c.retries}
func(c *Card) VerifyChallenge(challenge,sig []byte,expected Certificate)error{
 c.mu.Lock();defer c.mu.Unlock()
 if !c.inserted||expected.Serial!="TEST-ONLY-0001"||
  subtle.ConstantTimeCompare(expected.PublicKey,c.pub)!=1{return ErrUntrusted}
 if len(challenge)!=32||!ed25519.Verify(c.pub,challenge,sig){return ErrUntrusted}
 return nil
}
