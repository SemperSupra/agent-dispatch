// Command attack is a disposable hostile first-enrollment critic.
// It signs a QEMU-console-origin claim with a valid attacker-generated key,
// attempting to pin that key before the real guest evdev DOWN arrives.
// No secrets, network, physical USB, or production environment is used.
package main
import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "os"

 "example.org/usb-fabric-r26-releasegate/evidence"
 "example.org/usb-fabric-r26-releasegate/guestwire"
)
func main(){
 if len(os.Args)!=2{os.Exit(2)}
 raw,err:=hex.DecodeString(os.Args[1]);if err!=nil||len(raw)!=32{os.Exit(3)}
 var nonce [32]byte;copy(nonce[:],raw)
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{os.Exit(4)}
 event:=evidence.Event{Scope:guestwire.Scope(),Source:"qemu.serial",KeyCode:"key-a",Down:true,EventSequence:1,Proof:""}
 b,err:=json.Marshal(struct {
  Domain string
  Event evidence.Event
  Challenge [32]byte
 }{Domain:"USB-FABRIC-R22-TEST-ONLY-ED25519-v1",Event:event,Challenge:nonce})
 if err!=nil{os.Exit(5)}
 encoded,err:=json.Marshal(event);if err!=nil{os.Exit(6)}
 var v map[string]any
 if err=json.Unmarshal(encoded,&v);err!=nil{os.Exit(7)}
 v["r22_pub"]=hex.EncodeToString(pub)
 v["r22_sig"]=hex.EncodeToString(ed25519.Sign(priv,b))
 out,err:=json.Marshal(v);if err!=nil{os.Exit(8)}
 fmt.Println(string(out))
}
