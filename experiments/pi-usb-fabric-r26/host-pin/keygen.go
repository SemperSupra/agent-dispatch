//go:build ignore

// Generates a DIFFERENT disposable Ed25519 test identity for each
// uncached public runner image build. Never prints private seed.
package main

import (
  "crypto/ed25519"
  "crypto/rand"
  "encoding/hex"
  "errors"
  "os"
)
func main(){
 if len(os.Args)!=3{panic(errors.New("need seed-path and public-path"))}
 pub,private,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{panic(err)}
 seedText:=[]byte(hex.EncodeToString(private.Seed())+"\n")
 pubText:=[]byte(hex.EncodeToString(pub)+"\n")
 if err:=os.WriteFile(os.Args[1],seedText,0600);err!=nil{panic(err)}
 if err:=os.WriteFile(os.Args[2],pubText,0644);err!=nil{panic(err)}
}
