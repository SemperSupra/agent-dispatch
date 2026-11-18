// Synthetic QEMU image-builder key enrollment. Run ONLY in a disposable
// build stage controlled by the host. A private key embedded into initramfs
// is EXTRACTABLE and is NOT a production TPM/secure-boot/attested identity.
// The host pins the exported public key via builder custody, never the guest
// virtio-serial wire or untrusted guest console.
package main

import (
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "fmt"
 "os"
 "path/filepath"
)

func writeExclusive(path string,data []byte,mode os.FileMode)error{
 if !filepath.IsAbs(path){return errors.New("absolute output paths required")}
 f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,mode)
 if err!=nil{return err}
 _,err=f.Write(data)
 if err!=nil{_ = f.Close();return err}
 if err=f.Sync();err!=nil{_ = f.Close();return err}
 if err=f.Close();err!=nil{return err}
 return nil
}

func main(){
 if len(os.Args)!=3{fmt.Fprintln(os.Stderr,"usage: provision /absolute/guest-private /absolute/host-pub");os.Exit(2)}
 // Host builder controls BOTH paths and never obtains key from guest data.
 pub,priv,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(3)}
 if err=writeExclusive(os.Args[1],priv,0400);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(4)}
 if err=writeExclusive(os.Args[2],pub,0444);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(5)}
 // No pub/private material or derived fingerprint appears in CI logs.
 fmt.Println("R27C_HOST_CONTROLLED_IMAGE_KEY_PROVISIONING=PASS")
}
