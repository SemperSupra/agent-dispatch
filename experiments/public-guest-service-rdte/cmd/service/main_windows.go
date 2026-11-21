//go:build windows

// Public Synthetic RDTE service, not an actual remote access or credential service.
// The only observable effect is a marker file in a disposable VM's owned directory.
package main

import (
 "os"

 "golang.org/x/sys/windows/svc"
)

const serviceName = "PublicRDTECanary"

type program struct{}

func (program) Execute(_ []string, changes <-chan svc.ChangeRequest, updates chan<- svc.Status) (bool, uint32) {
 updates <- svc.Status{State: svc.StartPending}
 if err:=os.WriteFile(`C:\RDTE\public-service-running.ok`, []byte("synthetic-public-service-running-v1\n"), 0600);err!=nil{
  return false,1
 }
 running:=svc.Status{State:svc.Running,Accepts:svc.AcceptStop|svc.AcceptShutdown}
 updates<-running
 for c:=range changes{
  switch c.Cmd{
  case svc.Interrogate:
   updates<-running
  case svc.Stop,svc.Shutdown:
   updates<-svc.Status{State:svc.StopPending}
   if err:=os.WriteFile(`C:\RDTE\public-service-stopped.ok`, []byte("synthetic-public-service-stopped-v1\n"), 0600);err!=nil{
    return false,2
   }
   return false,0
  }
 }
 return false,3
}

func main(){
 if err:=svc.Run(serviceName,program{});err!=nil{os.Exit(1)}
}
