// Package proof holds the independent expected lifecycle, not an issuer or installer.
package proof

import (
 "errors"
 "fmt"
)
var Steps=[]string{"BINARY_VERIFIED","SERVICE_CREATED","SERVICE_RUNNING","IDEMPOTENT_READBACK","WRONG_HASH_DENIED","SERVICE_STOPPED","SERVICE_REMOVED","BINARY_REMOVED","GUEST_REMOVED"}
type Event struct{Stage string `json:"stage"`; Success bool `json:"success"`}
func Verify(events []Event)error{
 if len(events)!=len(Steps){return fmt.Errorf("expected %d independent stages, observed %d",len(Steps),len(events))}
 for i,expected:=range Steps{
  if events[i].Stage!=expected{return fmt.Errorf("stage %d: wanted %s, got %s",i,expected,events[i].Stage)}
  if !events[i].Success{return errors.New("oracle not satisfied: "+expected)}
 }
 return nil
}
