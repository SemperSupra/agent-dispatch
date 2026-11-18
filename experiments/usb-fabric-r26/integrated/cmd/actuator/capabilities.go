package main

import (
 "errors"
 "strings"
)

var ErrCapabilityDenied=errors.New("actuator: operation outside authenticated peer grant")

// operationPolicy is an optional capability allowlist OVER the real kernel
// SO_PEERCRED UID check, not an alternative identity source. The principal
// supplies no role/capability fields in JSON. A same-UID adversary is still
// able to impersonate that UID: this is a synthetic service experiment.
type operationPolicy struct{
 configured bool
 allowed map[string]bool
}
var availableOperations=map[string]bool{
 "status":true,"ports":true,"reserve":true,"attach":true,
 "start":true,"input":true,"revoke":true,"detach":true,
}
func parseOperationPolicy(raw string)(operationPolicy,error){
 if raw==""{return operationPolicy{},nil} // backward compatible legacy test mode
 policy:=operationPolicy{configured:true,allowed:make(map[string]bool)}
 for _,token:=range strings.Split(raw,","){
  if token=="" || token!=strings.TrimSpace(token) ||
   !availableOperations[token] || policy.allowed[token]{
   return operationPolicy{},ErrCapabilityDenied
  }
  policy.allowed[token]=true
 }
 if len(policy.allowed)==0{return operationPolicy{},ErrCapabilityDenied}
 return policy,nil
}
func (p operationPolicy)may(op string)bool{
 return availableOperations[op] && (!p.configured||p.allowed[op])
}
