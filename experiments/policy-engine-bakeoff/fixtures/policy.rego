package authz
import rego.v1

default allow := false

allow if {
  input.principal == "worker-a"
  input.resource == "workset-a"
  input.action == "observe"
}
