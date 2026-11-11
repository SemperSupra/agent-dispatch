package authz
import rego.v1

default allow := false

allow if {
    input.principal == "worker-a"
    input.workset_ref == "synthetic:workset-a"
    input.delegation == "observe"
    data.authz.enabled == true
}
