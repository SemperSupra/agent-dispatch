// Finite reference model of two synthetic users of a shared queue selector.
// This models harness serialization, not QEMU internal thread safety.
package model

type State struct {
 A, B, Selected uint8
 PresentPFN, AbsentPFN uint32
 WrongWrite, WrongRead, AbsentMutation bool
}
type Step struct { Actor, Action string; State State }
type Result struct {
 Schedules, Safe, Unsafe, UniqueStates int
 WrongWrite, WrongRead, AbsentMutation int
 FirstViolation []Step
}

// Explore enumerates all schedules of two ordered two-operation actors.
// A selects absent queue 1 and writes PFN=1; B selects present queue 0 and reads.
// serialized means the selector+operation pair is indivisible at this model
// boundary. mutant means the absent queue accepts a PFN write.
func Explore(serialized, mutant bool) Result {
 var r Result
 seen:=map[State]bool{}
 var visit func(State,[]Step)
 visit=func(s State, trace []Step) {
  seen[s]=true
  if s.A==2&&s.B==2 {
   r.Schedules++
   if s.WrongWrite {r.WrongWrite++}
   if s.WrongRead {r.WrongRead++}
   if s.AbsentMutation {r.AbsentMutation++}
   if s.WrongWrite||s.WrongRead||s.AbsentMutation {
    r.Unsafe++
    if r.FirstViolation==nil {r.FirstViolation=append([]Step(nil),trace...)}
   } else {r.Safe++}
   return
  }
  if s.A<2&&(!serialized||s.B!=1) {
   t:=s; action:="select-absent"
   if s.A==0 {t.Selected=1} else {
    action="write-pfn"
    if t.Selected==0 {t.PresentPFN=1;t.WrongWrite=true
    } else if mutant {t.AbsentPFN=1;t.AbsentMutation=true}
   }
   t.A++
   visit(t,append(append([]Step(nil),trace...),Step{"A",action,t}))
  }
  if s.B<2&&(!serialized||s.A!=1) {
   t:=s; action:="select-present"
   if s.B==0 {t.Selected=0} else {
    action="read-pfn"
    if t.Selected!=0 {t.WrongRead=true}
   }
   t.B++
   visit(t,append(append([]Step(nil),trace...),Step{"B",action,t}))
  }
 }
 visit(State{},nil); r.UniqueStates=len(seen);return r
}
