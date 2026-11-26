package model
import ("testing";"reflect")
func TestInterleavings(t *testing.T){
 for _,c:=range []struct{name string; serialized,mutant bool; schedules,safe,unsafe,wrongWrite,wrongRead,absent int}{
 {"unserialized",false,false,6,2,4,2,2,0},
 {"serialized",true,false,2,2,0,0,0,0},
 {"serialized-mutant",true,true,2,0,2,0,0,2},
 {"unserialized-mutant",false,true,6,0,6,2,2,4},
 }{t.Run(c.name,func(t *testing.T){
 r:=Explore(c.serialized,c.mutant)
 if r.Schedules!=c.schedules||r.Safe!=c.safe||r.Unsafe!=c.unsafe||r.WrongWrite!=c.wrongWrite||r.WrongRead!=c.wrongRead||r.AbsentMutation!=c.absent{t.Fatalf("unexpected %+v",r)}
 if !reflect.DeepEqual(r,Explore(c.serialized,c.mutant)){t.Fatal("nondeterministic")}
 if r.Unsafe>0&&len(r.FirstViolation)!=4{t.Fatal("missing complete witness")}
 t.Logf("schedules=%d safe=%d unsafe=%d unique_states=%d wrong_write=%d wrong_read=%d absent_mutation=%d witness=%+v",r.Schedules,r.Safe,r.Unsafe,r.UniqueStates,r.WrongWrite,r.WrongRead,r.AbsentMutation,r.FirstViolation)
 })}
}
