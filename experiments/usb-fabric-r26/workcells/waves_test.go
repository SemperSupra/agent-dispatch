package main
import("reflect";"testing";"strings")
func c(id,priority string,deps ...string)Cell{return Cell{ID:id,Priority:priority,Lane:id,Base:strings.Repeat("a",40),Writes:[]string{id+".go"},Depends:deps,Acceptance:"verify "+id}}
func TestWavesParallelP0First(t *testing.T){
 m:=Manifest{Schema:1,MaxParallel:3,Cells:[]Cell{c("b","P0"),c("a","P0"),c("c","P1"),c("d","P0"),c("e","P0")}}
 got,e:=planWaves(m);if e!=nil{t.Fatal(e)}
 want:=[][]string{{"a","b","d"},{"e","c"}}
 if !reflect.DeepEqual(got,want){t.Fatalf("got %v want %v",got,want)}
}
func TestWavesDependencyBarrier(t *testing.T){
 m:=Manifest{Schema:1,MaxParallel:4,Cells:[]Cell{c("join","P0","left","right"),c("right","P0"),c("left","P0"),c("misc","P1")}}
 got,e:=planWaves(m);if e!=nil{t.Fatal(e)}
 want:=[][]string{{"left","right","misc"},{"join"}}
 if !reflect.DeepEqual(got,want){t.Fatalf("got %v want %v",got,want)}
}
func TestWavesMissingDependenciesRefused(t *testing.T){
 m:=Manifest{Schema:1,MaxParallel:2,Cells:[]Cell{c("a","P0","missing"),c("b","P0")}}
 if _,e:=planWaves(m);e==nil{t.Fatal("invalid DAG accepted")}
}
func TestWavesRepeatDeterministic(t *testing.T){
 m:=Manifest{Schema:1,MaxParallel:2,Cells:[]Cell{c("c","P0"),c("a","P0"),c("b","P0"),c("d","P1")}}
 first,e:=planWaves(m);if e!=nil{t.Fatal(e)}
 for i:=0;i<100;i++{again,e:=planWaves(m);if e!=nil||!reflect.DeepEqual(first,again){t.Fatalf("nondeterministic scheduling %v %v",first,again)}}
}
func TestWavesNoFalseDependencySerialization(t *testing.T){
 m:=Manifest{Schema:1,MaxParallel:4,Cells:[]Cell{c("a","P0"),c("b","P0"),c("c","P1"),c("d","P0")}}
 got,e:=planWaves(m);if e!=nil{t.Fatal(e)}
 if len(got)!=1||len(got[0])!=4{t.Fatalf("independent work collapsed serially: %v",got)}
}
