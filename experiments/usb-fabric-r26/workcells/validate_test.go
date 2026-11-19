package main
import("testing";"strings")
func validManifest() Manifest {return Manifest{Schema:1,MaxParallel:4,Cells:[]Cell{
 {ID:"a",Priority:"P0",Lane:"one",Base:strings.Repeat("a",40),Writes:[]string{"a.go"},Acceptance:"test A"},
 {ID:"b",Priority:"P0",Lane:"two",Base:strings.Repeat("b",40),Writes:[]string{"b.go"},Acceptance:"test B"},
 {ID:"c",Priority:"P1",Lane:"three",Base:strings.Repeat("c",40),Writes:[]string{"c.go"},Acceptance:"test C",Depends:[]string{"a"}},
}}}
func TestIndependentBatch(t *testing.T){if e:=validate(validManifest());e!=nil{t.Fatal(e)}}
func TestRejectDuplicateWritePath(t *testing.T){m:=validManifest();m.Cells[1].Writes=[]string{"a.go"};if validate(m)==nil{t.Fatal("shared writer admitted")}}
func TestRejectDuplicateCell(t *testing.T){m:=validManifest();m.Cells[1].ID="a";if validate(m)==nil{t.Fatal("duplicate cell admitted")}}
func TestRejectUnknownDependency(t *testing.T){m:=validManifest();m.Cells[1].Depends=[]string{"absent"};if validate(m)==nil{t.Fatal("unknown dependency admitted")}}
func TestRejectCycles(t *testing.T){m:=validManifest();m.Cells[0].Depends=[]string{"c"};if validate(m)==nil{t.Fatal("cycle admitted")}}
func TestRejectOneCellSerialDrift(t *testing.T){m:=validManifest();m.Cells=m.Cells[:1];if validate(m)==nil{t.Fatal("silent serial drift admitted")}}
func TestRejectSelfDependency(t *testing.T){m:=validManifest();m.Cells[1].Depends=[]string{"b"};if validate(m)==nil{t.Fatal("self dependency admitted")}}
func TestRejectOverBudget(t *testing.T){m:=validManifest();m.MaxParallel=5;if validate(m)==nil{t.Fatal("overbudget slots admitted")}}
