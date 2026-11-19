package main
import ("testing";"strings")
func baseRC()RC{return RC{Schema:1,Release:"R27",Authority:"private#443",Baseline:strings.Repeat("a",40),Candidates:[]Candidate{
 {ID:"H9",PR:881,Head:strings.Repeat("b",40),Decision:"carry",Gate:"PASS",Reason:"integrated"},
 {ID:"H7",PR:858,Head:strings.Repeat("c",40),Decision:"preserve-red",Gate:"RED",Reason:"hostile"},
}}}
func TestRetainRedAndBlock(t *testing.T){ready,err:=assess(baseRC());if err!=nil||ready{t.Fatal(ready,err)}}
func TestQualifiedOnlyReady(t *testing.T){m:=baseRC();m.Candidates[1]=Candidate{ID:"B6",PR:880,Head:strings.Repeat("d",40),Decision:"carry",Gate:"PASS",Reason:"proof"};ready,err:=assess(m);if err!=nil||!ready{t.Fatal(ready,err)}}
func TestRejectUnqualifiedCarry(t *testing.T){m:=baseRC();m.Candidates[0].Gate="NOT_TESTED";if _,err:=assess(m);err==nil{t.Fatal("admitted untested carry")}}
func TestRejectDuplicatePR(t *testing.T){m:=baseRC();m.Candidates[1].PR=881;if _,err:=assess(m);err==nil{t.Fatal("duplicated PR")}}
func TestRejectUnknownDecision(t *testing.T){m:=baseRC();m.Candidates[0].Decision="merge";if _,err:=assess(m);err==nil{t.Fatal("unknown decision")}}
func TestRejectMissingSHA(t *testing.T){m:=baseRC();m.Candidates[0].Head="mutable-main";if _,err:=assess(m);err==nil{t.Fatal("mutable source")}}
func TestRejectLostRed(t *testing.T){m:=baseRC();m.Candidates[1].Gate="PASS";if _,err:=assess(m);err==nil{t.Fatal("RED history rewritten")}}
func TestBlockDeferredItem(t *testing.T){m:=baseRC();m.Candidates[1].Decision="defer";ready,err:=assess(m);if err!=nil||ready{t.Fatal(ready,err)}}
