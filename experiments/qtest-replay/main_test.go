package main
import ("encoding/json";"testing"; experiment "../qtest-contract")
func TestFiniteModel(t *testing.T){
 p,e:=plan();if e!=nil{t.Fatal(e)}
 if p.SafeStates!=10||p.MutantStates!=10||p.FirstViolation!=2||len(p.Trace)!=9||len(p.Expected)!=5{t.Fatalf("bad exploration %+v",p)}
}
func TestReceiptControls(t *testing.T){
 p,e:=plan();if e!=nil{t.Fatal(e)}
 b,_:=json.Marshal(p);b=append(b,'\n')
 good:=Receipt{hash(b),"qtest",append([]experiment.ExpectedRead{},p.Expected...),0,true,1}
 if e=verify(p,b,good);e!=nil{t.Fatal(e)}
 for _,c:=range []struct{name string;change func(*Receipt)}{
 {"false-success",func(r *Receipt){r.Observations[1].Value=1}},
 {"reorder",func(r *Receipt){r.Observations[0],r.Observations[1]=r.Observations[1],r.Observations[0]}},
 {"missing",func(r *Receipt){r.Observations=r.Observations[:4]}},
 {"wrong-plan",func(r *Receipt){r.PlanSHA="bad"}},
 {"bad-exit",func(r *Receipt){r.ProcessExit=33}},
 {"no-cleanup",func(r *Receipt){r.Cleanup=false}},
 {"live",func(r *Receipt){r.Vantage="live"}},
 {"no-timing",func(r *Receipt){r.ElapsedNS=0}},
 }{t.Run(c.name,func(t *testing.T){r:=good;r.Observations=append([]experiment.ExpectedRead{},good.Observations...);c.change(&r);if verify(p,b,r)==nil{t.Fatal("accepted contradiction")}})}
}
