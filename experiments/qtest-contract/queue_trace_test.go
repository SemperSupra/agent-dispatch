package experiment

import ("bytes";"testing")

func TestQueueCounterexample(t *testing.T){
 steps:=[]string{"select-absent","observe-absent","mutate-absent","observe-refused","notify-absent","observe-status","select-present","observe-present","observe-present-pfn"}
 plan,err:=TranslateQueueTrace(QueueTrace{steps});if err!=nil{t.Fatal(err)}
 e,err:=Decode(bytes.NewReader(plan.Proposal));if err!=nil||len(e.Operations)!=9||len(plan.Expected)!=5{t.Fatalf("bad plan %v",err)}
 if err=CheckQueueReads(plan,[]ExpectedRead{{1,0},{3,0},{5,3},{7,256},{8,0}});err!=nil{t.Fatal(err)}
 for _,c:=range []struct{name string; got []ExpectedRead}{
 {"missing",[]ExpectedRead{{1,0}}},
 {"false-success",[]ExpectedRead{{1,0},{3,1},{5,3},{7,256},{8,0}}},
 {"status-mutated",[]ExpectedRead{{1,0},{3,0},{5,0},{7,256},{8,0}}},
 {"queue-corruption",[]ExpectedRead{{1,0},{3,0},{5,3},{7,0},{8,0}}},
 {"valid-pfn-corruption",[]ExpectedRead{{1,0},{3,0},{5,3},{7,256},{8,1}}},
 {"reorder",[]ExpectedRead{{3,0},{1,0},{5,3},{7,256},{8,0}}},
 {"duplicate",[]ExpectedRead{{1,0},{1,0},{5,3},{7,256},{8,0}}},
 }{t.Run(c.name,func(t *testing.T){if CheckQueueReads(plan,c.got)==nil{t.Fatal("accepted contradictory trace")}})}
 for _,c:=range []struct{name string;steps []string}{
 {"empty",nil},{"truncated",steps[:8]},{"extended",append(append([]string{},steps...),"raw-command")},
 {"unsupported",append([]string{"raw-command"},steps[1:]...)},
 {"wrong-order",append([]string{steps[1],steps[0]},steps[2:]...)},
 }{t.Run(c.name,func(t *testing.T){if _,err:=TranslateQueueTrace(QueueTrace{c.steps});err==nil{t.Fatal("accepted unsupported counterexample")}})}
}
