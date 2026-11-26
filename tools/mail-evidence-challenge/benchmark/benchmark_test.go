package benchmark

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestFrozenMultilingualReferenceAndReplays(t *testing.T){
	first,err:=Reference(19);if err!=nil{t.Fatal(err)}
	if first.Development!=6||first.Heldout!=36||first.TypedExact!=36||
		first.ControlExact!=9||first.Verdict.Dev["typed-reference"].Exact!=6||
		first.Verdict.PromotionStatus!="HOLD"||first.ModelInference||
		len(first.Verdict.SelectedHardVetoes)!=0{
		t.Fatalf("unexpected independent reference report: %+v",first)
	}
	for _,lang:=range []string{"en","de","th"}{
		if first.HeldoutByLanguage[lang]!=12||first.HeldoutExactByLanguage[lang]!=12{t.Fatal("language coverage",first)}
	}
	if len(first.HeldoutByCategory)!=12{t.Fatal("category coverage",first.HeldoutByCategory)}
	for _,seed:=range []int64{42,73}{
		replay,err:=Reference(seed);if err!=nil{t.Fatal(err)}
		replay.Seed=first.Seed
		if !reflect.DeepEqual(first,replay){t.Fatalf("order replay drift seed %d",seed)}
	}
}

func TestOutwardContextHidesGoldAndPartitions(t *testing.T){
	contexts,err:=Contexts(19);if err!=nil{t.Fatal(err)}
	replay,err:=Contexts(42);if err!=nil{t.Fatal(err)}
	if !reflect.DeepEqual(contexts,replay)||len(contexts)!=42{t.Fatal("context replay mismatch")}
	for _,ctx:=range contexts{
		raw,err:=json.Marshal(ctx);if err!=nil{t.Fatal(err)}
		if len(ctx.Records)>2||len(ctx.SHA256)!=64{t.Fatalf("context budget or identity %s",ctx.TaskID)}
		for _,r:=range ctx.Records{
			if !strings.HasPrefix(r.ID,ctx.TaskID+"-")||r.AcquiredAt>ctx.KnownAt{
				t.Fatalf("scope or clock escape %s %s",ctx.TaskID,r.ID)
			}
		}
		for _,bad:=range []string{"ExpectedValue","Claims","Citati","Lineage","quarry access code is 314","Archivzugangscode lautet 719","รหัสเปิดห้องเก็บของคือ 628","corrected canal depth is 95","korrigierte Messung beträgt 6","ผลวัดที่แก้ไขคือ 125"}{
			if strings.Contains(string(raw),bad){t.Fatalf("oracle/hidden context %s: %s",ctx.TaskID,bad)}
		}
	}
}
