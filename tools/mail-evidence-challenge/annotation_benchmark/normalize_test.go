package annotationbenchmark

import(
	"encoding/json"
	"strings"
	"testing"
)

func rawContext(body string)Context{return Context{ID:"H",SourceID:"source",Body:body,BodySHA256:digest([]byte(body))}}
func completion(quote,from,to string,polarity int,modality string)[]byte{
	b,_:=json.Marshal(map[string]any{"claims":[]candidateClaim{{Quote:quote,Polarity:polarity,Modality:modality,ValidFrom:from,ValidTo:to}}});return b
}
func TestNormalizeThaiByteOffsetsAndExplicitOffset(t *testing.T){
	c:=rawContext("ก่อน: ประตูเปิด")
	r,err:=NormalizeCompletion(c,completion("ประตูเปิด","2026-09-01T08:00:00+07:00","2026-09-02T08:00:00+07:00",1,"actual"))
	if err!=nil||len(r.Claims)!=1{t.Fatal(r,err)}
	a:=r.Claims[0]
	if a.Begin!=len("ก่อน: ")||a.End!=len(c.Body)||a.ValidFrom!="2026-09-01T01:00:00Z"||a.ValidTo!="2026-09-02T01:00:00Z"{t.Fatal(a)}
}
func TestNormalizeRejectsStrictSchemaAndNoSilentRepair(t *testing.T){
	c:=rawContext("Gate open.")
	good:=string(completion("Gate open.","2026-09-01T08:00:00Z","",1,"actual"))
	for _,v:=range []string{
		"prefix "+good,good+" {}",strings.Replace(good,`"claims":`,`"claims":[],"claims":`,1),
		strings.Replace(good,`"polarity":1`,`"polarity":-1,"polarity":1`,1),
		strings.Replace(good,`"quote":`,`"Quote":`,1),
		strings.Replace(good,`"valid_to":""`,`"valid_to":null`,1),
		strings.Replace(good,`,"valid_to":""`,"",1),
		strings.Replace(good,"Gate open.",`\ud800`,1),
		strings.Replace(good,"Gate open.","gate open.",1),
		strings.Replace(good,"actual","maybe",1),
		`{"claims":null}`,`{"claims":[null]}`,`{"claims":[],"answer":"yes"}`,
	}{
		s,err:=NormalizeCompletion(c,[]byte(v));if err==nil||s.Claims!=nil{t.Fatalf("accepted %q %+v %v",v,s,err)}
	}
	s,err:=NormalizeCompletion(c,[]byte(`{"claims":[]}`))
	if err!=nil||s.Claims==nil||len(s.Claims)!=0{t.Fatal(s,err)}
}
func TestNormalizeAmbiguousAnchorAndMissingClock(t *testing.T){
	for _,c:=range []Context{rawContext("aaa"),rawContext("aa and aa")}{
		if _,err:=NormalizeCompletion(c,completion("aa","2026-09-01T08:00:00Z","",1,"actual"));err==nil{t.Fatal("ambiguous quote")}
	}
	c:=rawContext("Gate open.")
	for _,clock:=range []string{"","2026-09-01","2026-09-01T08:00:00","2026-09-01T08:00:00-00:00","2026-09-01T08:00:00.1Z","2026-09-01T08:00:00+00:60"}{
		if _,err:=NormalizeCompletion(c,completion(c.Body,clock,"",1,"actual"));err==nil{t.Fatal(clock)}
	}
}
func TestRawJournalSeparatesInvalidFromAbstention(t *testing.T){
	ctx,err:=Contexts();if err!=nil{t.Fatal(err)}
	rows:=[]RawResponse{}
	for _,c:=range ctx{rows=append(rows,RawResponse{ID:c.ID,SourceID:c.SourceID,BodySHA256:c.BodySHA256,Status:"completed",Completion:`{"claims":[]}`})}
	for i:=range rows{
		if rows[i].ID=="H08"{rows[i].Status="timeout"}
		if rows[i].ID=="H09"{rows[i].Completion="bad json"}
	}
	raw,err:=json.Marshal(rows);if err!=nil{t.Fatal(err)}
	out,err:=ScoreRawJSON(raw)
	if err!=nil||out.Report.Heldout.Invalid!=2||out.Report.Heldout.CorrectAbstention!=7||out.Report.Heldout.Exact!=7||
		out.Report.Promotion!="HOLD"||out.NormalizationCounts["timeout"]!=1||len(out.Rows)!=42{t.Fatal(out,err)}
	rows[0].BodySHA256=digest([]byte("wrong"))
	raw,_=json.Marshal(rows)
	if _,err=ScoreRawJSON(raw);err==nil{t.Fatal("misbound journal")}
}
