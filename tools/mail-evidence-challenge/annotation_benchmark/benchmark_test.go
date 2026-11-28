package annotationbenchmark

import(
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestReferenceAndFrozenCoverage(t *testing.T){
	r,err:=Reference();if err!=nil{t.Fatal(err)}
	if r.Dev.Cases!=6||r.Dev.Exact!=6||r.Heldout.Cases!=36||r.Heldout.Exact!=12||
		r.Heldout.Invalid!=0||r.Heldout.CorrectAbstention!=9||r.Heldout.MissingClaim!=27||
		r.Promotion!="HOLD"||len(r.HeldoutByCategory)!=12{t.Fatal(r)}
	for _,lang:=range []string{"en","de","th"}{
		x:=r.HeldoutByLanguage[lang]
		if x.Cases!=12||x.Exact!=4||x.CorrectAbstention!=3{t.Fatal(lang,x)}
	}
}
func TestContextDoesNotExportOracleLabels(t *testing.T){
	x,err:=Contexts();if err!=nil{t.Fatal(err)}
	raw,err:=json.Marshal(x);if err!=nil{t.Fatal(err)}
	for _,k:=range []string{`"category":`,`"family":`,`"lineage":`,`"partition":`,`"claims":`,`"polarity":`,`"valid_from":`,`"valid_to":`}{
		if strings.Contains(string(raw),k){t.Fatal("oracle field leaked",k)}
	}
	if len(x)!=42{t.Fatal("context count")}
}
func TestExactOracleControlAndOrderInvariance(t *testing.T){
	cases,gold,err:=load();if err!=nil{t.Fatal(err)}
	rows:=[]Submission{}
	for _,c:=range cases{g:=gold[c.ID];g.Claims=slices.Clone(g.Claims);slices.Reverse(g.Claims);rows=append(rows,g)}
	r,err:=Score(rows);if err!=nil||r.Heldout.Exact!=36||r.Dev.Exact!=6||r.Promotion!="HOLD"{t.Fatal(r,err)}
	slices.Reverse(rows)
	replay,err:=Score(rows);if err!=nil||!reflect.DeepEqual(r,replay){t.Fatal(replay,err)}
	rows[0].ID=rows[1].ID
	if _,err=Score(rows);err==nil{t.Fatal("duplicate accepted")}
}
func TestSeparateFailureClasses(t *testing.T){
	cases,gold,err:=load();if err!=nil{t.Fatal(err)}
	byID:=map[string]Context{};for _,c:=range cases{byID[c.ID]=context(c)}
	for _,name:=range []string{"wrong-meaning","wrong-time","wrong-span","invalid-span","future-modality","false-assertion","missing","wrong-source"}{
		t.Run(name,func(t *testing.T){
			id:="H01";if name=="false-assertion"{id="H08"};if name=="future-modality"{id="H03"}
			c:=byID[id];g:=gold[id];s:=g;s.Claims=slices.Clone(g.Claims)
			switch name{
			case "wrong-meaning":s.Claims[0].Polarity=-1
			case "wrong-time":s.Claims[0].ValidFrom="2026-09-07T09:00:00Z"
			case "wrong-span":
				s.Claims[0].Begin=0;s.Claims[0].End=len(c.Body);s.Claims[0].Quote=c.Body
			case "invalid-span":s.Claims[0].End++
			case "future-modality":s.Claims[0].Modality="actual"
			case "false-assertion":
				s.Claims=[]Claim{{Quote:c.Body,Begin:0,End:len(c.Body),Polarity:1,Modality:"actual",ValidFrom:c.AuthoredAt}}
			case "missing":s.Claims=[]Claim{}
			case "wrong-source":s.SourceID="different"
			}
			x:=scoreOne(c,g,s);if x.Exact!=0{t.Fatal("bad exact",x)}
			switch name{
			case "wrong-meaning","future-modality":if x.WrongMeaning!=1{t.Fatal(x)}
			case "wrong-time":if x.WrongTime!=1{t.Fatal(x)}
			case "wrong-span":if x.WrongSpan!=1{t.Fatal(x)}
			case "invalid-span","wrong-source":if x.Invalid!=1{t.Fatal(x)}
			case "false-assertion":if x.FalseAssertion!=1{t.Fatal(x)}
			case "missing":if x.MissingClaim!=1{t.Fatal(x)}
			}
		})
	}
}

func TestNormalizedTransportRejectsAmbiguousKeys(t *testing.T){
	cases,gold,err:=load();if err!=nil{t.Fatal(err)}
	rows:=[]Submission{}
	for _,c:=range cases{rows=append(rows,gold[c.ID])}
	raw,err:=json.Marshal(rows);if err!=nil{t.Fatal(err)}
	report,err:=ScoreJSON(raw);if err!=nil||report.Heldout.Exact!=36{t.Fatal(report,err)}
	original:=string(raw)
	for _,pair:=range [][2]string{
		{"\"id\":","\"id\":\"forged\",\"id\":"},
		{"\"source_id\":","\"Source_ID\":"},
		{"\"claims\":","\"Claims\":"},
		{"\"polarity\":","\"polarity\":-1,\"polarity\":"},
		{"\"begin\":","\"Begin\":"},
		{"\"valid_to\":","\"valid_to\":null,\"valid_to\":"},
	}{
		bad:=strings.Replace(original,pair[0],pair[1],1)
		if bad==original{t.Fatal("mutation not applied",pair)}
		if _,err=ScoreJSON([]byte(bad));err==nil{t.Fatal("ambiguous key accepted",pair)}
	}
	for i:=range rows{if rows[i].ID=="H01"{rows[i].Claims=nil}}
	raw,err=json.Marshal(rows);if err!=nil{t.Fatal(err)}
	report,err=ScoreJSON(raw);if err!=nil||report.Heldout.Invalid!=1||report.Heldout.Exact!=35{t.Fatal(report,err)}
}

func TestContextGenerationDoesNotDependOnOracle(t *testing.T){
	before,err:=Contexts();if err!=nil{t.Fatal(err)}
	saved:=oracleBytes;defer func(){oracleBytes=saved}()
	oracleBytes=[]byte("invalid oracle")
	after,err:=Contexts();if err!=nil||!reflect.DeepEqual(before,after){t.Fatal("contexts depend on oracle",err)}
	if _,err:=Reference();err==nil{t.Fatal("scoring accepted invalid oracle")}
}
func TestFrozenOracleAndSourceRejectDuplicateKeys(t *testing.T){
	originalSource,originalGold:=sourceBytes,oracleBytes
	defer func(){sourceBytes=originalSource;oracleBytes=originalGold}()
	for _,target:=range []string{"source","gold"}{
		if target=="source"{sourceBytes=[]byte(strings.Replace(string(originalSource),"\"id\":","\"id\":\"forged\",\"id\":",1))}
		if target=="gold"{sourceBytes=originalSource;oracleBytes=[]byte(strings.Replace(string(originalGold),"\"id\":","\"id\":\"forged\",\"id\":",1))}
		if _,_,err:=load();err==nil{t.Fatal("duplicate key accepted",target)}
	}
}
func TestGoldAndCompletionRejectOverlappingQuote(t *testing.T){
	if _,ok:=uniqueQuote("aaa","aa");ok{t.Fatal("overlapping anchor accepted")}
	if i,ok:=uniqueQuote("ก่อน: เปิด","เปิด");!ok||i!=len("ก่อน: "){t.Fatal(i,ok)}
	var cases []Case;var gold []goldCase
	if err:=json.Unmarshal(sourceBytes,&cases);err!=nil{t.Fatal(err)}
	if err:=json.Unmarshal(oracleBytes,&gold);err!=nil{t.Fatal(err)}
	id:=cases[0].ID
	cases[0].Body="aaa"
	found:=false
	for i:=range gold{if gold[i].ID==id{
		gold[i].Claims=[]goldClaim{{Quote:"aa",Polarity:1,Modality:"actual",ValidFrom:cases[0].AuthoredAt}}
		found=true
	}}
	if !found{t.Fatal("missing gold")}
	oldSource,oldGold:=sourceBytes,oracleBytes
	defer func(){sourceBytes=oldSource;oracleBytes=oldGold}()
	var err error
	sourceBytes,err=json.Marshal(cases);if err!=nil{t.Fatal(err)}
	oracleBytes,err=json.Marshal(gold);if err!=nil{t.Fatal(err)}
	if _,err:=Contexts();err!=nil{t.Fatal("valid mutated sources rejected",err)}
	if _,_,err:=load();err==nil||err.Error()!="GOLD_AMBIGUOUS_SPAN"{t.Fatal("gold ambiguity not rejected",err)}
}
