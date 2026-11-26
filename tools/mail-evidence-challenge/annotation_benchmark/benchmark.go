// Package annotationbenchmark measures source annotation, not answer generation.
// The public corpus and gold are distinct, frozen authored fixtures, not
// blinded external annotations or evidence of actual model execution.
package annotationbenchmark

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const Schema="mail-public-annotation-benchmark/v1"
const MaxInput=1<<20

//go:embed sources.json
var sourceBytes []byte
//go:embed oracle.json
var oracleBytes []byte

type Case struct {
	ID string `json:"id"`
	Partition string `json:"partition"`
	Language string `json:"language"`
	Category string `json:"category"`
	Target string `json:"target"`
	Proposition string `json:"proposition"`
	Family string `json:"family"`
	Lineage string `json:"lineage"`
	SourceID string `json:"source_id"`
	AuthoredAt string `json:"authored_at"`
	AcquiredAt string `json:"acquired_at"`
	Body string `json:"body"`
}

// Context is the model-facing envelope. Category/family/split and oracle
// labels are evaluator metadata, not model inputs.
type Context struct {
	ID string `json:"id"`
	SourceID string `json:"source_id"`
	Language string `json:"language"`
	Target string `json:"target"`
	Proposition string `json:"proposition"`
	AuthoredAt string `json:"authored_at"`
	AcquiredAt string `json:"acquired_at"`
	Body string `json:"body"`
	BodySHA256 string `json:"body_sha256"`
}

type Claim struct {
	Quote string `json:"quote"`
	Begin int `json:"begin"`
	End int `json:"end"`
	Polarity int `json:"polarity"`
	Modality string `json:"modality"`
	ValidFrom string `json:"valid_from"`
	ValidTo string `json:"valid_to"`
}
type Submission struct {
	ID string `json:"id"`
	SourceID string `json:"source_id"`
	BodySHA256 string `json:"body_sha256"`
	Claims []Claim `json:"claims"` // empty is explicit abstention
}
type goldClaim struct {
	Quote string `json:"quote"`
	Polarity int `json:"polarity"`
	Modality string `json:"modality"`
	ValidFrom string `json:"valid_from"`
	ValidTo string `json:"valid_to"`
}
type goldCase struct{
	ID string `json:"id"`
	Claims []goldClaim `json:"claims"`
}
type Stats struct{
	Cases,Exact,Invalid,Abstained,CorrectAbstention,FalseAssertion,
	MissingClaim,ExtraClaim,WrongSpan,WrongMeaning,WrongTime int
}
type Report struct{
	Schema,CorpusSHA256,OracleSHA256,Classification string
	Dev,Heldout Stats
	HeldoutByLanguage,HeldoutByCategory map[string]Stats
	Promotion string
}

func digest(b []byte)string{h:=sha256.Sum256(b);return hex.EncodeToString(h[:])}
func instant(s string)(time.Time,error){
	t,e:=time.Parse(time.RFC3339,s)
	if e!=nil||t.UTC().Format(time.RFC3339)!=s{return time.Time{},errors.New("CANONICAL_UTC_SECONDS_REQUIRED")}
	return t,nil
}
func decode(raw []byte,out any)error{
	if len(raw)>MaxInput||!utf8.Valid(raw){return errors.New("INPUT_BOUND_OR_UTF8")}
	d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
	if err:=d.Decode(out);err!=nil{return err}
	var extra any
	if err:=d.Decode(&extra);err!=io.EOF{return errors.New("TRAILING_JSON")}
	return nil
}
func context(c Case)Context{return Context{ID:c.ID,SourceID:c.SourceID,Language:c.Language,
	Target:c.Target,Proposition:c.Proposition,AuthoredAt:c.AuthoredAt,AcquiredAt:c.AcquiredAt,
	Body:c.Body,BodySHA256:digest([]byte(c.Body))}}
func validClaim(c Claim,ctx Context)bool{
	if c.Quote==""||c.Begin<0||c.End<=c.Begin||c.End>len(ctx.Body)||
		!utf8.RuneStart(ctx.Body[c.Begin])||(c.End<len(ctx.Body)&&!utf8.RuneStart(ctx.Body[c.End]))||
		ctx.Body[c.Begin:c.End]!=c.Quote||(c.Polarity!=1&&c.Polarity != -1)||
		(c.Modality!="actual"&&c.Modality!="planned"){return false}
	from,err:=instant(c.ValidFrom);if err!=nil{return false}
	if c.ValidTo!=""{to,err:=instant(c.ValidTo);if err!=nil||!to.After(from){return false}}
	return true
}
func canonical(cs []Claim)[]Claim{
	out:=slices.Clone(cs)
	sort.Slice(out,func(i,j int)bool{
		if out[i].Begin!=out[j].Begin{return out[i].Begin<out[j].Begin}
		return out[i].End<out[j].End
	})
	return out
}
func validate(s Submission,c Context)bool{
	if s.ID!=c.ID||s.SourceID!=c.SourceID||s.BodySHA256!=c.BodySHA256||
		s.Claims==nil||len(s.Claims)>32{return false}
	seen:=map[[2]int]bool{}
	for _,x:=range s.Claims{
		k:=[2]int{x.Begin,x.End}
		if seen[k]||!validClaim(x,c){return false};seen[k]=true
	}
	return true
}
func load()([]Case,map[string]Submission,error){
	var cases []Case;var gold []goldCase
	if err:=decode(sourceBytes,&cases);err!=nil{return nil,nil,err}
	if err:=decode(oracleBytes,&gold);err!=nil{return nil,nil,err}
	if len(cases)!=42||len(gold)!=42{return nil,nil,errors.New("FROZEN_COUNT")}
	ids:=map[string]Context{};seen:=map[string]bool{};counts:=map[string]int{}
	for _,c:=range cases{
		if c.ID==""||c.Body==""||len(c.Body)>16384||c.Target==""||c.Proposition==""||c.Category==""||
			(c.Partition!="dev"&&c.Partition!="heldout")||
			(c.Language!="en"&&c.Language!="de"&&c.Language!="th"){
			return nil,nil,errors.New("SOURCE_CONTRACT")
		}
		a,e:=instant(c.AuthoredAt);b,f:=instant(c.AcquiredAt)
		if e!=nil||f!=nil||a.After(b){return nil,nil,errors.New("SOURCE_CLOCK")}
		x:=context(c)
		for _,k:=range []string{"id:"+c.ID,"source:"+c.SourceID,"family:"+c.Family,"lineage:"+c.Lineage,"bytes:"+x.BodySHA256}{
			if seen[k]||strings.HasSuffix(k,":"){return nil,nil,errors.New("SOURCE_IDENTITY_REUSED")};seen[k]=true
		}
		ids[c.ID]=x;counts[c.Partition+":"+c.Language]++
	}
	for _,lang:=range []string{"en","de","th"}{
		if counts["dev:"+lang]!=2||counts["heldout:"+lang]!=12{return nil,nil,errors.New("SPLIT_COVERAGE")}
	}
	out:=map[string]Submission{}
	for _,g:=range gold{
		c,ok:=ids[g.ID];if !ok||out[g.ID].ID!=""||g.Claims==nil{return nil,nil,errors.New("GOLD_IDENTITY")}
		s:=Submission{ID:c.ID,SourceID:c.SourceID,BodySHA256:c.BodySHA256,Claims:[]Claim{}}
		for _,x:=range g.Claims{
			if x.Quote==""||strings.Count(c.Body,x.Quote)!=1{return nil,nil,errors.New("GOLD_AMBIGUOUS_SPAN")}
			begin:=strings.Index(c.Body,x.Quote)
			s.Claims=append(s.Claims,Claim{Quote:x.Quote,Begin:begin,End:begin+len(x.Quote),
				Polarity:x.Polarity,Modality:x.Modality,ValidFrom:x.ValidFrom,ValidTo:x.ValidTo})
		}
		if !validate(s,c){return nil,nil,errors.New("GOLD_INVALID")}
		out[g.ID]=s
	}
	return cases,out,nil
}

func Contexts()([]Context,error){
	cases,_,err:=load();if err!=nil{return nil,err}
	out:=make([]Context,0,len(cases));for _,c:=range cases{out=append(out,context(c))}
	return out,nil
}

// StructuredBaseline is an intentionally limited explicit-record recognizer.
// It does not receive gold, detect natural language, infer effective clocks,
// follow source instructions, or claim that a recognized record is truthful.
func StructuredBaseline(c Context)Submission{
	out:=Submission{ID:c.ID,SourceID:c.SourceID,BodySHA256:c.BodySHA256,Claims:[]Claim{}}
	polarities:=map[string]int{"yes":1,"no":-1,"ja":1,"nein":-1,"ใช่":1,"ไม่ใช่":-1}
	offset:=0
	for _,line:=range strings.Split(c.Body,"\n"){
		parts:=strings.Split(line," | ")
		if len(parts)==3&&parts[1]==c.Target{
			_,err:=instant(parts[0]);p,ok:=polarities[parts[2]]
			if err==nil&&ok{out.Claims=append(out.Claims,Claim{Quote:line,Begin:offset,End:offset+len(line),Polarity:p,Modality:"actual",ValidFrom:parts[0]})}
		}
		offset+=len(line)+1
	}
	return out
}

func scoreOne(c Context,g,s Submission)Stats{
	x:=Stats{Cases:1}
	if !validate(s,c){x.Invalid=1;return x}
	if len(s.Claims)==0{x.Abstained=1}
	if slices.Equal(canonical(g.Claims),canonical(s.Claims)){
		x.Exact=1;if len(g.Claims)==0{x.CorrectAbstention=1};return x
	}
	if len(g.Claims)==0&&len(s.Claims)>0{x.FalseAssertion=1}
	if len(s.Claims)<len(g.Claims){x.MissingClaim=len(g.Claims)-len(s.Claims)}
	if len(s.Claims)>len(g.Claims){x.ExtraClaim=len(s.Claims)-len(g.Claims)}
	bySpan:=map[[2]int]Claim{}
	for _,a:=range g.Claims{bySpan[[2]int{a.Begin,a.End}]=a}
	for _,a:=range s.Claims{
		b,ok:=bySpan[[2]int{a.Begin,a.End}]
		if !ok{x.WrongSpan++;continue}
		if a.Polarity!=b.Polarity||a.Modality!=b.Modality{x.WrongMeaning++}
		if a.ValidFrom!=b.ValidFrom||a.ValidTo!=b.ValidTo{x.WrongTime++}
	}
	return x
}
func add(a,b Stats)Stats{return Stats{
	Cases:a.Cases+b.Cases,Exact:a.Exact+b.Exact,Invalid:a.Invalid+b.Invalid,
	Abstained:a.Abstained+b.Abstained,CorrectAbstention:a.CorrectAbstention+b.CorrectAbstention,
	FalseAssertion:a.FalseAssertion+b.FalseAssertion,MissingClaim:a.MissingClaim+b.MissingClaim,
	ExtraClaim:a.ExtraClaim+b.ExtraClaim,WrongSpan:a.WrongSpan+b.WrongSpan,
	WrongMeaning:a.WrongMeaning+b.WrongMeaning,WrongTime:a.WrongTime+b.WrongTime}}
func Score(submissions []Submission)(Report,error){
	cases,gold,err:=load();if err!=nil{return Report{},err}
	if len(submissions)!=len(cases){return Report{},errors.New("SUBMISSION_COUNT")}
	byID:=map[string]Submission{}
	for _,s:=range submissions{
		if _,ok:=gold[s.ID];!ok||byID[s.ID].ID!=""{return Report{},errors.New("SUBMISSION_IDENTITY")}
		byID[s.ID]=s
	}
	out:=Report{Schema:Schema,CorpusSHA256:digest(sourceBytes),OracleSHA256:digest(oracleBytes),
		Classification:"SCORE_NORMALIZED_ANNOTATIONS_NOT_EXECUTION_ATTESTATION",Promotion:"HOLD",
		HeldoutByLanguage:map[string]Stats{},HeldoutByCategory:map[string]Stats{}}
	for _,c:=range cases{
		x:=scoreOne(context(c),gold[c.ID],byID[c.ID])
		if c.Partition=="dev"{out.Dev=add(out.Dev,x);continue}
		out.Heldout=add(out.Heldout,x)
		out.HeldoutByLanguage[c.Language]=add(out.HeldoutByLanguage[c.Language],x)
		out.HeldoutByCategory[c.Category]=add(out.HeldoutByCategory[c.Category],x)
	}
	return out,nil
}
func ScoreJSON(raw []byte)(Report,error){
	var submissions []Submission
	if err:=decode(raw,&submissions);err!=nil{return Report{},err}
	return Score(submissions)
}
func Reference()(Report,error){
	ctx,err:=Contexts();if err!=nil{return Report{},err}
	rows:=make([]Submission,0,len(ctx))
	for _,c:=range ctx{rows=append(rows,StructuredBaseline(c))}
	report,err:=Score(rows);if err!=nil{return Report{},fmt.Errorf("reference: %w",err)}
	report.Classification="DETERMINISTIC_STRUCTURED_RECORD_REFERENCE"
	return report,nil
}
