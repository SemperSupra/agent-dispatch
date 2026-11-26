// Package benchmark defines a fixed public synthetic comparison corpus.
// Source annotations drive a typed reference, not natural-language inference.
// The model-facing projection never includes gold or typed claim annotations.
package benchmark

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"slices"
	"sort"
	"strings"

	evidence "sempersupra/mail-evidence-challenge"
	gate "sempersupra/mail-evidence-challenge/improvement_gate"
	"sempersupra/mail-evidence-challenge/pipeline"
)

//go:embed cases.json
var caseBytes []byte

//go:embed gold.json
var goldBytes []byte

type sourceSpec struct {
	ID,Tenant,Lineage,Group,MessageID,CapturedAt,Raw string
	Claims []evidence.Claim
}
type caseSpec struct {
	ID,Partition,Language,Family,Lineage,Category,Tenant,KnownAt,Group,Key,Question string
	Sources []sourceSpec
}
type goldCitation struct{ID,Quote string}
type goldSpec struct{
	ID,Value string
	Citations []goldCitation
}
type corpus struct {
	session *pipeline.Session
	cases []caseSpec
	dev,held []gate.Case
}

type Report struct {
	Schema,FixtureSHA256,GoldSHA256,Classification string
	Seed int64
	Development,Heldout int
	HeldoutByLanguage,HeldoutExactByLanguage,HeldoutByCategory map[string]int
	TypedExact,ControlExact int
	Verdict gate.Verdict
	ModelInference bool
}

func digest(raw []byte)string{h:=sha256.Sum256(raw);return hex.EncodeToString(h[:])}
func strictDecode(raw []byte,out any)error{
	if len(raw)>1<<20{return errors.New("FIXTURE_BOUND")}
	d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
	if err:=d.Decode(out);err!=nil{return err}
	var tail any
	if err:=d.Decode(&tail);err!=io.EOF{return errors.New("FIXTURE_TRAILING_JSON")}
	return nil
}
func task(c caseSpec)pipeline.Task{
	return pipeline.Task{ID:c.ID,Tenant:c.Tenant,Language:c.Language,
		Group:c.Group,Key:c.Key,KnownAt:c.KnownAt,Question:c.Question,
		Partition:pipeline.Partition(c.Partition)}
}

func load(seed int64)(corpus,error){
	var cases []caseSpec
	var gold []goldSpec
	if err:=strictDecode(caseBytes,&cases);err!=nil{return corpus{},err}
	if err:=strictDecode(goldBytes,&gold);err!=nil{return corpus{},err}
	if len(cases)!=42||len(gold)!=42{return corpus{},errors.New("FROZEN_CASE_COUNT")}
	ids:=map[string]bool{}
	families:=map[string]bool{}
	tenants:=map[string]bool{}
	lineages:=map[string]string{}
	sources:=map[string]sourceSpec{}
	owners:=map[string]string{}
	ledger:=evidence.Ledger{Schema:evidence.Schema}
	split:=pipeline.Split{}
	for _,c:=range cases{
		if ids[c.ID]||families[c.Family]||tenants[c.Tenant]||
			c.Family==""||c.Lineage==""||c.Tenant==""||c.Category==""||
			(c.Partition!="dev"&&c.Partition!="heldout")||len(c.Sources)==0{
			return corpus{},errors.New("CASE_IDENTITY_OR_PARTITION")
		}
		ids[c.ID]=true;families[c.Family]=true;tenants[c.Tenant]=true
		if prior,ok:=lineages[c.Lineage];ok&&prior!=c.ID{return corpus{},errors.New("CASE_LINEAGE_REUSED")}
		lineages[c.Lineage]=c.ID
		for _,s:=range c.Sources{
			if _,ok:=sources[s.ID];ok||s.Lineage==""||
				(s.Tenant!=c.Tenant&&s.Tenant!=c.Tenant+"-foreign"){
				return corpus{},errors.New("SOURCE_CASE_SCOPE")
			}
			if prior,ok:=lineages[s.Lineage];ok&&prior!=c.ID{return corpus{},errors.New("SOURCE_LINEAGE_REUSED")}
			lineages[s.Lineage]=c.ID;sources[s.ID]=s;owners[s.ID]=c.ID
			ledger.Observations=append(ledger.Observations,evidence.Observation{
				ID:s.ID,Archive:"fixture-"+c.ID,Locator:s.ID,Tenant:s.Tenant,
				Group:s.Group,MessageID:s.MessageID,CapturedAt:s.CapturedAt,
				Raw:s.Raw,SHA256:digest([]byte(s.Raw)),Claims:s.Claims})
			if c.Partition=="dev"{split.DevIDs=append(split.DevIDs,s.ID)}else{split.HeldoutIDs=append(split.HeldoutIDs,s.ID)}
		}
	}
	goldByID:=map[string]goldSpec{}
	for _,g:=range gold{
		if !ids[g.ID]||goldByID[g.ID].ID!=""||g.Value==""{return corpus{},errors.New("GOLD_CASE_IDENTITY")}
		goldByID[g.ID]=g
	}
	// Permute only ingestion order, never model seed or candidate selection.
	rng:=rand.New(rand.NewSource(seed))
	rng.Shuffle(len(ledger.Observations),func(i,j int){ledger.Observations[i],ledger.Observations[j]=ledger.Observations[j],ledger.Observations[i]})
	s,rerr:=pipeline.New(ledger,split);if rerr!=nil{return corpus{},rerr}
	out:=corpus{session:s,cases:cases}
	for _,c:=range cases{
		g:=goldByID[c.ID]
		if g.ID==""{return corpus{},errors.New("GOLD_MISSING")}
		card:=gate.Case{ID:c.ID,Family:c.Family,Lineage:c.Lineage,
			Tenant:c.Tenant,Language:c.Language,KnownAt:c.KnownAt,ExpectedValue:g.Value}
		for _,a:=range g.Citations{
			src,ok:=sources[a.ID]
			if !ok||owners[a.ID]!=c.ID||src.Tenant!=c.Tenant||
				a.Quote==""||strings.Count(src.Raw,a.Quote)!=1{return corpus{},errors.New("GOLD_SPAN_UNANCHORED")}
			i:=strings.Index(src.Raw,a.Quote)
			card.Allowed=append(card.Allowed,gate.Evidence{SourceID:a.ID,Begin:i,End:i+len(a.Quote)})
		}
		if c.Partition=="dev"{out.dev=append(out.dev,card)}else{out.held=append(out.held,card)}
	}
	if len(out.dev)!=6||len(out.held)!=36{return corpus{},errors.New("FROZEN_SPLIT_COUNT")}
	return out,nil
}

// Contexts provides deterministic, per-case visible source envelopes. The
// synthetic per-case tenant is deliberately isolated to keep prompts bounded.
// This is not a production ACL system or an independent model run receipt.
func Contexts(seed int64)([]pipeline.Context,error){
	c,err:=load(seed);if err!=nil{return nil,err}
	out:=make([]pipeline.Context,0,len(c.cases))
	for _,x:=range c.cases{
		p,err:=c.session.Prepare(task(x));if err!=nil{return nil,err}
		out=append(out,p)
	}
	sort.Slice(out,func(i,j int)bool{return out[i].TaskID<out[j].TaskID})
	return out,nil
}

func Reference(seed int64)(Report,error){
	c,err:=load(seed);if err!=nil{return Report{},err}
	report:=Report{Schema:"mail-public-multilingual-reference/v1",
		Classification:"SYNTHETIC_TYPED_REFERENCE",FixtureSHA256:digest(caseBytes),
		GoldSHA256:digest(goldBytes),Seed:seed,Development:len(c.dev),Heldout:len(c.held),
		HeldoutByLanguage:map[string]int{},HeldoutExactByLanguage:map[string]int{},
		HeldoutByCategory:map[string]int{},ModelInference:false}
	ref:=gate.Arm{Name:"typed-reference",PolicySHA256:digest([]byte("typed-reference/v1"))}
	control:=gate.Arm{Name:"abstain-control",PolicySHA256:digest([]byte("abstain-control/v1"))}
	gold:=map[string]gate.Case{}
	for _,x:=range c.held{gold[x.ID]=x}
	for _,x:=range c.cases{
		a,err:=c.session.AnswerFact(task(x))
		if err!=nil{return Report{},fmt.Errorf("%s: %w",x.ID,err)}
		n:=gate.Answer{CaseID:x.ID,Value:gate.Unknown}
		if x.Partition=="dev"{ref.Dev=append(ref.Dev,a);control.Dev=append(control.Dev,n);continue}
		ref.Heldout=append(ref.Heldout,a);control.Heldout=append(control.Heldout,n)
		report.HeldoutByLanguage[x.Language]++;report.HeldoutByCategory[x.Category]++
		g:=gold[x.ID]
		if a.Value==g.ExpectedValue&&((a.Citation==nil&&len(g.Allowed)==0)||
			(a.Citation!=nil&&slices.Contains(g.Allowed,*a.Citation))){
			report.HeldoutExactByLanguage[x.Language]++
		}
	}
	report.Verdict,err=gate.Evaluate(gate.Experiment{Sources:c.session.Sources(),
		Dev:c.dev,Heldout:c.held,Arms:[]gate.Arm{control,ref},
		Baseline:control.Name,InferenceKind:gate.Simulated})
	if err!=nil{return Report{},err}
	report.TypedExact=report.Verdict.Heldout[ref.Name].Exact
	report.ControlExact=report.Verdict.Heldout[control.Name].Exact
	return report,nil
}
