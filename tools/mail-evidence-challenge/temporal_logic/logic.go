// Package temporallogic is a small source-anchored, four-valued research
// *adapter contract*. It is NOT a new general-purpose belief-revision engine.
// W3C PROV/ATMS/Prolog/Graphiti remain independently qualified alternatives.
package temporallogic

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "slices"
    "sort"
    "strings"
    "time"
)

type Status string
const (
    Neither Status = "NEITHER"
    Supported Status = "SUPPORTED"
    Refuted Status = "REFUTED"
    Both Status = "BOTH"
)
type Polarity int
const (
    Supports Polarity = 1
    Refutes Polarity = -1
)
type Source struct {
    ID, Tenant, Lineage, Raw, SHA256, AuthoredAt, AcquiredAt string
}
type Claim struct {
    ID, SourceID, Predicate, Modality, Quote, ValidFrom, ValidTo string
    Polarity Polarity
}
type Rule struct {
    ID, Tenant, Consequent, PolicySHA256 string
    Premises []string
}
type Store struct {
    Sources []Source
    Claims []Claim
    Rules []Rule
}
type Derivation struct {
    RuleID string
    Premises []string
    SourceIDs []string
    LineageIDs []string
    PolicySHA256 string
}
type Belief struct {
    Predicate string
    Status Status
    SupportingSourceIDs []string
    RefutingSourceIDs []string
    SupportingLineages []string
    RefutingLineages []string
    Derivations []Derivation
}
type Assessment struct {
    Tenant, ValidAt, KnowledgeAt string
    Beliefs []Belief
}
func digest(raw string) string {
    b:=sha256.Sum256([]byte(raw))
    return hex.EncodeToString(b[:])
}
func parseMoment(raw string) (time.Time,error) {
    t,err:=time.Parse(time.RFC3339,raw)
    if err!=nil{return t,err}
    if t.Location()==nil{return t,errors.New("INVALID_TIMEZONE")}
    return t,nil
}
func uniqueSorted(items []string) []string {
    present:=make(map[string]bool,len(items))
    for _,x:=range items {present[x]=true}
    out:=make([]string,0,len(present))
    for x:=range present {out=append(out,x)}
    sort.Strings(out)
    return out
}
func classify(pos,neg bool) Status {
    if pos&&neg{return Both}
    if pos{return Supported}
    if neg{return Refuted}
    return Neither
}
func (s Store) Validate() error {
    origins:=map[string]Source{}
    for _,v:=range s.Sources {
        if v.ID==""||v.Tenant==""||v.Lineage==""||v.SHA256!=digest(v.Raw) {
            return errors.New("INVALID_SOURCE_PROVENANCE")
        }
        if _,ok:=origins[v.ID];ok{return errors.New("DUPLICATE_SOURCE_OCCURRENCE")}
        if _,err:=parseMoment(v.AuthoredAt);err!=nil{return errors.New("INVALID_SOURCE_AUTHORED_TIME")}
        if _,err:=parseMoment(v.AcquiredAt);err!=nil{return errors.New("INVALID_SOURCE_ACQUIRED_TIME")}
        origins[v.ID]=v
    }
    claims:=map[string]bool{}
    for _,c:=range s.Claims {
        v,exists:=origins[c.SourceID]
        if !exists||c.ID==""||claims[c.ID]||c.Predicate==""||c.Quote==""||
           !strings.Contains(v.Raw,c.Quote) {
            return errors.New("CLAIM_NOT_SOURCE_ANCHORED")
        }
        claims[c.ID]=true
        if c.Polarity!=Supports&&c.Polarity!=Refutes{
            return errors.New("POLARITY_INVALID")
        }
        if c.Modality!="actual"&&c.Modality!="planned"{
            return errors.New("MODALITY_INVALID")
        }
        from,err:=parseMoment(c.ValidFrom)
        if err!=nil{return errors.New("VALID_FROM_INVALID")}
        if c.ValidTo!="" {
            to,err:=parseMoment(c.ValidTo)
            if err!=nil||!to.After(from){return errors.New("VALID_INTERVAL_INVALID")}
        }
    }
    ruleIDs:=map[string]bool{}
    graphs:=map[string]map[string][]string{}
    for _,r:=range s.Rules {
        if r.ID==""||ruleIDs[r.ID]||r.Tenant==""||r.Consequent==""||
           len(r.Premises)==0||len(r.PolicySHA256)!=64{
            return errors.New("RULE_CONTRACT_INVALID")
        }
        ruleIDs[r.ID]=true
        for _,p:=range r.Premises {
            if p==""||p==r.Consequent{return errors.New("CYCLIC_RULE")}
        }
        if graphs[r.Tenant]==nil{graphs[r.Tenant]=map[string][]string{}}
        graphs[r.Tenant][r.Consequent]=append(
            graphs[r.Tenant][r.Consequent],r.Premises...)
    }
    for _,graph:=range graphs {
        visiting:=map[string]uint8{}
        var visit func(string) error
        visit=func(p string) error{
            if visiting[p]==1{return errors.New("CYCLIC_RULE")}
            if visiting[p]==2{return nil}
            visiting[p]=1
            for _,prior:=range graph[p] {
                if err:=visit(prior);err!=nil{return err}
            }
            visiting[p]=2
            return nil
        }
        for p:=range graph {
            if err:=visit(p);err!=nil{return err}
        }
    }
    return nil
}
func (s Store) Assess(tenant,validAt,knowledgeAt string) (Assessment,error) {
    if err:=s.Validate();err!=nil{return Assessment{},err}
    valid,err:=parseMoment(validAt)
    if err!=nil{return Assessment{},errors.New("INVALID_QUERY_VALID_TIME")}
    known,err:=parseMoment(knowledgeAt)
    if err!=nil{return Assessment{},errors.New("INVALID_QUERY_KNOWLEDGE_TIME")}
    sourceByID:=map[string]Source{}
    for _,o:=range s.Sources {sourceByID[o.ID]=o}
    results:=map[string]*Belief{}
    get:=func(predicate string)*Belief{
        if b,ok:=results[predicate];ok{return b}
        b:=&Belief{Predicate:predicate,Status:Neither}
        results[predicate]=b
        return b
    }
    for _,c:=range s.Claims {
        o:=sourceByID[c.SourceID]
        if o.Tenant!=tenant||c.Modality!="actual"{continue}
        acquired,_:=parseMoment(o.AcquiredAt)
        if acquired.After(known){continue}
        start,_:=parseMoment(c.ValidFrom)
        if start.After(valid){continue}
        if c.ValidTo!="" {
            end,_:=parseMoment(c.ValidTo)
            if !valid.Before(end){continue}
        }
        b:=get(c.Predicate)
        if c.Polarity==Supports {
            b.SupportingSourceIDs=append(b.SupportingSourceIDs,o.ID)
            b.SupportingLineages=append(b.SupportingLineages,o.Lineage)
        } else {
            b.RefutingSourceIDs=append(b.RefutingSourceIDs,o.ID)
            b.RefutingLineages=append(b.RefutingLineages,o.Lineage)
        }
    }
    // A conservative, fixed-policy rule derives only from uncontroverted
    // supporting premises. Explicit source disagreement quarantines the rule.
    // Reevaluate over a validated acyclic rule DAG until a stable fixed point.
    // Review-time policy and provenance never come from untrusted source text.
    ordered:=slices.Clone(s.Rules)
    sort.Slice(ordered,func(i,j int)bool{return ordered[i].ID<ordered[j].ID})
    applied:=map[string]bool{}
    for pass:=0;pass<len(ordered);pass++ {
        progressed:=false
        for _,r:=range ordered {
            if r.Tenant!=tenant||applied[r.ID]{continue}
            complete:=true
            refs:=[]string{}
            lineages:=[]string{}
            for _,p:=range r.Premises {
                b:=get(p)
                if len(b.SupportingLineages)==0||len(b.RefutingLineages)!=0 {
                    complete=false
                    break
                }
                refs=append(refs,b.SupportingSourceIDs...)
                lineages=append(lineages,b.SupportingLineages...)
            }
            if !complete{continue}
            b:=get(r.Consequent)
            b.SupportingSourceIDs=append(b.SupportingSourceIDs,refs...)
            b.SupportingLineages=append(b.SupportingLineages,lineages...)
            b.Derivations=append(b.Derivations,Derivation{
                RuleID:r.ID,Premises:slices.Clone(r.Premises),
                SourceIDs:uniqueSorted(refs),LineageIDs:uniqueSorted(lineages),
                PolicySHA256:r.PolicySHA256,
            })
            applied[r.ID]=true
            progressed=true
        }
        if !progressed{break}
    }
    out:=Assessment{Tenant:tenant,ValidAt:validAt,KnowledgeAt:knowledgeAt}
    for predicate,b:=range results {
        b.Predicate=predicate
        b.SupportingSourceIDs=uniqueSorted(b.SupportingSourceIDs)
        b.RefutingSourceIDs=uniqueSorted(b.RefutingSourceIDs)
        b.SupportingLineages=uniqueSorted(b.SupportingLineages)
        b.RefutingLineages=uniqueSorted(b.RefutingLineages)
        b.Status=classify(len(b.SupportingLineages)>0,len(b.RefutingLineages)>0)
        out.Beliefs=append(out.Beliefs,*b)
    }
    sort.Slice(out.Beliefs,func(i,j int)bool{
        return out.Beliefs[i].Predicate<out.Beliefs[j].Predicate
    })
    return out,nil
}
func (a Assessment) Find(predicate string) Belief {
    for _,b:=range a.Beliefs {if b.Predicate==predicate{return b}}
    return Belief{Predicate:predicate,Status:Neither}
}
func (a Assessment) Explain(predicate string)(string,error){
    b:=a.Find(predicate)
    if b.Status==Neither{return "NO_SUPPORTED_OR_REFUTING_SOURCE",nil}
    if len(b.SupportingSourceIDs)+len(b.RefutingSourceIDs)==0 {
        return "",fmt.Errorf("UNSOURCED_ASSESSMENT_%s",predicate)
    }
    return fmt.Sprintf("%s: supporting=%s; refuting=%s; derived_rules=%d",
        b.Status,strings.Join(b.SupportingSourceIDs,","),
        strings.Join(b.RefutingSourceIDs,","),len(b.Derivations)),nil
}
