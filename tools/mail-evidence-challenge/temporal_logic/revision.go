package temporallogic

import (
	"errors"
	"sort"
	"strings"
	"time"
)

// Revision is a reviewed, source-anchored annotation, not an inference from
// timestamps or message identity. It suppresses only the named predecessor
// where both actual claims are valid and known and the reviewed relation has
// been recorded. Outside that overlap the
// predecessor remains eligible. Original claims and source bytes are retained.
type Revision struct {
	ID, PredecessorID, SuccessorID, Quote, RecordedAt string
}

type RevisionWitness struct {
	RevisionID, PredecessorID, SuccessorID, SourceID, RecordedAt string
}

type RevisionAssessment struct {
	Assessment Assessment
	Applied []RevisionWitness
}

func activeAt(c Claim, src Source, valid, known time.Time) bool {
	acquired, _ := parseMoment(src.AcquiredAt)
	from, _ := parseMoment(c.ValidFrom)
	if c.Modality != "actual" || acquired.After(known) || from.After(valid) {
		return false
	}
	if c.ValidTo != "" {
		end, _ := parseMoment(c.ValidTo)
		return valid.Before(end)
	}
	return true
}

// AssessRevisions reuses the four-valued resolver after a detached, explicit
// revision projection. A later observation alone never withdraws evidence.
// The bounded policy deliberately disallows cross-lineage supersession; a
// conflicting independent lineage remains a counterclaim. A reviewed
// annotation is not proof that its natural-language interpretation is correct.
func (s Store) AssessRevisions(tenant, validAt, knowledgeAt string, revisions []Revision) (RevisionAssessment,error) {
	if err:=s.Validate();err!=nil{return RevisionAssessment{},err}
	if tenant==""{return RevisionAssessment{},errors.New("REVISION_TENANT_REQUIRED")}
	valid,err:=parseMoment(validAt);if err!=nil{return RevisionAssessment{},errors.New("INVALID_QUERY_VALID_TIME")}
	known,err:=parseMoment(knowledgeAt);if err!=nil{return RevisionAssessment{},errors.New("INVALID_QUERY_KNOWLEDGE_TIME")}
	if len(revisions)>4096{return RevisionAssessment{},errors.New("REVISION_COUNT_BOUND")}
	sources:=map[string]Source{}
	claims:=map[string]Claim{}
	for _,o:=range s.Sources{sources[o.ID]=o}
	for _,c:=range s.Claims{claims[c.ID]=c}
	seen:=map[string]bool{}
	type pair struct{old,new string}
	pairs:=map[pair]bool{}
	graph:=map[string][]string{}
	for _,r:=range revisions{
		old,ok1:=claims[r.PredecessorID];new,ok2:=claims[r.SuccessorID]
		key:=pair{r.PredecessorID,r.SuccessorID}
		if r.ID==""||seen[r.ID]||pairs[key]||!ok1||!ok2||old.ID==new.ID{
			return RevisionAssessment{},errors.New("REVISION_IDENTITY_INVALID")
		}
		seen[r.ID]=true;pairs[key]=true
		a,b:=sources[old.SourceID],sources[new.SourceID]
		if a.ID==b.ID||a.Tenant!=b.Tenant||a.Lineage!=b.Lineage||
			old.Predicate!=new.Predicate||old.Modality!="actual"||new.Modality!="actual" {
			return RevisionAssessment{},errors.New("REVISION_SCOPE_INVALID")
		}
		if strings.TrimSpace(r.Quote)==""||!strings.Contains(b.Raw,r.Quote){
			return RevisionAssessment{},errors.New("REVISION_QUOTE_UNANCHORED")
		}
		oldAuthored,_:=parseMoment(a.AuthoredAt)
		newAuthored,_:=parseMoment(b.AuthoredAt)
		if newAuthored.Before(oldAuthored){
			return RevisionAssessment{},errors.New("REVISION_AUTHOR_ORDER")
		}
		recorded,err:=parseMoment(r.RecordedAt)
		if err!=nil{return RevisionAssessment{},errors.New("REVISION_RECORDED_CLOCK_INVALID")}
		oldAcquired,_:=parseMoment(a.AcquiredAt)
		newAcquired,_:=parseMoment(b.AcquiredAt)
		// An annotation cannot be known before the evidence it explicitly links.
		if recorded.Before(oldAcquired)||recorded.Before(newAcquired){
			return RevisionAssessment{},errors.New("REVISION_RECORDED_BEFORE_EVIDENCE")
		}
		graph[old.ID]=append(graph[old.ID],new.ID)
	}
	visiting:=map[string]uint8{}
	var visit func(string) error
	visit=func(id string)error{
		if visiting[id]==1{return errors.New("REVISION_CYCLE")}
		if visiting[id]==2{return nil}
		visiting[id]=1
		for _,n:=range graph[id]{if err:=visit(n);err!=nil{return err}}
		visiting[id]=2;return nil
	}
	for id:=range graph{if err:=visit(id);err!=nil{return RevisionAssessment{},err}}
	suppressed:=map[string]bool{}
	witnesses:=[]RevisionWitness{}
	for _,r:=range revisions{
		a,b:=claims[r.PredecessorID],claims[r.SuccessorID]
		old,new:=sources[a.SourceID],sources[b.SourceID]
		recorded,_:=parseMoment(r.RecordedAt)
		if old.Tenant!=tenant||recorded.After(known)||!activeAt(a,old,valid,known)||!activeAt(b,new,valid,known){continue}
		suppressed[a.ID]=true
		witnesses=append(witnesses,RevisionWitness{r.ID,a.ID,b.ID,new.ID,r.RecordedAt})
	}
	sort.Slice(witnesses,func(i,j int)bool{return witnesses[i].RevisionID<witnesses[j].RevisionID})
	projected:=Store{Sources:s.Sources,Rules:s.Rules,Claims:make([]Claim,0,len(s.Claims))}
	for _,c:=range s.Claims{if !suppressed[c.ID]{projected.Claims=append(projected.Claims,c)}}
	assessment,err:=projected.Assess(tenant,validAt,knowledgeAt)
	if err!=nil{return RevisionAssessment{},err}
	return RevisionAssessment{Assessment:assessment,Applied:witnesses},nil
}
