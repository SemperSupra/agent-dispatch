// Package temporallanguage qualifies deterministic, annotated date/aspect
// contracts over EN/DE/TH fictional mail. It is NOT a general NLP parser.
// Uncertain dates and unqualified calendars fail closed.
package temporallanguage

import (
    "errors"
    "fmt"
    "sort"
    "strings"
    "time"
    _ "time/tzdata"
)
type Calendar string
const (
    Gregorian Calendar = "GREGORIAN"
    ThaiBuddhist Calendar = "THAI_BUDDHIST_ERA"
)
type Aspect string
const (
    Completed Aspect = "COMPLETED"
    Prospective Aspect = "PROSPECTIVE"
    NotYet Aspect = "NOT_YET"
    Undetermined Aspect = "UNDETERMINED"
)
type AnnotatedPhrase struct {
    Language, Quote, OriginalSourceID string
    EffectiveDateISO string
    Calendar Calendar
}
type TemporalFinding struct {
    SourceID, Language, OriginalQuote, GregorianDate string
    Aspect Aspect
    AssertsCompletedEvent bool
    RuleID string
}
type LocalResolution struct {
    Classification string
    UTC string
    CandidateUTC []string
}

var reviewed = map[string]struct{aspect Aspect; rule string}{
    "en|Approval was granted.":{Completed,"EN_EXPLICIT_COMPLETED_01"},
    "en|Approval will be granted.":{Prospective,"EN_EXPLICIT_PROSPECTIVE_01"},
    "en|Approval has not yet been granted.":{NotYet,"EN_EXPLICIT_NOT_YET_01"},
    "de|Die Freigabe wurde erteilt.":{Completed,"DE_EXPLICIT_COMPLETED_01"},
    "de|Die Freigabe wird morgen erteilt.":{Prospective,"DE_EXPLICIT_PROSPECTIVE_01"},
    "de|Die Freigabe ist noch nicht erteilt.":{NotYet,"DE_EXPLICIT_NOT_YET_01"},
    "th|อนุมัติแล้ว":{Completed,"TH_EXPLICIT_COMPLETED_01"},
    "th|จะอนุมัติ":{Prospective,"TH_EXPLICIT_PROSPECTIVE_01"},
    "th|ยังไม่อนุมัติ":{NotYet,"TH_EXPLICIT_NOT_YET_01"},
}

func NormalizeDate(calendar Calendar,year,month,day int)(string,error){
    if calendar!=Gregorian&&calendar!=ThaiBuddhist{
        return "",errors.New("CALENDAR_NOT_DECLARED")
    }
    if calendar==ThaiBuddhist {
        // Explicit BE year only; never infer calendar from language.
        if year<2400||year>2800{return "",errors.New("BE_YEAR_OUT_OF_SCOPE")}
        year-=543
    }
    if year<1600||year>2500{return "",errors.New("YEAR_OUT_OF_SCOPE")}
    if month<1||month>12||day<1||day>31{return "",errors.New("DATE_COMPONENT_INVALID")}
    value:=time.Date(year,time.Month(month),day,0,0,0,0,time.UTC)
    if value.Year()!=year||int(value.Month())!=month||value.Day()!=day {
        return "",errors.New("IMPOSSIBLE_DATE")
    }
    return value.Format("2006-01-02"),nil
}
func Interpret(p AnnotatedPhrase)(TemporalFinding,error){
    if p.OriginalSourceID==""||p.Quote==""{
        return TemporalFinding{},errors.New("SOURCE_OR_QUOTE_MISSING")
    }
    if p.Calendar!=Gregorian && p.Calendar!=ThaiBuddhist {
        return TemporalFinding{},errors.New("CALENDAR_NOT_DECLARED")
    }
    // Date is source-annotated and explicit ISO Gregorian. It is a DATE,
    // not a UTC event instant; no midnight is invented for the original.
    parsed,err:=time.Parse("2006-01-02",p.EffectiveDateISO)
    if err!=nil||parsed.Format("2006-01-02")!=p.EffectiveDateISO {
        return TemporalFinding{},errors.New("DATE_ANNOTATION_INVALID")
    }
    key:=p.Language+"|"+p.Quote
    entry,ok:=reviewed[key]
    if !ok{return TemporalFinding{},errors.New("UNSUPPORTED_TEMPORAL_PHRASE")}
    return TemporalFinding{
        SourceID:p.OriginalSourceID,Language:p.Language,
        OriginalQuote:p.Quote,GregorianDate:p.EffectiveDateISO,
        Aspect:entry.aspect,AssertsCompletedEvent:entry.aspect==Completed,
        RuleID:entry.rule,
    },nil
}
func parseWall(wall string)(time.Time,error){
    t,err:=time.Parse("2006-01-02T15:04:05",wall)
    if err!=nil || t.Format("2006-01-02T15:04:05")!=wall {
        return time.Time{},errors.New("LOCAL_WALL_CLOCK_INVALID")
    }
    return t,nil
}
func ResolveLocalWall(wall,timezone string,offsetMinutes *int)(LocalResolution,error){
    naive,err:=parseWall(wall)
    if err!=nil{return LocalResolution{},err}
    if timezone!="Europe/Berlin"&&timezone!="Asia/Bangkok" {
        return LocalResolution{},errors.New("TIMEZONE_NOT_REVIEWED")
    }
    loc,err:=time.LoadLocation(timezone)
    if err!=nil{return LocalResolution{},err}
    // Enumerate possible UTC offsets at 15-minute granularity; explicitly
    // locate the same local wall time. This detects DST folds and gaps rather
    // than silently letting time.Date pick an arbitrary answer.
    candidates:=[]time.Time{}
    for offset:=-14*60;offset<=14*60;offset+=15 {
        utc:=naive.Add(-time.Duration(offset)*time.Minute)
        local:=utc.In(loc)
        if local.Format("2006-01-02T15:04:05")!=wall{continue}
        _,actual:=local.Zone()
        if actual!=offset*60 {continue}
        candidates=append(candidates,utc)
    }
    sort.Slice(candidates,func(i,j int)bool{return candidates[i].Before(candidates[j])})
    opts:=make([]string,len(candidates))
    for i,instant:=range candidates {opts[i]=instant.UTC().Format(time.RFC3339)}
    if len(candidates)==0{
        return LocalResolution{Classification:"NONEXISTENT_LOCAL_CLOCK"},nil
    }
    if offsetMinutes!=nil{
        for _,instant:=range candidates {
            _,seconds:=instant.In(loc).Zone()
            if seconds==(*offsetMinutes)*60{
                return LocalResolution{Classification:"RESOLVED_EXPLICIT_OFFSET",
                    UTC:instant.UTC().Format(time.RFC3339),CandidateUTC:opts},nil
            }
        }
        return LocalResolution{},errors.New("OFFSET_CONTRADICTS_TIMEZONE")
    }
    if len(candidates)>1{
        return LocalResolution{Classification:"AMBIGUOUS_LOCAL_CLOCK",
            CandidateUTC:opts},nil
    }
    return LocalResolution{Classification:"UNAMBIGUOUS_LOCAL_CLOCK",
        UTC:opts[0],CandidateUTC:opts},nil
}
func LocalRelativeDate(referenceInstant time.Time,timezone,relation string)(string,error){
    if timezone!="Europe/Berlin"&&timezone!="Asia/Bangkok"{
        return "",errors.New("TIMEZONE_NOT_REVIEWED")
    }
    if relation!="today"&&relation!="tomorrow"&&relation!="yesterday"{
        return "",errors.New("RELATIVE_EXPRESSION_UNSUPPORTED")
    }
    loc,err:=time.LoadLocation(timezone)
    if err!=nil{return "",err}
    base:=referenceInstant.In(loc)
    delta:=0
    if relation=="tomorrow"{delta=1}
    if relation=="yesterday"{delta=-1}
    // AddDate changes calendar dates, not 24-hour UTC durations.
    return base.AddDate(0,0,delta).Format("2006-01-02"),nil
}
func SameTemporalPresentation(a,b TemporalFinding)bool{
    // Same representation never implies same source identity or truth.
    return a.GregorianDate==b.GregorianDate &&
        a.Aspect==b.Aspect && a.Aspect==Completed
}
func ValidateQuoteBound(sourceRaw,quote string)error{
    if quote==""||!strings.Contains(sourceRaw,quote){
        return fmt.Errorf("SOURCE_QUOTE_NOT_ANCHORED")
    }
    return nil
}
