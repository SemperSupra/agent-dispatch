package temporallanguage

import (
    "slices"
    "strings"
    "testing"
    "time"
)

func TestExplicitBuddhistAndGregorianCalendarDateNormalization(t *testing.T){
    cases:=[]struct{
        calendar Calendar
        year,month,day int
        expected string
    }{
        {ThaiBuddhist,2569,4,13,"2026-04-13"},
        {Gregorian,2026,4,13,"2026-04-13"},
        {ThaiBuddhist,2569,2,28,"2026-02-28"},
        {Gregorian,2024,2,29,"2024-02-29"},
    }
    for _,tc:=range cases {
        got,err:=NormalizeDate(tc.calendar,tc.year,tc.month,tc.day)
        if err!=nil||got!=tc.expected{t.Fatalf("expected %q, got %q (%v)",tc.expected,got,err)}
    }
    for _,tc:=range []struct{calendar Calendar;year,month,day int}{
        {"",2569,4,13},{ThaiBuddhist,2026,4,13},
        {Gregorian,2026,2,29},{Gregorian,2026,13,1},
        {Gregorian,2026,4,31},
    }{
        if got,err:=NormalizeDate(tc.calendar,tc.year,tc.month,tc.day);err==nil{
            t.Fatalf("accepted undeclared/impossible calendar %q",got)
        }
    }
}
func TestBerlinDaylightSavingNonexistentAndAmbiguousWallTimes(t *testing.T){
    gap,err:=ResolveLocalWall("2026-03-29T02:30:00","Europe/Berlin",nil)
    if err!=nil||gap.Classification!="NONEXISTENT_LOCAL_CLOCK"||len(gap.CandidateUTC)!=0 {
        t.Fatalf("spring DST gap was resolved without evidence: %+v %v",gap,err)
    }
    fold,err:=ResolveLocalWall("2026-10-25T02:30:00","Europe/Berlin",nil)
    if err!=nil||fold.Classification!="AMBIGUOUS_LOCAL_CLOCK"||
       !slices.Equal(fold.CandidateUTC,[]string{
           "2026-10-25T00:30:00Z","2026-10-25T01:30:00Z"}) {
        t.Fatalf("fall DST fold lost an alternative: %+v %v",fold,err)
    }
    first:=120
    resolved,err:=ResolveLocalWall("2026-10-25T02:30:00","Europe/Berlin",&first)
    if err!=nil||resolved.UTC!="2026-10-25T00:30:00Z"||
       resolved.Classification!="RESOLVED_EXPLICIT_OFFSET"{
        t.Fatalf("first fold UTC incorrect: %+v %v",resolved,err)
    }
    second:=60
    resolved,err=ResolveLocalWall("2026-10-25T02:30:00","Europe/Berlin",&second)
    if err!=nil||resolved.UTC!="2026-10-25T01:30:00Z"{
        t.Fatalf("second fold UTC incorrect: %+v %v",resolved,err)
    }
    impossible:=180
    if _,err:=ResolveLocalWall("2026-10-25T02:30:00","Europe/Berlin",&impossible);
        err==nil||!strings.Contains(err.Error(),"OFFSET_CONTRADICTS_TIMEZONE"){
        t.Fatalf("explicit wrong zone offset was accepted: %v",err)
    }
    bangkok,err:=ResolveLocalWall("2026-10-25T02:30:00","Asia/Bangkok",nil)
    if err!=nil||bangkok.Classification!="UNAMBIGUOUS_LOCAL_CLOCK"||
       bangkok.UTC!="2026-10-24T19:30:00Z"{
        t.Fatalf("Bangkok time handling incorrect: %+v %v",bangkok,err)
    }
    for _,bad:=range []string{"2026-03-29T24:30:00","2026-02-29T12:00:00",
        "2026-10-25T02:30","not-a-time"} {
        if _,err:=ResolveLocalWall(bad,"Europe/Berlin",nil);err==nil{
            t.Fatalf("invalid wall time accepted: %q",bad)
        }
    }
}
func TestTomorrowUsesLocalCalendarNotUtcDuration(t *testing.T){
    instant:=time.Date(2026,10,24,21,30,0,0,time.UTC)
    berlin,err:=LocalRelativeDate(instant,"Europe/Berlin","tomorrow")
    if err!=nil||berlin!="2026-10-25"{t.Fatalf("German local tomorrow: %q %v",berlin,err)}
    bangkok,err:=LocalRelativeDate(instant,"Asia/Bangkok","tomorrow")
    if err!=nil||bangkok!="2026-10-26"{t.Fatalf("Thai local tomorrow: %q %v",bangkok,err)}
    if _,err:=LocalRelativeDate(instant,"Europe/Berlin","next Friday");err==nil{
        t.Fatal("ambiguous relative weekday accepted without reference rule")
    }
}
func TestEnglishGermanThaiProspectiveAndCompletedSeparate(t *testing.T){
    corpus:=[]struct{
        lang,quote string
        want Aspect
    }{
        {"en","Approval was granted.",Completed},
        {"en","Approval will be granted.",Prospective},
        {"en","Approval has not yet been granted.",NotYet},
        {"de","Die Freigabe wurde erteilt.",Completed},
        {"de","Die Freigabe wird morgen erteilt.",Prospective},
        {"de","Die Freigabe ist noch nicht erteilt.",NotYet},
        {"th","อนุมัติแล้ว",Completed},
        {"th","จะอนุมัติ",Prospective},
        {"th","ยังไม่อนุมัติ",NotYet},
    }
    for i,tc:=range corpus{
        p:=AnnotatedPhrase{Language:tc.lang,Quote:tc.quote,
            OriginalSourceID:string(rune('A'+i)),Calendar:Gregorian,
            EffectiveDateISO:"2026-04-13"}
        result,err:=Interpret(p)
        if err!=nil||result.Aspect!=tc.want||
            result.AssertsCompletedEvent!=(tc.want==Completed)||
            result.SourceID!=p.OriginalSourceID||result.RuleID==""{
            t.Fatalf("quoted annotated language failed: %+v %v",result,err)
        }
        if err:=ValidateQuoteBound("source occurrence: "+tc.quote,tc.quote);err!=nil{
            t.Fatal("exact source quote became unanchored",err)
        }
    }
    for _,unsupported:=range []AnnotatedPhrase{
        {Language:"th",Quote:"อนุมัติ",OriginalSourceID:"th-ambiguous",
            Calendar:ThaiBuddhist,EffectiveDateISO:"2026-04-13"},
        {Language:"de",Quote:"wird erteilt",OriginalSourceID:"de-ambiguous",
            Calendar:Gregorian,EffectiveDateISO:"2026-04-13"},
        {Language:"en",Quote:"Approval maybe granted.",OriginalSourceID:"en-ambiguous",
            Calendar:Gregorian,EffectiveDateISO:"2026-04-13"},
        {Language:"th",Quote:"อนุมัติแล้ว",OriginalSourceID:"missing-calendar",
            EffectiveDateISO:"2026-04-13"},
    }{
        if _,err:=Interpret(unsupported);err==nil{
            t.Fatalf("uncertain/undeclared phrase treated as fact: %+v",unsupported)
        }
    }
}
func TestSameDateDoesNotMergeIndependentDocuments(t *testing.T){
    left,err:=Interpret(AnnotatedPhrase{Language:"de",Quote:"Die Freigabe wurde erteilt.",
        OriginalSourceID:"archive-a/native-7",Calendar:Gregorian,EffectiveDateISO:"2026-04-13"})
    if err!=nil{t.Fatal(err)}
    right,err:=Interpret(AnnotatedPhrase{Language:"th",Quote:"อนุมัติแล้ว",
        OriginalSourceID:"archive-b/native-21",Calendar:ThaiBuddhist,EffectiveDateISO:"2026-04-13"})
    if err!=nil{t.Fatal(err)}
    if !SameTemporalPresentation(left,right)||left.SourceID==right.SourceID{
        t.Fatal("temporal presentation or source occurrence identity invalid")
    }
    if err:=ValidateQuoteBound("A different unrelated source",left.OriginalQuote);err==nil{
        t.Fatal("allowing quote from source not containing original words")
    }
}
