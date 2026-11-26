// Package intervalqual is a bounded Go test adapter for Allen's established
// interval algebra. It does not reinvent time parsing or infer temporal truth.
package intervalqual

import (
    "errors"
    "time"
)

type Relation string

const (
    Before Relation="BEFORE"
    Meets Relation="MEETS"
    Overlaps Relation="OVERLAPS"
    Starts Relation="STARTS"
    During Relation="DURING"
    Finishes Relation="FINISHES"
    Equals Relation="EQUALS"
    After Relation="AFTER"
    MetBy Relation="MET_BY"
    OverlappedBy Relation="OVERLAPPED_BY"
    StartedBy Relation="STARTED_BY"
    Contains Relation="CONTAINS"
    FinishedBy Relation="FINISHED_BY"
    Undetermined Relation="UNDETERMINED"
)
type Interval struct {
    Start time.Time
    End time.Time
}
type Uncertain struct {
    EarliestStart time.Time
    LatestStart time.Time
    EarliestEnd time.Time
    LatestEnd time.Time
}
func (v Interval) Validate() error {
    if v.Start.IsZero()||v.End.IsZero()||!v.Start.Before(v.End){
        return errors.New("INVALID_EXACT_INTERVAL")
    }
    return nil
}
func (b Uncertain) Validate() error {
    if b.EarliestStart.IsZero()||b.LatestStart.IsZero()||
       b.EarliestEnd.IsZero()||b.LatestEnd.IsZero() ||
       b.EarliestStart.After(b.LatestStart)||
       b.EarliestEnd.After(b.LatestEnd)||
       !b.EarliestStart.Before(b.LatestEnd){
        return errors.New("INVALID_UNCERTAIN_BOUNDS")
    }
    // There must be at least one permitted positive-duration interval.
    return nil
}
func (v Interval) Bounds() Uncertain {
    return Uncertain{v.Start,v.Start,v.End,v.End}
}
func Compare(a,b Interval) (Relation,error) {
    if err:=a.Validate();err!=nil{return Undetermined,err}
    if err:=b.Validate();err!=nil{return Undetermined,err}
    s,e,x,y:=a.Start,a.End,b.Start,b.End
    switch {
    case e.Before(x):return Before,nil
    case e.Equal(x):return Meets,nil
    case s.After(y):return After,nil
    case s.Equal(y):return MetBy,nil
    case s.Equal(x)&&e.Equal(y):return Equals,nil
    case s.Equal(x)&&e.Before(y):return Starts,nil
    case s.Equal(x)&&e.After(y):return StartedBy,nil
    case e.Equal(y)&&s.After(x):return Finishes,nil
    case e.Equal(y)&&s.Before(x):return FinishedBy,nil
    case s.After(x)&&e.Before(y):return During,nil
    case s.Before(x)&&e.After(y):return Contains,nil
    case s.Before(x)&&e.After(x)&&e.Before(y):return Overlaps,nil
    case s.After(x)&&s.Before(y)&&e.After(y):return OverlappedBy,nil
    default:return Undetermined,errors.New("ALLEN_CLASSIFICATION_INCOMPLETE")
    }
}
func ConservativeCompare(a,b Uncertain)(Relation,error){
    if err:=a.Validate();err!=nil{return Undetermined,err}
    if err:=b.Validate();err!=nil{return Undetermined,err}
    if a.EarliestStart.Equal(a.LatestStart)&&
       a.EarliestEnd.Equal(a.LatestEnd)&&
       b.EarliestStart.Equal(b.LatestStart)&&
       b.EarliestEnd.Equal(b.LatestEnd){
        return Compare(Interval{a.EarliestStart,a.EarliestEnd},
                       Interval{b.EarliestStart,b.EarliestEnd})
    }
    // Strict separation can be certain despite fuzzy boundaries; if not,
    // refuse to invent a single unique Allen relation from incomplete dates.
    if a.LatestEnd.Before(b.EarliestStart){return Before,nil}
    if a.EarliestStart.After(b.LatestEnd){return After,nil}
    return Undetermined,nil
}
func Invert(r Relation) Relation {
    inverse:=map[Relation]Relation{
        Before:After,Meets:MetBy,Overlaps:OverlappedBy,
        Starts:StartedBy,During:Contains,Finishes:FinishedBy,
        Equals:Equals,After:Before,MetBy:Meets,
        OverlappedBy:Overlaps,StartedBy:Starts,Contains:During,
        FinishedBy:Finishes,Undetermined:Undetermined,
    }
    return inverse[r]
}
