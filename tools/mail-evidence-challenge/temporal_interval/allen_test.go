package intervalqual

import (
    "testing"
    "time"
)
func hour(v int)time.Time{return time.Date(2026,5,1,v,0,0,0,time.UTC)}
func rangeOf(start,end int)Interval{return Interval{hour(start),hour(end)}}
func TestAllThirteenAllenRelationsAndInverses(t *testing.T){
    base:=rangeOf(4,9)
    tests:=[]struct{name string; other Interval; want Relation}{
        {"before",rangeOf(10,12),Before},
        {"meets",rangeOf(9,12),Meets},
        {"overlaps",rangeOf(7,12),Overlaps},
        {"starts",rangeOf(4,12),Starts},
        {"during",rangeOf(3,12),During},
        {"finishes",rangeOf(3,9),Finishes},
        {"equals",rangeOf(4,9),Equals},
        {"after",rangeOf(1,3),After},
        {"met-by",rangeOf(1,4),MetBy},
        {"overlapped-by",rangeOf(1,6),OverlappedBy},
        {"started-by",rangeOf(4,6),StartedBy},
        {"contains",rangeOf(6,8),Contains},
        {"finished-by",rangeOf(6,9),FinishedBy},
    }
    if len(tests)!=13 {t.Fatal("expected all 13 cases")}
    found:=map[Relation]bool{}
    for _,tc:=range tests{
        t.Run(tc.name,func(t *testing.T){
            actual,err:=Compare(base,tc.other)
            if err!=nil||actual!=tc.want{
                t.Fatalf("Allen relation: actual %s expected %s err %v",actual,tc.want,err)
            }
            reverse,err:=Compare(tc.other,base)
            if err!=nil||reverse!=Invert(tc.want){
                t.Fatalf("inverse relation actual %s expected %s err %v",reverse,Invert(tc.want),err)
            }
            found[actual]=true
        })
    }
    if len(found)!=13{t.Fatalf("only %d distinct relations",len(found))}
}
func TestUncertainIntervalsFailClosedWithoutInventingPointTime(t *testing.T){
    exact:=rangeOf(4,9)
    fuzzy:=Uncertain{hour(5),hour(6),hour(10),hour(12)}
    relation,err:=ConservativeCompare(exact.Bounds(),fuzzy)
    if err!=nil||relation!=Undetermined{
        t.Fatalf("uncertain overlap converted to certain relation %s %v",relation,err)
    }
    future:=Uncertain{hour(13),hour(14),hour(15),hour(16)}
    relation,err=ConservativeCompare(fuzzy,future)
    if err!=nil||relation!=Before{
        t.Fatalf("definitive separation denied %s %v",relation,err)
    }
    relation,err=ConservativeCompare(future,fuzzy)
    if err!=nil||relation!=After {
        t.Fatalf("inverted definitive separation failed %s %v",relation,err)
    }
    // Uncertain ranges must never be treated as a point-date timestamp.
    if relation,err:=ConservativeCompare(
        Uncertain{hour(4),hour(4),hour(9),hour(9)},
        exact.Bounds());err!=nil||relation!=Equals{
        t.Fatalf("degenerate uncertainty lost exactness %s %v",relation,err)
    }
}
func TestMalformedIntervalsAndMissingTimeDenied(t *testing.T){
    for _,tc:=range []Interval{
        {hour(4),hour(4)},{hour(9),hour(4)},{time.Time{},hour(4)},
        {hour(4),time.Time{}},
    }{
        if _,err:=Compare(tc,rangeOf(5,9));err==nil{
            t.Fatalf("accepted invalid interval %+v",tc)
        }
    }
    if _,err:=ConservativeCompare(Uncertain{
        hour(9),hour(4),hour(8),hour(10)},rangeOf(3,9).Bounds());err==nil{
        t.Fatal("reversed possible-start bound accepted")
    }
}
