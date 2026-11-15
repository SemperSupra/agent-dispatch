// Package evidence qualifies an immutable, synthetic mail evidence contract.
//
// This is a deterministic typed-query oracle, NOT an email parser, an LLM,
// a natural-language QA model or a qualified PST reader. Original source
// occurrences and attachment multiplicity cannot be collapsed.
package evidence

import (
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "sort"
    "strings"
    "time"
)

const Schema = "mail-public-evidence-challenge/v1"

type Attachment struct {
    ID string
    Filename string
    Content string
    SHA256 string
}
type Claim struct {
    Key string
    Value string
    Quote string
    ValidAt string
}
type Observation struct {
    ID string
    Archive string
    Locator string
    Tenant string
    MessageID string
    Group string
    ParentID string
    CapturedAt string
    Raw string
    SHA256 string
    Attachments []Attachment
    Claims []Claim
}
type Ledger struct {
    Schema string
    Observations []Observation
}
type Citation struct {
    OccurrenceID string
    SourceSHA256 string
    Start int
    End int
    Quote string
}
type Question struct {
    ID string
    Language string
    Question string
    Tenant string
    Mode string
    Group string
    Key string
    AsOf string
    OccurrenceID string
    OtherID string
    Filename string
}
type AttachmentRef struct {
    SourceOccurrenceID string
    AttachmentID string
    Filename string
    SHA256 string
}
type Answer struct {
    QuestionID string
    Classification string
    Value string
    IDs []string
    Citations []Citation
    AttachmentRefs []AttachmentRef
}
type Evaluation struct {
    Schema string
    Classification string
    SourceOccurrences int
    AttachmentOccurrences int
    QuestionCount int
    VerifiedQuestions int
    FalseMergeCount int
    CrossTenantLeaks int
    IndependentGold bool
    PersistenceRecovery bool
    ModelInference bool
    NativePSTConformance string
    CorpusSHA256 string
}

func hash(content string) string {
    sum := sha256.Sum256([]byte(content))
    return hex.EncodeToString(sum[:])
}
func newAttachment(id, filename, content string) Attachment {
    return Attachment{ID:id, Filename:filename, Content:content, SHA256:hash(content)}
}
func newObservation(id, archive, locator, tenant, msgID, group, parent, at, raw string, claims []Claim, files ...Attachment) Observation {
    return Observation{ID:id, Archive:archive, Locator:locator, Tenant:tenant,
        MessageID:msgID, Group:group, ParentID:parent, CapturedAt:at,
        Raw:raw, SHA256:hash(raw), Attachments:files, Claims:claims}
}
func Fixture() Ledger {
    v1 := newAttachment("a-1/0", "report.txt", "fictional report first attachment")
    v2 := newAttachment("a-1/1", "report.txt", "fictional report second attachment")
    updated := newAttachment("b-1/0", "report.txt", "fictional report revised")
    rawBudget := "Subject: Fictional coast budget\nCoast budget: 120 units.\n"
    rawFerry := "Subject: Fictional ferry\nFerry date: Friday.\n"
    rawUpdated := "Subject: Fictional coast budget revision\nCoast budget: 150 units.\n"
    rawDeutsch := "Betreff: Küstenfreigabe\nBudgetfreigabe abgelehnt.\n"
    rawThai := "เรื่อง: อนุมัติชายฝั่ง\nอนุมัติแล้ว\n"
    rawPending := "Subject: Unassigned release\nRelease status: pending.\n"
    rawPrivate := "Subject: Confidential starling ledger\nSecret marker is beta-only.\n"
    return Ledger{Schema:Schema, Observations:[]Observation{
        newObservation("a-1","export-a","folder:1/item:1","alpha","<collision@invalid.test>","coast","","2026-05-01T09:00:00Z",rawBudget,
            []Claim{{Key:"budget",Value:"120",Quote:"Coast budget: 120 units.",ValidAt:"2026-05-01T09:00:00Z"}},v1,v2),
        // A distinct message uses an identical Message-ID on purpose.
        newObservation("a-2","export-a","folder:1/item:2","alpha","<collision@invalid.test>","ferry","","2026-05-02T09:00:00Z",rawFerry,
            []Claim{{Key:"date",Value:"Friday",Quote:"Ferry date: Friday.",ValidAt:"2026-05-02T09:00:00Z"}}),
        newObservation("b-1","export-b","folder:9/item:7","alpha","<collision@invalid.test>","coast","","2026-05-03T09:00:00Z",rawUpdated,
            []Claim{{Key:"budget",Value:"150",Quote:"Coast budget: 150 units.",ValidAt:"2026-05-03T09:00:00Z"}},updated),
        // A repeated acquisition of the same original bytes is still an occurrence.
        newObservation("c-1","export-c","folder:3/item:8","alpha","<collision@invalid.test>","coast","","2026-05-04T09:00:00Z",rawBudget,
            []Claim{{Key:"budget",Value:"120",Quote:"Coast budget: 120 units.",ValidAt:"2026-05-01T09:00:00Z"}},
            newAttachment("c-1/0","report.txt","fictional report first attachment"),
            newAttachment("c-1/1","report.txt","fictional report second attachment")),
        newObservation("a-3","export-a","folder:1/item:3","alpha","<german-reply@invalid.test>","coast","a-1","2026-05-02T11:00:00Z",rawDeutsch,
            []Claim{{Key:"approval",Value:"denied",Quote:"Budgetfreigabe abgelehnt.",ValidAt:"2026-05-02T11:00:00Z"}}),
        newObservation("a-4","export-a","folder:1/item:4","alpha","<thai-reply@invalid.test>","coast","a-3","2026-05-04T12:00:00Z",rawThai,
            []Claim{{Key:"approval",Value:"approved",Quote:"อนุมัติแล้ว",ValidAt:"2026-05-04T12:00:00Z"}}),
        // Missing Message-ID and absent from later snapshots does NOT imply deleted.
        newObservation("a-5","export-a","folder:1/item:5","alpha","","release","","2026-05-02T13:00:00Z",rawPending,
            []Claim{{Key:"status",Value:"pending",Quote:"Release status: pending.",ValidAt:"2026-05-02T13:00:00Z"}}),
        newObservation("beta-1","export-beta","folder:secret/item:1","beta","<private@invalid.test>","starling","","2026-05-02T10:00:00Z",rawPrivate,
            []Claim{{Key:"marker",Value:"beta-only",Quote:"Secret marker is beta-only.",ValidAt:"2026-05-02T10:00:00Z"}}),
    }}
}
func (l Ledger) Validate() error {
    if l.Schema != Schema || len(l.Observations)==0 {return errors.New("SCHEMA_OR_EMPTY")}
    seen := map[string]bool{}
    attachmentIDs:=map[string]bool{}
    for _,o:= range l.Observations {
        if o.ID=="" || o.Tenant=="" || o.Archive=="" || o.Locator=="" || seen[o.ID] {return errors.New("OCCURRENCE_IDENTITY")}
        seen[o.ID]=true
        if hash(o.Raw)!=o.SHA256 {return errors.New("SOURCE_DIGEST_MISMATCH")}
        for _,a:=range o.Attachments {
            if a.ID=="" || attachmentIDs[a.ID] || hash(a.Content)!=a.SHA256 {return errors.New("ATTACHMENT_ID_OR_DIGEST")}
            attachmentIDs[a.ID]=true
        }
        for _,c:=range o.Claims {
            if c.Key=="" || c.Quote=="" || !strings.Contains(o.Raw,c.Quote) {return errors.New("CLAIM_NOT_ANCHORED")}
            if _,err:=time.Parse(time.RFC3339,c.ValidAt);err!=nil {return errors.New("CLAIM_TIME_INVALID")}
        }
        if o.ParentID==o.ID {return errors.New("SELF_REPLY_PARENT")}
    }
    for _,o:=range l.Observations {
        if o.ParentID!="" {
            if !seen[o.ParentID] {return errors.New("PARENT_ABSENT")}
            parent,_:=l.byID(o.ParentID)
            if parent.Tenant!=o.Tenant {return errors.New("CROSS_TENANT_THREAD")}
        }
    }
    return nil
}
func (l Ledger) byID(id string) (Observation,bool) {
    for _,o:=range l.Observations {if o.ID==id{return o,true}}
    return Observation{},false
}
func cite(o Observation, quote string) Citation {
    start:=bytes.Index([]byte(o.Raw),[]byte(quote))
    if start<0 {panic("invalid fixture quote")}
    return Citation{OccurrenceID:o.ID, SourceSHA256:o.SHA256,Start:start,End:start+len([]byte(quote)),Quote:quote}
}
func (l Ledger) Answer(q Question) (Answer,error) {
    if err:=l.Validate();err!=nil{return Answer{},err}
    ans:=Answer{QuestionID:q.ID,Classification:"ABSTAIN"}
    visible:=[]Observation{}
    for _,o:=range l.Observations {if o.Tenant==q.Tenant {visible=append(visible,o)}}
    switch q.Mode {
    case "fact-asof":
        cutoff,err:=time.Parse(time.RFC3339,q.AsOf);if err!=nil{return ans,errors.New("BAD_ASOF")}
        var best *Claim
        var bestObservation Observation
        var bestAt time.Time
        for _,o:=range visible {
            if o.Group!=q.Group {continue}
            for _,c:=range o.Claims {
                when,_:=time.Parse(time.RFC3339,c.ValidAt)
                if c.Key!=q.Key||when.After(cutoff){continue}
                if best==nil || when.After(bestAt) || (when.Equal(bestAt)&&o.ID<bestObservation.ID) {
                    copyClaim:=c
                    best=&copyClaim
                    bestObservation=o
                    bestAt=when
                }
            }
        }
        if best!=nil{
            ans.Classification="SUPPORTED";ans.Value=best.Value
            ans.IDs=[]string{bestObservation.ID}
            ans.Citations=[]Citation{cite(bestObservation,best.Quote)}
        }
    case "source-by-id":
        for _,o:=range visible {
            if o.ID==q.OccurrenceID {
                ans.Classification="SUPPORTED";ans.Value=o.Group
                ans.IDs=[]string{o.ID};ans.Citations=[]Citation{cite(o,o.Raw)}
            }
        }
    case "message-id-collisions":
        ids:=[]string{}
        for _,o:=range visible {if o.MessageID!="" && o.MessageID==q.Key {ids=append(ids,o.ID)}}
        if len(ids)>0 {
            sort.Strings(ids);ans.Classification="SUPPORTED";ans.Value=fmt.Sprint(len(ids));ans.IDs=ids
            for _,id:=range ids {o,_:=l.byID(id);ans.Citations=append(ans.Citations,cite(o,o.Raw))}
        }
    case "attachment-by-filename":
        for _,o:=range visible {
            if o.ID!=q.OccurrenceID {continue}
            for _,a:=range o.Attachments {if a.Filename==q.Filename{
                ans.IDs=append(ans.IDs,a.ID)
                ans.AttachmentRefs=append(ans.AttachmentRefs,AttachmentRef{SourceOccurrenceID:o.ID,AttachmentID:a.ID,Filename:a.Filename,SHA256:a.SHA256})
            }}
        }
        if len(ans.IDs)>0 {ans.Classification="SUPPORTED";ans.Value=fmt.Sprint(len(ans.IDs))}
    case "attachment-version":
        a,foundA:=l.byID(q.OccurrenceID);b,foundB:=l.byID(q.OtherID)
        if foundA&&foundB&&a.Tenant==q.Tenant&&b.Tenant==q.Tenant {
            left:=[]string{};right:=[]string{}
            for _,x:=range a.Attachments {left=append(left,x.SHA256)}
            for _,x:=range b.Attachments {right=append(right,x.SHA256)}
            if len(left)>0&&len(right)>0 {
                sort.Strings(left);sort.Strings(right)
                if strings.Join(left,",")!=strings.Join(right,","){ans.Value="changed"}else{ans.Value="unchanged"}
                ans.Classification="SUPPORTED";ans.IDs=[]string{a.ID,b.ID}
                for _,o:=range []Observation{a,b} {
                    ans.Citations=append(ans.Citations,cite(o,o.Raw))
                    for _,f:=range o.Attachments {
                        ans.AttachmentRefs=append(ans.AttachmentRefs,AttachmentRef{SourceOccurrenceID:o.ID,AttachmentID:f.ID,Filename:f.Filename,SHA256:f.SHA256})
                    }
                }
            }
        }
    case "thread-parent":
        o,ok:=l.byID(q.OccurrenceID)
        if ok && o.Tenant==q.Tenant && o.ParentID!="" {
            p,exists:=l.byID(o.ParentID)
            if exists&&p.Tenant==q.Tenant {
                ans.Classification="SUPPORTED";ans.Value=p.ID;ans.IDs=[]string{p.ID,o.ID}
                ans.Citations=[]Citation{cite(p,p.Raw),cite(o,o.Raw)}
            }
        }
    default:return ans,errors.New("UNKNOWN_QUERY_MODE")
    }
    return ans,nil
}
func (l Ledger) Persist(path string) error {
    if err:=l.Validate();err!=nil {return err}
    payload,err:=json.Marshal(l);if err!=nil{return err}
    dir:=filepath.Dir(path)
    temp,err:=os.CreateTemp(dir,".mail-public-*.tmp");if err!=nil{return err}
    tmpname:=temp.Name();defer os.Remove(tmpname)
    if _,err=temp.Write(payload);err!=nil {temp.Close();return err}
    if err=temp.Sync();err!=nil {temp.Close();return err}
    if err=temp.Close();err!=nil{return err}
    return os.Rename(tmpname,path)
}
func Recover(path string) (Ledger,error) {
    raw,err:=os.ReadFile(path);if err!=nil{return Ledger{},err}
    if len(raw)>1_048_576 {return Ledger{},errors.New("SOURCE_SNAPSHOT_TOO_LARGE")}
    var value Ledger
    if err=json.Unmarshal(raw,&value);err!=nil{return Ledger{},err}
    if err=value.Validate();err!=nil{return Ledger{},err}
    return value,nil
}
func (l Ledger) Digest() string {
    copies:=append([]Observation(nil),l.Observations...)
    sort.Slice(copies,func(i,j int)bool{return copies[i].ID<copies[j].ID})
    data,_:=json.Marshal(copies)
    return hash(string(data))
}
