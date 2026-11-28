package annotationbenchmark

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxCompletionBytes = 32768

// RawResponse is supplied by the execution harness, not by the model. The
// frozen context binds each output to its source. A noncompleted execution is
// deliberately scored invalid, never converted to an empty successful answer.
type RawResponse struct {
	ID string `json:"id"`
	SourceID string `json:"source_id"`
	BodySHA256 string `json:"body_sha256"`
	Status string `json:"status"` // completed, timeout, transport_error, truncated
	Completion string `json:"completion"`
}

type NormalizedRow struct {
	Submission Submission `json:"submission"`
	Status string `json:"status"`
	CompletionSHA256 string `json:"completion_sha256"`
}

type RawReport struct {
	Report Report `json:"report"`
	JournalSHA256 string `json:"journal_sha256"`
	NormalizationCounts map[string]int `json:"normalization_counts"`
	Rows []NormalizedRow `json:"rows"`
}

type candidateClaim struct {
	Quote string `json:"quote"`
	Polarity int `json:"polarity"`
	Modality string `json:"modality"`
	ValidFrom string `json:"valid_from"`
	ValidTo string `json:"valid_to"`
}

// Validate JSON recursively before decoding into structs. encoding/json
// otherwise accepts duplicate keys, case-folded fields and some lossy
// string encodings. U+FFFD is conservatively unsupported at this boundary,
// including a literal replacement character: no silent surrogate repair.
func strictValue(d *json.Decoder,depth int)error{
	if depth>16{return errors.New("JSON_DEPTH")}
	t,err:=d.Token();if err!=nil{return errors.New("JSON_TOKEN")}
	switch v:=t.(type){
	case string:
		if strings.ContainsRune(v,utf8.RuneError){return errors.New("JSON_REPLACEMENT_CHARACTER")}
	case json.Delim:
		switch v{
		case '{':
			seen:=map[string]bool{}
			for d.More(){
				k,e:=d.Token();if e!=nil{return errors.New("JSON_KEY")}
				key,ok:=k.(string);if !ok||strings.ContainsRune(key,utf8.RuneError)||seen[key]{return errors.New("JSON_DUPLICATE_OR_INVALID_KEY")}
				seen[key]=true
				if err:=strictValue(d,depth+1);err!=nil{return err}
			}
			end,e:=d.Token();if e!=nil||end!=json.Delim('}'){return errors.New("JSON_OBJECT")}
		case '[':
			for d.More(){if err:=strictValue(d,depth+1);err!=nil{return err}}
			end,e:=d.Token();if e!=nil||end!=json.Delim(']'){return errors.New("JSON_ARRAY")}
		default:return errors.New("JSON_DELIMITER")
		}
	}
	return nil
}
func strictJSON(raw []byte,limit int)error{
	if len(raw)==0||len(raw)>limit||!utf8.Valid(raw){return errors.New("JSON_BYTE_BOUND_OR_UTF8")}
	d:=json.NewDecoder(bytes.NewReader(raw));d.UseNumber()
	if err:=strictValue(d,0);err!=nil{return err}
	if _,err:=d.Token();err!=io.EOF{return errors.New("JSON_TRAILING")}
	return nil
}
func exactKeys(m map[string]json.RawMessage,names ...string)bool{
	if len(m)!=len(names){return false}
	for _,n:=range names{
		v,ok:=m[n];if !ok||bytes.Equal(bytes.TrimSpace(v),[]byte("null")){return false}
	}
	return true
}

var explicitSecond = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(Z|[+-][0-9]{2}:[0-9]{2})$`)
func normalizedTime(s string)(string,error){
	if !explicitSecond.MatchString(s)||strings.HasSuffix(s,"-00:00"){return "",errors.New("TIME_EXPLICIT_OFFSET_REQUIRED")}
	t,err:=time.Parse(time.RFC3339,s);if err!=nil{return "",errors.New("TIME_INVALID")}
	if !strings.HasSuffix(s,"Z"){
		zone:=s[len(s)-6:]
		if zone[1:3]>"23"||zone[4:6]>"59"{return "",errors.New("TIME_OFFSET_INVALID")}
	}
	out:=t.UTC().Format(time.RFC3339)
	if _,err=instant(out);err!=nil{return "",errors.New("TIME_NORMALIZATION_INVALID")}
	return out,nil
}

// uniqueQuote checks overlapping matches as well as disjoint occurrences.
// Use the same byte-anchor semantics for frozen gold and model completions.
func uniqueQuote(body,quote string)(int,bool){
	begin:=strings.Index(body,quote)
	if quote==""||begin<0||strings.Contains(body[begin+1:],quote){return 0,false}
	return begin,true
}

// NormalizeCompletion accepts only {claims:[{quote,polarity,modality,
// valid_from,valid_to}...]}. Quotes must occur exactly once, including
// overlapping occurrences. Offsets, IDs and hashes are derived by the
// harness. Only representation conversion is performed; no semantics repair,
// fuzzy matching, default time, partial acceptance or fabricated abstention.
func NormalizeCompletion(c Context,raw []byte)(Submission,error){
	s:=Submission{ID:c.ID,SourceID:c.SourceID,BodySHA256:c.BodySHA256}
	if c.ID==""||c.SourceID==""||len(c.Body)>16384||!utf8.ValidString(c.Body)||
		c.BodySHA256!=digest([]byte(c.Body)){return s,errors.New("CONTEXT_BINDING")}
	if err:=strictJSON(raw,MaxCompletionBytes);err!=nil{return s,err}
	var top map[string]json.RawMessage
	if err:=json.Unmarshal(raw,&top);err!=nil||!exactKeys(top,"claims"){return s,errors.New("RESPONSE_SCHEMA")}
	var items []json.RawMessage
	if err:=json.Unmarshal(top["claims"],&items);err!=nil||items==nil||len(items)>32{return s,errors.New("CLAIM_LIST")}
	claims:=[]Claim{}
	for _,item:=range items{
		var fields map[string]json.RawMessage
		if err:=json.Unmarshal(item,&fields);err!=nil||!exactKeys(fields,"quote","polarity","modality","valid_from","valid_to"){return s,errors.New("CLAIM_SCHEMA")}
		var x candidateClaim
		if err:=json.Unmarshal(item,&x);err!=nil{return s,errors.New("CLAIM_FIELD_TYPE")}
		begin,unique:=uniqueQuote(c.Body,x.Quote)
		if !unique{return s,errors.New("CLAIM_QUOTE_NOT_UNIQUE")}
		from,err:=normalizedTime(x.ValidFrom);if err!=nil{return s,err}
		to:="";if x.ValidTo!=""{to,err=normalizedTime(x.ValidTo);if err!=nil{return s,err}}
		claim:=Claim{Quote:x.Quote,Begin:begin,End:begin+len(x.Quote),Polarity:x.Polarity,
			Modality:x.Modality,ValidFrom:from,ValidTo:to}
		if !validClaim(claim,c){return s,errors.New("CLAIM_INVALID")}
		claims=append(claims,claim)
	}
	s.Claims=claims
	if !validate(s,c){s.Claims=nil;return s,errors.New("CLAIM_DUPLICATE_OR_INVALID")}
	return s,nil
}

// ScoreRawJSON consumes exactly one harness-bound response per frozen
// context. The oracle is used only in the subsequent Score call. Unknown,
// duplicate, omitted or misbound journal identities reject the entire arm.
func ScoreRawJSON(raw []byte)(RawReport,error){
	var zero RawReport
	if err:=strictJSON(raw,MaxInput);err!=nil{return zero,err}
	var items []json.RawMessage
	if err:=json.Unmarshal(raw,&items);err!=nil{return zero,errors.New("JOURNAL_SCHEMA")}
	ctx,err:=Contexts();if err!=nil{return zero,err}
	if len(items)!=len(ctx){return zero,errors.New("JOURNAL_COUNT")}
	byID:=map[string]Context{};for _,c:=range ctx{byID[c.ID]=c}
	seen:=map[string]bool{}
	rows:=[]Submission{}
	out:=RawReport{JournalSHA256:digest(raw),NormalizationCounts:map[string]int{},Rows:[]NormalizedRow{}}
	for _,item:=range items{
		var fields map[string]json.RawMessage
		if err:=json.Unmarshal(item,&fields);err!=nil||!exactKeys(fields,"id","source_id","body_sha256","status","completion"){return zero,errors.New("JOURNAL_ROW_SCHEMA")}
		var x RawResponse
		if err:=json.Unmarshal(item,&x);err!=nil{return zero,errors.New("JOURNAL_ROW_TYPE")}
		c,ok:=byID[x.ID]
		if !ok||seen[x.ID]||c.SourceID!=x.SourceID||c.BodySHA256!=x.BodySHA256{return zero,errors.New("JOURNAL_BINDING")}
		seen[x.ID]=true
		if len(x.Completion)>MaxCompletionBytes{return zero,errors.New("JOURNAL_COMPLETION_BOUND")}
		s:=Submission{ID:c.ID,SourceID:c.SourceID,BodySHA256:c.BodySHA256}
		status:=x.Status
		switch x.Status{
		case "completed":
			s,err=NormalizeCompletion(c,[]byte(x.Completion))
			if err!=nil{status=err.Error()}else{status="NORMALIZED"}
		case "timeout","transport_error","truncated":
			// keep nil claims, including if partial text appears valid
		default:return zero,errors.New("JOURNAL_STATUS")
		}
		rows=append(rows,s)
		out.NormalizationCounts[status]++
		out.Rows=append(out.Rows,NormalizedRow{Submission:s,Status:status,CompletionSHA256:digest([]byte(x.Completion))})
	}
	out.Report,err=Score(rows)
	if err!=nil{return zero,err}
	out.Report.Classification="SCORE_RAW_NORMALIZED_NOT_EXECUTION_ATTESTATION"
	return out,nil
}
