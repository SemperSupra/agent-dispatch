package experiment

import (
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "strings"
)

type Operation struct {
 Kind string `json:"kind"`
 Port *uint32 `json:"port,omitempty"`
 Width *uint32 `json:"width,omitempty"`
 Value *uint32 `json:"value,omitempty"`
 Nanoseconds *uint64 `json:"nanoseconds,omitempty"`
}

type Experiment struct {
 Version string `json:"version"`
 Scope string `json:"scope"`
 Operations []Operation `json:"operations"`
}

// exactObject rejects ambiguous JSON before typed decoding. It checks decoded
// key spelling, duplicate keys, nulls and the complete object shape.
func exactObject(raw []byte, allowed map[string]bool) (map[string]json.RawMessage,error) {
 d:=json.NewDecoder(strings.NewReader(string(raw)))
 t,err:=d.Token()
 if err!=nil || t!=json.Delim('{'){return nil,errors.New("object required")}
 fields:=map[string]json.RawMessage{}
 for d.More() {
  tok,err:=d.Token();if err!=nil{return nil,err}
  k,ok:=tok.(string);if !ok || !allowed[k]{return nil,errors.New("unknown or noncanonical field")}
  if _,exists:=fields[k];exists{return nil,errors.New("duplicate field")}
  var v json.RawMessage
  if err=d.Decode(&v);err!=nil{return nil,err}
  if strings.TrimSpace(string(v))=="null"{return nil,errors.New("null field")}
  fields[k]=v
 }
 t,err=d.Token()
 if err!=nil || t!=json.Delim('}') {return nil,errors.New("object end required")}
 var extra any
 if d.Decode(&extra)!=io.EOF{return nil,errors.New("trailing data")}
 return fields,nil
}

func exactExperiment(raw []byte) error {
 root,err:=exactObject(raw,map[string]bool{"version":true,"scope":true,"operations":true})
 if err!=nil{return err}
 var ops []json.RawMessage
 if err=json.Unmarshal(root["operations"],&ops);err!=nil{return err}
 if len(ops)==0 || len(ops)>128{return errors.New("operation count")}
 for _,op:=range ops{
  if _,err=exactObject(op,map[string]bool{"kind":true,"port":true,"width":true,"value":true,"nanoseconds":true});err!=nil{return err}
 }
 return nil
}

// Decode validates a bounded synthetic experiment proposal, not execution authority.
func Decode(r io.Reader) (Experiment,error) {
 var e Experiment
 b,err:=io.ReadAll(io.LimitReader(r,65537))
 if err!=nil || len(b)>65536 {return e,errors.New("input limit")}
 if err=exactExperiment(b);err!=nil{return e,err}
 d:=json.NewDecoder(strings.NewReader(string(b)))
 d.DisallowUnknownFields()
 if err=d.Decode(&e);err!=nil{return e,err}
 var extra any
 if err=d.Decode(&extra);err!=io.EOF{return e,errors.New("trailing data")}
 if e.Version!="v1" || e.Scope!="synthetic-device-model" || len(e.Operations)==0 || len(e.Operations)>128{return e,errors.New("invalid version, scope or operation count")}
 var total uint64
 for i,o:=range e.Operations {
  switch o.Kind {
  case "clock-step":
   if o.Nanoseconds==nil || *o.Nanoseconds==0 || *o.Nanoseconds>1_000_000_000 || o.Port!=nil || o.Width!=nil || o.Value!=nil{return e,fmt.Errorf("operation %d: clock fields",i)}
   total+=*o.Nanoseconds
   if total>10_000_000_000{return e,errors.New("clock budget")}
  case "pio-read","pio-write":
   if o.Port==nil || o.Width==nil || o.Nanoseconds!=nil{return e,fmt.Errorf("operation %d: io fields",i)}
   w,p:=*o.Width,*o.Port
   if (w!=1 && w!=2 && w!=4) || p>65535 || p+w>65536 || p%w!=0{return e,fmt.Errorf("operation %d: io range",i)}
   if o.Kind=="pio-read" && o.Value!=nil{return e,errors.New("read value prohibited")}
   if o.Kind=="pio-write" && (o.Value==nil || uint64(*o.Value)>((uint64(1)<<(8*w))-1)){return e,errors.New("write value out of range")}
  default:return e,fmt.Errorf("operation %d: unsupported",i)
  }
 }
 return e,nil
}
