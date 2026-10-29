package main

// rejectAmbiguousPairJSON is a bounded, source-neutral parser-front gate.
// Borrowed algorithmically from the independently qualified public signed
// membrane JSON scanner. It prevents Go's case-insensitive struct decoder
// from silently accepting duplicate/case-variant keys at a trust boundary.
// It does not authenticate a manifest or authorize source release.
import (
 "bytes"
 "encoding/json"
 "errors"
 "io"
 "strings"
)

func rejectAmbiguousPairJSON(raw []byte) error {
 d:=json.NewDecoder(bytes.NewReader(raw))
 var scan func(int) error
 scan=func(depth int) error {
  if depth>32 {return errors.New("pair JSON nesting exceeds 32")}
  token,err:=d.Token();if err!=nil{return err}
  sep,ok:=token.(json.Delim);if !ok{return nil}
  switch sep {
  case '{':
   // Go's encoding/json struct-field matching uses EqualFold, which is
   // broader than strings.ToLower equality (e.g. ASCII s and long-s U+017F).
   // The schema is tiny; a bounded linear scan avoids differential aliases.
   seen:=make([]string,0,12)
   for d.More(){
    next,err:=d.Token();if err!=nil{return err}
    key,ok:=next.(string);if !ok{return errors.New("non-string JSON object key")}
    if len(seen)>=64{return errors.New("too many JSON object keys")}
    for _,prior:=range seen{
     if strings.EqualFold(key,prior){return errors.New("duplicate or case-fold alias JSON key")}
    }
    seen=append(seen,key)
    if err=scan(depth+1);err!=nil{return err}
   }
   end,err:=d.Token();if err!=nil{return err}
   if end!=json.Delim('}') {return errors.New("malformed JSON object")}
   return nil
  case '[':
   for d.More(){if err:=scan(depth+1);err!=nil{return err}}
   end,err:=d.Token();if err!=nil{return err}
   if end!=json.Delim(']'){return errors.New("malformed JSON array")}
   return nil
  default:return errors.New("unexpected JSON delimiter")
  }
 }
 if err:=scan(0);err!=nil{return err}
 if _,err:=d.Token();err!=io.EOF{return errors.New("trailing pair JSON value")}
 return nil
}
