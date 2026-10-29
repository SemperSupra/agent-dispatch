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
   seen:=make(map[string]struct{})
   for d.More(){
    next,err:=d.Token();if err!=nil{return err}
    key,ok:=next.(string);if !ok{return errors.New("non-string JSON object key")}
    folded:=strings.ToLower(key)
    if _,found:=seen[folded];found{return errors.New("duplicate or case-fold alias JSON key")}
    seen[folded]=struct{}{}
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
