// Package hidreport parses a bounded subset of USB HID short-item
// report descriptors. It makes no claims about physical key count, printed
// keycaps, language layout, user identity or real device interoperability.
package hidreport

import (
 "errors"
 "fmt"
)
var ErrMalformed=errors.New("hidreport: malformed, oversized or unsupported descriptor")
type Field struct{
 ReportID uint32 `json:"report_id"`
 MainType string `json:"type"`
 UsagePage uint32 `json:"usage_page"`
 UsageMin uint32 `json:"usage_min"`
 UsageMax uint32 `json:"usage_max"`
 ReportCount uint32 `json:"report_count"`
 ReportSize uint32 `json:"report_size"`
 Variable bool `json:"variable"`
 Constant bool `json:"constant"`
}
type Summary struct{
 Fields []Field `json:"fields"`
 ModifierBits uint32 `json:"modifier_bits"`
 BootArraySlots uint32 `json:"boot_array_slots"`
 NKROBits uint32 `json:"nkro_bits"`
 LEDBits uint32 `json:"led_bits"`
 ReportIDs []uint32 `json:"report_ids"`
 PhysicalKeyCountKnown bool `json:"physical_key_count_known"`
 KeyboardLocaleKnown bool `json:"keyboard_locale_known"`
}
type global struct{page,size,count,id uint32}
type local struct{low,high uint32;haveMin,haveMax bool}
func (l *local)reset(){*l=local{}}
func (l local) rangeOf()(uint32,uint32){
 if l.haveMin && l.haveMax{return l.low,l.high}
 return 0,0
}
func Decode(b []byte)(Summary,error){
 out:=Summary{Fields:make([]Field,0,24)}
 if len(b)==0||len(b)>2048{return out,ErrMalformed}
 var g global
 stack:=make([]global,0,4)
 var l local
 depth:=0
 ids:=map[uint32]bool{}
 for pos:=0;pos<len(b);{
  prefix:=b[pos];pos++
  if prefix==0xfe{return out,fmt.Errorf("%w: long items require explicit policy",ErrMalformed)}
  length:=int(prefix&3);if length==3{length=4}
  if len(b)-pos<length{return out,ErrMalformed}
  var v uint32
  for n:=0;n<length;n++{v|=uint32(b[pos+n])<<uint(8*n)}
  pos+=length
  kind:=(prefix>>2)&3
  tag:=prefix>>4
  switch kind{
  case 0: // Main
   switch tag{
   case 8,9,11: // Input/Output/Feature
    if depth==0 || g.size==0 || g.count==0 || g.size>32 || g.count>4096 || uint64(g.size)*uint64(g.count)>8192 {return out,ErrMalformed}
    low,high:=l.rangeOf()
    if l.haveMin&&l.haveMax&&high<low{return out,ErrMalformed}
    f:=Field{ReportID:g.id,UsagePage:g.page,UsageMin:low,UsageMax:high,
     ReportCount:g.count,ReportSize:g.size,
     Constant:v&1!=0,Variable:v&2!=0}
    switch tag{case 8:f.MainType="input";case 9:f.MainType="output";case 11:f.MainType="feature"}
    out.Fields=append(out.Fields,f)
    if len(out.Fields)>128{return out,ErrMalformed}
    ids[g.id]=true
    if f.Constant{break}
    if f.UsagePage==7 && f.MainType=="input" {
     if f.Variable && f.ReportSize==1 && low==0xe0 && high==0xe7 && f.ReportCount==8 {
      out.ModifierBits+=8
     }else if !f.Variable && f.ReportSize==8 && f.ReportCount<=32{
      if f.ReportCount>out.BootArraySlots{out.BootArraySlots=f.ReportCount}
     }else if f.Variable && f.ReportSize==1 && f.ReportCount>=6{
      out.NKROBits+=f.ReportCount
     }
    }
    if f.MainType=="output" && f.UsagePage==8 && f.Variable && f.ReportSize==1 {
     out.LEDBits+=f.ReportCount
    }
   case 10:depth++;if depth>16{return out,ErrMalformed}
   case 12:depth--;if depth<0{return out,ErrMalformed}
   default:return out,fmt.Errorf("%w: unsupported main tag %d",ErrMalformed,tag)
   }
   l.reset()
  case 1: // Global
   switch tag{
   case 0:g.page=v
   case 7:g.size=v
   case 8:if v==0||v>255{return out,ErrMalformed};g.id=v
   case 9:g.count=v
   case 10:if len(stack)>=8{return out,ErrMalformed};stack=append(stack,g)
   case 11:if len(stack)==0{return out,ErrMalformed};g=stack[len(stack)-1];stack=stack[:len(stack)-1]
   default: // logical ranges and units affect interpretation but not this
    // bounded summary; parse but never infer mappings from them.
   }
  case 2: // Local
   switch tag{
   case 1:l.low=v;l.haveMin=true
   case 2:l.high=v;l.haveMax=true
   }
  case 3:return out,ErrMalformed
  }
 }
 if depth!=0||len(stack)!=0||len(out.Fields)==0{return out,ErrMalformed}
 for id:=uint32(0);id<256;id++{
  if ids[id]{out.ReportIDs=append(out.ReportIDs,id)}
 }
 // No HID report descriptor proves physical switches or OS layout.
 out.PhysicalKeyCountKnown=false
 out.KeyboardLocaleKnown=false
 return out,nil
}
