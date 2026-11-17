// Package keyboard models USB keyboard usages separately from physical
// keyboard geometry and OS text layout. It is NOT a keyboard descriptor
// probe, a guest text-IME implementation, or a password-input facility.
package keyboard

import (
 "errors"
 "fmt"
)
var (
 ErrUnsupported=errors.New("keyboard: unsupported usage or report")
 ErrRollover=errors.New("keyboard: boot keyboard exceeds six ordinary keys")
 ErrDuplicate=errors.New("keyboard: duplicate HID usage")
)
type Profile struct {
 Model string
 Geometry string
 DeclaredPhysicalKeys int
 BootProtocol bool
 NKRO bool
 NonUSISO bool
 JISExtra bool
}
func (p Profile) Validate()error{
 if p.Model=="" || p.DeclaredPhysicalKeys<1 || p.DeclaredPhysicalKeys>512 || (!p.BootProtocol && !p.NKRO) {return ErrUnsupported}
 // Geometry and count are declarative. A keyboard descriptor does not
 // reveal an exact physical key count, and 6KRO != 101/104 keys.
 if p.NonUSISO && p.Geometry!="ISO" {return ErrUnsupported}
 if p.JISExtra && p.Geometry!="JIS" {return ErrUnsupported}
 return nil
}
const (
 HIDY=0x1c
 HIDZ=0x1d
 HIDNonUSBackslash=0x64
 HIDInternational1=0x87
 HIDInternational3=0x89
 HIDLanguage1=0x90
 HIDLanguage2=0x91
)
type Report struct{
 Modifiers byte
 Keys [6]byte
}
func BootReport(mods byte,usages []byte)(Report,error){
 var r Report;r.Modifiers=mods
 if len(usages)>6{return Report{},ErrRollover}
 seen:=map[byte]bool{}
 for i,u:=range usages{
  if u<4 || u>0xA4{return Report{},fmt.Errorf("%w: 0x%02x",ErrUnsupported,u)}
  if seen[u]{return Report{},ErrDuplicate}
  seen[u]=true;r.Keys[i]=u
 }
 return r,nil
}
func NKROBitmap(usages []byte)([]byte,error){
 // Usages 0..0xe7 form 232-bit selection field. Modifier byte is
 // separately expressed; this is NOT a universal HID report descriptor.
 out:=make([]byte,29)
 seen:=map[byte]bool{}
 for _,u:=range usages {
  if u<4 || u>0xA4{return nil,ErrUnsupported}
  if seen[u]{return nil,ErrDuplicate}
  seen[u]=true
  out[u/8] |= 1<<(u%8)
 }
 return out,nil
}
func Models()[]Profile {
 return []Profile{
  {"ANSI-101","ANSI",101,true,false,false,false},
  {"ISO-102","ISO",102,true,false,true,false},
  {"ANSI-104","ANSI",104,true,true,false,false},
  {"ISO-105","ISO",105,true,true,true,false},
  {"JIS-106","JIS",106,true,false,false,true},
  {"JIS-109","JIS",109,true,true,false,true},
  {"Compact-87","ANSI",87,true,true,false,false},
  {"Brazil-ABNT2-107","ISO",107,true,true,true,false},
 }
}
