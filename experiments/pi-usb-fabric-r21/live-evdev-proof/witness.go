package liveevdevproof

import (
 "bufio"
 "errors"
 "strings"
)

// Witness describes evidence parsed from a Linux QEMU guest's text console.
// This is a TEST-ONLY transcript parser, NOT authenticated guest-origin proof.
// The verifier must never accept it alone as a release credential.
type Witness struct { Down, Up bool }
var ErrIncomplete=errors.New("guest evdev trace incomplete or contaminated")

func ParseGuestEvdevConsole(raw string)(Witness,error){
 var w Witness
 s:=bufio.NewScanner(strings.NewReader(raw))
 s.Buffer(make([]byte,4096),128*1024)
 for s.Scan(){
  line:=strings.TrimSpace(s.Text())
  // Only exact, standalone markers. Transport-only or host-side markers
  // cannot synthesize an observed down/up sequence.
  switch line {
  case "USBFABRIC_R06_REAL_KEY_A_DOWN=PASS":
   if w.Down || w.Up{return Witness{},ErrIncomplete}
   w.Down=true
  case "USBFABRIC_R06_REAL_KEY_A_UP=PASS":
   if !w.Down || w.Up{return Witness{},ErrIncomplete}
   w.Up=true
  }
 }
 if s.Err()!=nil || !w.Down || !w.Up{return Witness{},ErrIncomplete}
 return w,nil
}
