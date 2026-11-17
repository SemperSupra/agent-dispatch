// Package card is a scoped ISO 7816 APDU contract for an approved test
// smartcard. This does not clone, provision or rewrite an official CAC.
package card

import (
 "errors"
 "fmt"
)
var (
 ErrDenied=errors.New("card: operation denied")
 ErrMalformed=errors.New("card: malformed APDU/response")
)
const (
 INSSelect byte=0xA4
 INSReadBinary byte=0xB0
 INSUpdateBinary byte=0xD6
)
type CardKind uint8
const (
 TestCard CardKind=iota+1
 GovernmentCAC
)
type Policy struct {
 Card CardKind
 Read bool
 Write bool
 TestAID []byte
}
func (p Policy) Permit(ins byte,aid []byte)error{
 if len(aid)==0 || len(p.TestAID)==0 || string(aid)!=string(p.TestAID) {return ErrDenied}
 if p.Card!=TestCard && p.Card!=GovernmentCAC{return ErrDenied}
 switch ins {
 case INSSelect,INSReadBinary:
  if !p.Read{return ErrDenied}
 case INSUpdateBinary:
  // Government-issued CAC certificates and identity applications
  // must never be written through this generic API.
  if p.Card!=TestCard || !p.Write{return ErrDenied}
 default:return ErrDenied
 }
 return nil
}
func SelectAID(aid []byte)([]byte,error){
 if len(aid)<5||len(aid)>16{return nil,ErrMalformed}
 result:=[]byte{0x00,INSSelect,0x04,0x00,byte(len(aid))}
 result=append(result,aid...)
 return result,nil
}
func ReadBinary(offset uint16,le byte)[]byte {
 return []byte{0x00,INSReadBinary,byte(offset>>8),byte(offset),le}
}
func UpdateBinary(p Policy,aid []byte,offset uint16,data []byte)([]byte,error){
 if e:=p.Permit(INSUpdateBinary,aid);e!=nil{return nil,e}
 if len(data)==0||len(data)>220{return nil,ErrMalformed}
 apdu:=[]byte{0x00,INSUpdateBinary,byte(offset>>8),byte(offset),byte(len(data))}
 apdu=append(apdu,data...)
 return apdu,nil
}
type Result struct{SW uint16;Success bool;DataLength int;Diagnostic string}
func ParseResponse(frame []byte)(Result,error){
 if len(frame)<2||len(frame)>4096{return Result{},ErrMalformed}
 sw:=uint16(frame[len(frame)-2])<<8|uint16(frame[len(frame)-1])
 r:=Result{SW:sw,Success:sw==0x9000,DataLength:len(frame)-2}
 switch {
 case sw==0x9000:r.Diagnostic="ok"
 case sw==0x6982:r.Diagnostic="security-status-not-satisfied"
 case sw==0x6A82:r.Diagnostic="file-not-found"
 case sw&0xFFF0==0x63C0:r.Diagnostic="verification-failed"
 default:r.Diagnostic=fmt.Sprintf("status-%04x",sw)
 }
 // APDU data and any credential material are NEVER logged.
 return r,nil
}
