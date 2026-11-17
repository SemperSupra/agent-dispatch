// Package ctaphid models FIDO2 CTAPHID's 64-byte HID report framing.
// This is a protocol transport model; it does not enumerate USB or implement
// an authenticator, PIN, biometric, attestation or signing private keys.
package ctaphid

import (
 "encoding/binary"
 "errors"
)
const (
 ReportSize=64
 InitialPayload=57
 ContinuePayload=59
 MaxMessage=InitialPayload+128*ContinuePayload
 CmdInit=0x86
 CmdPing=0x81
 CmdCbor=0x90
 CmdCancel=0x91
 CmdKeepalive=0xbb
)
var(
 ErrFrame=errors.New("ctaphid: malformed or unsupported HID report")
 ErrChannel=errors.New("ctaphid: mismatched channel")
 ErrSequence=errors.New("ctaphid: wrong continuation sequence")
 ErrLength=errors.New("ctaphid: out-of-bounds message")
)
type Message struct{CID uint32; Command byte; Payload []byte}
func allowed(cmd byte)bool{
 switch cmd{case CmdInit,CmdPing,CmdCbor,CmdCancel,CmdKeepalive:return true}
 return false
}
func Encode(m Message)([][ReportSize]byte,error){
 if !allowed(m.Command){return nil,ErrFrame}
 if m.CID==0 || len(m.Payload)>MaxMessage{return nil,ErrLength}
 length:=len(m.Payload)
 count:=1
 if length>InitialPayload{count+=(length-InitialPayload+ContinuePayload-1)/ContinuePayload}
 if count>129{return nil,ErrLength}
 result:=make([][ReportSize]byte,count)
 binary.BigEndian.PutUint32(result[0][:4],m.CID)
 result[0][4]=m.Command
 binary.BigEndian.PutUint16(result[0][5:7],uint16(length))
 used:=copy(result[0][7:],m.Payload)
 for i:=1;i<count;i++{
  binary.BigEndian.PutUint32(result[i][:4],m.CID)
  result[i][4]=byte(i-1)
  used+=copy(result[i][5:],m.Payload[used:])
 }
 return result,nil
}
func Decode(reports [][ReportSize]byte)(Message,error){
 if len(reports)==0||len(reports)>129{return Message{},ErrLength}
 first:=reports[0]
 cid:=binary.BigEndian.Uint32(first[:4])
 cmd:=first[4]
 if cid==0||!allowed(cmd){return Message{},ErrFrame}
 length:=int(binary.BigEndian.Uint16(first[5:7]))
 if length>MaxMessage{return Message{},ErrLength}
 need:=1
 if length>InitialPayload{need+=(length-InitialPayload+ContinuePayload-1)/ContinuePayload}
 if len(reports)!=need{return Message{},ErrLength}
 payload:=make([]byte,length)
 copied:=copy(payload,first[7:])
 for i:=1;i<len(reports);i++{
  if binary.BigEndian.Uint32(reports[i][:4])!=cid{return Message{},ErrChannel}
  if reports[i][4]!=byte(i-1) || reports[i][4]>=128{return Message{},ErrSequence}
  copied+=copy(payload[copied:],reports[i][5:])
 }
 if copied!=length{return Message{},ErrLength}
 return Message{CID:cid,Command:cmd,Payload:payload},nil
}
