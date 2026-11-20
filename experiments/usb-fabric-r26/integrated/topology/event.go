package topology
import (
 "encoding/json"
 "errors"
 "fmt"
)
// DetachWithEvent requires BOTH the QMP command's successful return and an
// asynchronous DEVICE_DELETED event naming the exact device. The caller
// retains exclusive use of its existing buffered QMP decoder/encoder and
// sets a bounded read deadline on the underlying connection.
func DetachWithEvent(enc *json.Encoder,dec *json.Decoder,id string)error{
 if enc==nil||dec==nil||id==""{return ErrUntrusted}
 if err:=enc.Encode(map[string]any{"execute":"device_del","arguments":map[string]any{"id":id}});err!=nil{return err}
 returned,deleted:=false,false
 for i:=0;i<256;i++{
  var r map[string]json.RawMessage
  if err:=dec.Decode(&r);err!=nil{return err}
  if raw,ok:=r["event"];ok{
   var ev string
   if err:=json.Unmarshal(raw,&ev);err!=nil{return err}
   if ev!="DEVICE_DELETED"{continue}
   var data struct{Device string `json:"device"`}
   if err:=json.Unmarshal(r["data"],&data);err!=nil{return err}
   if data.Device!=id{return fmt.Errorf("%w: DEVICE_DELETED wrong id %q",ErrUntrusted,data.Device)}
   if deleted{return errors.New("duplicate DEVICE_DELETED event")}
   deleted=true
  }else if raw,ok:=r["error"];ok{
   return fmt.Errorf("QMP device_del error %s",string(raw))
  }else if _,ok:=r["return"];ok{
   if returned{return errors.New("duplicate QMP device_del return")}
   returned=true
  }else{return ErrUntrusted}
  if returned&&deleted{return nil}
 }
 return errors.New("no QMP return plus DEVICE_DELETED event within bounded read")
}
