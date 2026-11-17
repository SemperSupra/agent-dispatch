package keyboard
import ("errors";"testing")
func TestPhysicalModelsDoNotDetermineRollover(t *testing.T){
 for _,p:=range Models(){
  if e:=p.Validate();e!=nil{t.Fatalf("%s: %v",p.Model,e)}
  // Number of physical keys and 6KRO capacity are independent.
  if p.DeclaredPhysicalKeys<=6{t.Fatal("invalid physical key model")}
  _,e:=BootReport(0,[]byte{4,5,6,7,8,9,10})
  if !errors.Is(e,ErrRollover){t.Fatalf("%s failed rollover %v",p.Model,e)}
 }
}
func TestUSBPhysicalUsagesNeverLocalized(t *testing.T){
 if HIDY!=0x1c||HIDZ!=0x1d||HIDNonUSBackslash!=0x64 ||
  HIDInternational1!=0x87||HIDInternational3!=0x89 ||
  HIDLanguage1!=0x90||HIDLanguage2!=0x91{t.Fatal("HID usage page changed")}
 r,e:=BootReport(0x02,[]byte{HIDY,HIDZ,HIDNonUSBackslash})
 if e!=nil||r.Modifiers!=0x02||r.Keys[0]!=HIDY{t.Fatal(e)}
}
func TestNKRODoesNotImplyPhysicalKeycount(t *testing.T){
 b,e:=NKROBitmap([]byte{4,5,6,7,8,9,10,HIDNonUSBackslash,HIDInternational3})
 if e!=nil{t.Fatal(e)}
 if len(b)!=29 || b[4/8]&(1<<(4%8))==0 || b[HIDInternational3/8]&(1<<(HIDInternational3%8))==0{
  t.Fatal("NKRO usage bit absent")
 }
 if _,e=NKROBitmap([]byte{4,4});!errors.Is(e,ErrDuplicate){t.Fatal("repeated key accepted")}
 if _,e=BootReport(0,[]byte{4,4});!errors.Is(e,ErrDuplicate){t.Fatal("repeated boot usage accepted")}
}
func TestUnknownAndVendorUsagesFailClosed(t *testing.T){
 if _,e:=BootReport(0,[]byte{0x01});!errors.Is(e,ErrUnsupported){t.Fatal("USB rollover code as key")}
 if _,e:=NKROBitmap([]byte{0xff});!errors.Is(e,ErrUnsupported){t.Fatal("vendor usage accepted")}
 if e:=(Profile{"bad","ANSI",104,true,false,true,false}).Validate();!errors.Is(e,ErrUnsupported){t.Fatal("ISO flag on ANSI")}
}
