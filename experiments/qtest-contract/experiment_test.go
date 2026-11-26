package experiment
import ("strings";"testing")
func TestDecode(t *testing.T) {
 const head="{\"version\":\"v1\",\"scope\":\"synthetic-device-model\",\"operations\":"
 for _,c:=range []struct{name,body string;ok bool}{
 {"clock",head+"[{\"kind\":\"clock-step\",\"nanoseconds\":1}]}",true},
 {"read",head+"[{\"kind\":\"pio-read\",\"port\":0,\"width\":1}]}",true},
 {"write-zero",head+"[{\"kind\":\"pio-write\",\"port\":0,\"width\":1,\"value\":0}]}",true},
 {"raw-command",head+"[{\"kind\":\"raw\",\"value\":1}]}",false},
 {"empty",head+"[]}",false},
 {"null",head+"null}",false},
 {"live-claim",strings.Replace(head,"synthetic-device-model","live",1)+"[]}",false},
 {"unknown",head+"[{\"kind\":\"clock-step\",\"nanoseconds\":1,\"authority\":true}]}",false},
 {"missing",head+"[{\"kind\":\"pio-read\",\"width\":1}]}",false},
 {"overflow",head+"[{\"kind\":\"pio-write\",\"port\":0,\"width\":1,\"value\":256}]}",false},
 {"unaligned",head+"[{\"kind\":\"pio-read\",\"port\":1,\"width\":4}]}",false},
 {"range",head+"[{\"kind\":\"pio-read\",\"port\":65536,\"width\":1}]}",false},
 {"mixed",head+"[{\"kind\":\"clock-step\",\"nanoseconds\":1,\"port\":0}]}",false},
 {"trailing",head+"[{\"kind\":\"clock-step\",\"nanoseconds\":1}]}{}",false},
 {"clock-limit",head+"[{\"kind\":\"clock-step\",\"nanoseconds\":1000000001}]}",false},
 {"read-value",head+"[{\"kind\":\"pio-read\",\"port\":0,\"width\":1,\"value\":0}]}",false},
 } {t.Run(c.name,func(t *testing.T){_,err:=Decode(strings.NewReader(c.body));if (err==nil)!=c.ok{t.Fatalf("error=%v want accepted=%v",err,c.ok)}})}
}
