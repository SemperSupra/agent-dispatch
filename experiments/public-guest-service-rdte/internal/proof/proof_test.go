package proof
import "testing"
func events()[]Event {out:=make([]Event,len(Steps));for i,s:=range Steps{out[i]=Event{Stage:s,Success:true}};return out}
func TestAllStages(t *testing.T){if err:=Verify(events());err!=nil{t.Fatal(err)}}
func TestRejectMissing(t *testing.T){if err:=Verify(events()[:3]);err==nil{t.Fatal("truncated receipt accepted")}}
func TestRejectFailed(t *testing.T){for i:=range Steps{e:=events();e[i].Success=false;if err:=Verify(e);err==nil{t.Fatalf("%s accepted",e[i].Stage)}}}
func TestRejectOutOfOrder(t *testing.T){for i:=1;i<len(Steps);i++{e:=events();e[i].Stage,e[i-1].Stage=e[i-1].Stage,e[i].Stage;if err:=Verify(e);err==nil{t.Fatalf("out-of-order %d accepted",i)}}}
