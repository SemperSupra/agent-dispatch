package main
import("archive/zip";"bytes";"encoding/binary";"fmt";"sort";"strings";"testing")
func fixture()[]byte{
 var b strings.Builder;b.WriteString("[I 0.000000] OPENED\n")
 for _,p:=range pairs{fmt.Fprintf(&b,"[R +0.1] %s",p.cmd);for _,a:=range p.args{fmt.Fprintf(&b," %#x",a)};b.WriteString("\n[S +0.2] OK");for _,v:=range p.reply{fmt.Fprintf(&b," %#x",v)};b.WriteByte('\n')}
 b.WriteString("[I +0.3] CLOSED\n");return []byte(b.String())
}
func TestRawQTest(t *testing.T){
 g:=fixture();r,e:=qtest(g);if e!=nil||len(r)!=5{t.Fatalf("%v %v",r,e)}
 for i,w:=range oracle{if r[i]!=w{t.Fatal("oracle")}}
 for _,c:=range []struct{name string; data []byte}{
 {"wrong-write",[]byte(strings.Replace(string(g),"outl 0x1008 0x1","outl 0x1008 0x2",1))},
 {"wrong-read",[]byte(strings.Replace(string(g),"OK 0x10011af4","OK 0x10011af5",1))},
 {"missing-close",[]byte(strings.TrimSuffix(string(g),"[I +0.3] CLOSED\n"))},
 {"extra",append(append([]byte{},g...),[]byte("unbound\n")...)},
 {"wrong-reply",[]byte(strings.Replace(string(g),"[S +0.2] OK","[S +0.2] FAIL",1))},
 {"oversize",make([]byte,65537)},
 }{t.Run(c.name,func(t *testing.T){if _,e:=qtest(c.data);e==nil{t.Fatal("accepted")}})}
}
func TestRawGuest(t *testing.T){
 b:=make([]byte,44);for i,v:=range []uint32{0x35454856,0x10011af4,0x1001,3,256,0,0,0,3,256,0}{binary.LittleEndian.PutUint32(b[i*4:],v)}
 if r,e:=guest(b);e!=nil||len(r)!=5{t.Fatalf("%v %v",r,e)}
 for _,i:=range []int{0,1,2,3,4,5,6,7,8,9,10}{bad:=append([]byte{},b...);bad[i*4]^=1;if _,e:=guest(bad);e==nil{t.Fatalf("accepted word %d",i)}}
 if _,e:=guest(b[:43]);e==nil{t.Fatal("truncated")}
}
func archive(t *testing.T,m map[string][]byte)[]byte{
 var b bytes.Buffer;z:=zip.NewWriter(&b);keys:=[]string{};for k:=range m{keys=append(keys,k)};sort.Strings(keys)
 for _,k:=range keys{w,e:=z.Create(k);if e!=nil{t.Fatal(e)};if _,e=w.Write(m[k]);e!=nil{t.Fatal(e)}};if e:=z.Close();e!=nil{t.Fatal(e)};return b.Bytes()
}
func TestArchiveControls(t *testing.T){
 v:=[]byte("synthetic");m:=map[string][]byte{"x":v,"SHA256SUMS":[]byte(digest(v)+"  ./x\n")};b:=archive(t,m)
 if _,e:=members(b,digest(b));e!=nil{t.Fatal(e)}
 if _,e:=members(b,strings.Repeat("0",64));e==nil{t.Fatal("wrong digest")}
 for _,c:=range []struct{name string; m map[string][]byte}{
 {"unlisted",map[string][]byte{"x":v,"y":v,"SHA256SUMS":m["SHA256SUMS"]}},
 {"bad-member",map[string][]byte{"x":[]byte("changed"),"SHA256SUMS":m["SHA256SUMS"]}},
 {"duplicate-manifest",map[string][]byte{"x":v,"SHA256SUMS":append(append([]byte{},m["SHA256SUMS"]...),m["SHA256SUMS"]...)}},
 {"traversal",map[string][]byte{"../x":v,"SHA256SUMS":[]byte(digest(v)+"  ../x\n")}},
 }{t.Run(c.name,func(t *testing.T){b:=archive(t,c.m);if _,e:=members(b,digest(b));e==nil{t.Fatal("accepted")}})}
 if _,e:=project(b,digest(b));e==nil{t.Fatal("unsupported fixture accepted")}
}
