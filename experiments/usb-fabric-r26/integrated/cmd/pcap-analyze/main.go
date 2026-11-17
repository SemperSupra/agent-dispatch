package main

import (
 "encoding/json"
 "fmt"
 "os"

 "example.org/usb-fabric-r26-integrated/capture"
)

func main() {
 if len(os.Args)!=2 {fmt.Fprintln(os.Stderr,"usage: r26-pcap-analyze <synthetic-usb.pcap>");os.Exit(2)}
 b,e:=os.ReadFile(os.Args[1])
 if e!=nil{fmt.Fprintln(os.Stderr,"cannot read PCAP:",e);os.Exit(3)}
 summary,e:=capture.Decode(b)
 if e!=nil{fmt.Fprintln(os.Stderr,"USB PCAP invalid:",e);os.Exit(4)}
 encoder:=json.NewEncoder(os.Stdout)
 encoder.SetEscapeHTML(true)
 if e=encoder.Encode(summary);e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(5)}
}
