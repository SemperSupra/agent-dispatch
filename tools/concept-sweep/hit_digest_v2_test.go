package main

import "testing"

// Golden values independently computed from the v2 domain + 3 big-endian
// uint32 byte lengths + raw UTF-8 field bytes. These are metadata hashes,
// neither signatures nor durable provider-native source identifiers.
func TestHitDigestV2GoldenVectors(t *testing.T) {
 vectors:=[]struct{url,title,snippet,want string}{
  {"https://example.org/p","A:B","C","3ce5f5f587a30c8864749cf6057c2b1bb826bc79e8b890322f577f54dba25c0c"},
  {"https://example.org/p","A","B:C","7612032137ecd111eb62a0f5d8c3243e2f8c6ed829e9353c12ace704c36701cf"},
  {"https://example.org/路径","กรุงเทพ","Berlin:東京","f5a50944a09bd7aebf0d4c7527f9aa6ad64f240e0daeea1b31db273ffc3043ec"},
  {"","","","9aab54a7f4ee1eba4e5bb23ab273c08c3b8c6a37721357c521df01d021d39f53"},
 }
 for _,v:=range vectors{
  if got:=digestHitV2(v.url,v.title,v.snippet);got!=v.want{
   t.Fatalf("v2 hit metadata preimage mismatch for %q: got %s want %s",v.url,got,v.want)
  }
 }
}
func TestHitDigestV2DistinguishesLegacyDelimiterAmbiguity(t *testing.T) {
 u:="https://example.org/p"
 firstLegacy:=digest([]byte(u+":"+"A:B"+":"+"C"))
 secondLegacy:=digest([]byte(u+":"+"A"+":"+"B:C"))
 if firstLegacy!=secondLegacy{t.Fatal("falsifier does not reproduce legacy delimiter ambiguity")}
 first:=digestHitV2(u,"A:B","C")
 second:=digestHitV2(u,"A","B:C")
 if first==second{t.Fatal("v2 metadata hash failed to distinguish two field tuples")}
}
func TestHitDigestV2FieldOrderAndUnicodeAreMaterial(t *testing.T) {
 a:=digestHitV2("https://a.example","日本語","ภาษาไทย")
 b:=digestHitV2("https://a.example","ภาษาไทย","日本語")
 if a==b{t.Fatal("v2 preimage dropped field order")}
 if a==digestHitV2("https://a.example","日本語","ภาษาไทย "){t.Fatal("v2 preimage dropped trailing Unicode field bytes")}
}
