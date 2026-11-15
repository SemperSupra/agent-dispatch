package planpermit

import (
 "context"
 "crypto/tls"
 "errors"
 "fmt"
 "net/http"
 "net/url"
 "strings"
 "time"
)

// RemoteHTTPSNonceWitness implements ExternalNonceAuthority over one
// separately governed, strongly authenticated HTTPS 1.3 reservation endpoint.
// It sends only a salted-domain SHA256 nonce KEY (not the permit/signature).
// It never retries uncertain requests and NEVER treats 200/202 as a commit.
// An authenticated HTTPS response does not establish server durability:
// operators must separately verify persistent monotonic storage outside the
// TrueNAS/Wyse snapshot domains, audit, backup and power-failure semantics.
type RemoteHTTPSNonceWitness struct {
 endpoint string
 httpClient *http.Client
}
func NewRemoteHTTPSNonceWitness(endpoint string,trust *tls.Config)(*RemoteHTTPSNonceWitness,error){
 parsed,err:=url.Parse(endpoint)
 if err!=nil||parsed==nil||parsed.Scheme!="https"||parsed.Host==""||
   parsed.User!=nil||parsed.RawQuery!=""||parsed.Fragment!=""||
   (parsed.Path!=""&&parsed.Path!="/")||strings.HasSuffix(parsed.Host,"."){
  return nil,errors.New("exact HTTPS authority URL without credentials/path/query required")
 }
 if trust==nil||trust.InsecureSkipVerify||trust.RootCAs==nil||
    trust.MinVersion<tls.VersionTLS13||len(trust.Certificates)!=1{
  return nil,errors.New("trusted TLS 1.3 client certificate, roots and hostname validation required")
 }
 copyTLS:=trust.Clone()
 transport:=&http.Transport{
  Proxy:nil,TLSClientConfig:copyTLS,DisableKeepAlives:true,
  TLSHandshakeTimeout:2*time.Second,ResponseHeaderTimeout:2*time.Second,
  MaxResponseHeaderBytes:2048,ForceAttemptHTTP2:false,
 }
 client:=&http.Client{
  Transport:transport,
  CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse},
 }
 return &RemoteHTTPSNonceWitness{
  endpoint:strings.TrimSuffix(parsed.String(),"/"),
  httpClient:client,
 },nil
}
func(w *RemoteHTTPSNonceWitness)ReserveOutsideRollbackDomain(ctx context.Context,key string)error{
 if w==nil||w.httpClient==nil||!validHex256(key){return errors.New("invalid external nonce witness or key")}
 if err:=ctx.Err();err!=nil{return err}
 // All failure, timeout, redirect and unknown-commit outcomes DENY.
 // Never retry a nonce after a network failure; escrow unresolved outcomes.
 bounded,cancel:=context.WithTimeout(ctx,4*time.Second)
 defer cancel()
 req,err:=http.NewRequestWithContext(bounded,http.MethodPost,
   w.endpoint+"/v1/nonce-reservations/"+key,http.NoBody)
 if err!=nil{return fmt.Errorf("external nonce request refused: %w",err)}
 req.Header.Set("Accept","application/json")
 req.Header.Set("Cache-Control","no-store")
 res,err:=w.httpClient.Do(req)
 if err!=nil{return fmt.Errorf("external nonce reservation uncertain; deny: %w",err)}
 defer res.Body.Close()
 if res.StatusCode!=http.StatusCreated{
  return fmt.Errorf("external nonce reservation refused/uncertain (HTTP %d)",res.StatusCode)
 }
 return nil
}
