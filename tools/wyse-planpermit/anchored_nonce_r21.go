package planpermit

import (
 "context"
 "errors"
 "fmt"
)

// ExternalNonceAuthority is implemented by an independently durable,
// strictly monotonic, atomic reserve-once authority OUTSIDE all local Wyse
// and TrueNAS snapshot/restore domains. A local test double is not evidence
// of such independence. Configuration, credentials, transport and authority
// lifecycle must be separately qualified.
type ExternalNonceAuthority interface {
 ReserveOutsideRollbackDomain(context.Context,string)error
}

// AnchoredNonceStore protects against a local ledger rollback only IF its
// external authority is genuinely durable and out of the rollback domain.
// It intentionally burns the global reservation FIRST; uncertain downstream
// local failure cannot make a nonce reusable. It never auto-retries.
// It does not perform privileged operations or create another scheduler.
type AnchoredNonceStore struct {
 local NonceStore
 independent ExternalNonceAuthority
}

func NewAnchoredNonceStore(local NonceStore,independent ExternalNonceAuthority)(*AnchoredNonceStore,error){
 if local==nil||independent==nil{
  return nil,errors.New("both local nonce ledger and independent rollback authority required")
 }
 return &AnchoredNonceStore{local:local,independent:independent},nil
}

func (s *AnchoredNonceStore)ConsumeOnce(ctx context.Context,key string)error{
 if s==nil||s.local==nil||s.independent==nil {
  return errors.New("missing independent rollback authority")
 }
 if err:=ctx.Err();err!=nil{return err}
 if err:=s.independent.ReserveOutsideRollbackDomain(ctx,key);err!=nil{
  return fmt.Errorf("external replay reservation denied or unavailable: %w",err)
 }
 // Fail closed. If this write/sync fails, the external marker is already
 // consumed. Operators must reconcile the uncertain transaction; no retry
 // with the same approval and no compensation/unreserve is allowed.
 if err:=s.local.ConsumeOnce(ctx,key);err!=nil{
  return fmt.Errorf("local replay reservation failed after global burn; operator reconciliation required: %w",err)
 }
 return nil
}
