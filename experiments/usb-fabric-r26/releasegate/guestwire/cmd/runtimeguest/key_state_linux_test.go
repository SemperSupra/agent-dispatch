package main
import "testing"
func TestKeyABitInKernelSnapshot(t *testing.T){b:=make([]byte,keyBytes);b[keyA/8]=1<<uint(keyA%8);if !heldFromKeyBits(b){t.Fatal("kernel held key A ignored")}}
func TestNoKeyDownDoesNotClaimHeld(t *testing.T){if heldFromKeyBits(make([]byte,keyBytes)){t.Fatal("invented key state")}}
func TestOtherKeyCannotBeKeyA(t *testing.T){b:=make([]byte,keyBytes);b[2]=0xff;if heldFromKeyBits(b){t.Fatal("other key falsely claimed")}}
func TestTruncatedSnapshotFailClosed(t *testing.T){if heldFromKeyBits([]byte{0,0}){t.Fatal("truncated kernel snapshot accepted")}}
func TestInvalidDescriptorRejected(t *testing.T){if h,e:=kernelHeldKey(^uintptr(0));e==nil||h{t.Fatal("invalid device accepted")}}
