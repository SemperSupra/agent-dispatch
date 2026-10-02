# FRITZ E2 startup-semantics recovery

E2-R1 showed that no-argument `/bin/supervisor` exits 1 before becoming live.
This D2 slice recovers the exact 8.25 startup semantics without publishing raw
AVM shell script content.

It emits only:
- startup file paths containing relevant semantics;
- supervisor invocation argv shapes;
- exact absolute path arguments and option names;
- hashes/lengths instead of arbitrary literal arguments;
- ctlmgr-bearing variable assignments;
- svctl verb/service/variable-reference shapes;
- same-file variable-flow relations proving when a ctlmgr-bearing variable is
  consumed by svctl;
- related absolute descriptor/config paths.

The output is intended to earn the exact next runtime treatment. It is not a
general shell decompiler and must not become one.

Private product authority: `SemperSupra/fritzbox-automation-private#72`.
