# WRT3200ACM DUT Generation Contract

Status: pre-HIL design. No physical write authority.

## Generation intents

### DUT-A Gold
- Known-good recovery baseline.
- No experimental EasyMesh enablement.
- Exact physical image/slot identity is **observed and hashed during R1/R2**, not manufactured by emulation.

### DUT-B Gold
- Same baseline class as DUT-A, with independent observed image/slot identity.
- No assumption that slot numbering or current boot selection matches DUT-A until observed.

### DUT-A RDTE
- External/package/config generation only after R2.
- EasyMesh role: Multi-AP Controller + Agent.
- First HIL batch uses wired backhaul and one bounded W8964 radio/BSS.
- Returns to Gold between experiments.

### DUT-B RDTE
- External/package/config generation only after R2.
- EasyMesh role: Multi-AP Agent.
- First HIL batch uses wired backhaul and one bounded W8964 radio/BSS.
- Returns to Gold between experiments.

## Pre-HIL emulator binding

The x86/64 QEMU digital twin may use synthetic:
- IP addresses;
- interface names;
- hwsim PHYs;
- virtual NIC topology.

Those values are **test fixtures only** and may never be promoted directly to physical configuration.

The emulator may prove:
- UCI syntax;
- prplMesh management-mode semantics;
- service start/stop behavior;
- controller/agent process selection;
- wired peer reachability;
- generation identity and boot markers.

It cannot prove:
- WRT3200ACM NAND slot identity;
- U-Boot/environment semantics;
- mwlwifi/W8964 behavior;
- physical interface/radio naming;
- recovery/power behavior;
- protected-partition safety.

## Physical binder inputs

Before a physical RDTE generation is rendered, the binder must consume reviewed R1/R2 evidence for:
- board/model identity;
- current boot_part and slot mapping;
- Gold/Rescue image hashes;
- protected/unknown MTD deny list;
- management path;
- LAN/bridge interface map;
- radio/BSS interface map;
- serial and independent power recovery state;
- evidence-sink reachability.

Missing or ambiguous inputs fail closed.

## Promotion rule

A pre-HIL config can be labeled `EMULATOR_QUALIFIED`.
A physical generation can be labeled `R3_READY` only after reviewed R1 + fully qualified R2 evidence and a binder render that contains no unresolved physical placeholders.
