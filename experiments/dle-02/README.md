# DLE-02 — replacement continuity rep

Authority/evidence owner: SemperSupra/engineering-governance-private#169 and SemperSupra/agent-dispatch-private#97.

Hypothesis: a replacement activation can recover a bounded DLE from durable repository state alone and continue the work without transcript archaeology, human relay, or authority widening.

This is deliberately public-safe and deterministic. The originating interactive actor writes the durable capsule. A fresh standard public GitHub Actions Ubuntu runner then receives only the repository checkout and must reconstruct the required continuation facts.

PASS proves only this bounded continuity claim. It does not prove general DLE portability or actor semantic equivalence.

Kill rule: do not promote a new DLE schema from this fixture. Reuse existing project-native durable semantics unless a materially different rep proves a representation gap.

Activation trigger note: this content-only revision is the first push after the branch workflow exists; it is the execution revision for the public fresh-body rep.
