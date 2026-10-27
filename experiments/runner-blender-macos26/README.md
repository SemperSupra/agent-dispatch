# macOS26 Blender runner experiment

Reuse exact public synthetic two-bone rig script validated on Ubuntu 24.04 at
run 40421345574. Fetch official Blender 4.5.15 Apple Silicon DMG with Blender
SHA256, run actual three-frame Cycles CPU animated-mesh oracle, then
independently attempt one Cycles Metal frame only if Blender itself enumerates
a non-CPU Metal device. GPU absence/failure is a negative/inconclusive outcome,
not a CPU test failure; no silent CPU fallback claimed to be GPU proof.

Owner: Agent Dispatch #223 (runner census), annex #281. Only public original
synthetic objects; no private character or vendor assets. No merge or release.