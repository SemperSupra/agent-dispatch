# Ubuntu 24.04 Blender CPU renderer qualification

Owner: Agent Dispatch private #223, standard free-tier GitHub Actions runner census.
Public-safe synthetic geometry only: exactly two original rig bones, one skinned
lever, three 256x144 Cycles-CPU renders at frames 1,9,17.

Run entrypoint: `.github/workflows/blender-cpu-smoke-ubuntu24.yml`
Experiment branch: `exp/runner-blender-ubuntu24-20261027`; no PR or main merge required.
Blender pin: official `blender-4.5.15-linux-x64.tar.xz`; SHA256 verified
against Blender Foundation's published `blender-4.5.15.sha256` at job time.

Oracle: actual Blender background process, evaluated skinned vertex displacement
>0.20m, three distinct PNG hashes, exact version, original .blend, machine
receipt. No visual realism, contact physics, GPU, source character, or Blender
portability across other runner labels is established.

No real-person assets, external credentials, vendor meshes or private project
source are copied to this workflow. Artifact retention 7 days; repo branch
remains an unmerged experiment. Follow-up reduction belongs to private #223.
