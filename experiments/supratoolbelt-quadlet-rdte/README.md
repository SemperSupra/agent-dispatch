# M1 disposable-node Quadlet manifest reference

These are **rootless service generator templates** for use inside a disposable VM/pod **only**. They are NOT instructions to install Podman, Quadlet or systemd units on any persistent workstation, build machine, TrueNAS host or long-lived shared VPS. The `%t` expansion is the **user runtime directory in the ephemeral node**; no permanent host HOME paths are needed for gateway config or WebUI encryption-key references.

The image references are immutable digest pins, with loopback-only ports, dropped capabilities, no-new-privileges and systemd CPU/memory limits. CI runs the actual `podman-system-generator --user --dryrun`, verifying generated syntax on both free public AMD64 and ARM64 GitHub-hosted runners. This proves **generator compatibility**, not live service deployment, healthy MCP traffic or full VM replacement.

Open WebUI's `supra-webui-data.volume` is for **non-durable synthetic RDTE only**. It does not survive destruction of its host VM. Production or durability-dependent RDTE must instead use an independent off-node database, object storage, key authority and audit sink, with state recovery tested across whole-node destruction.

**Owner tooling correction:** use disposable containers, VMs and free public GHA for installation/build/test by preference. Narrow user `~/.local` or project `.local` tool installations are expressly permitted but lower priority. This exception does not allow permanent service runtimes in those directories.

Authoritative acceptance: private MCP Projection M1 DLE #170, draft integration PR #171 and its Gate Z contract. No merge, production rollout, secret injection, external ingress or paid runner authorization is implied.
