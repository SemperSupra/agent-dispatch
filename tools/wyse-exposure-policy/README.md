# Wyse exposure policy (R45-A) — synthetic, non-actuating

One Go stdlib policy decision supports human UI, operator CLI and agent API. This module **does not bind a port**, open a firewall, configure tailscaled/Headscale, verify a real Headscale policy, authenticate a caller or publish a service. The sample addresses are **fictional**.

Each service explicitly chooses `disabled`, `local`, `lan`, `overlay`, or `both` with literal per-plane addresses. No wildcard binding or overlay-to-LAN fallback. Ordinary remote API surfaces **only guest-assigned information**, never host GPU, USB, PCI, IOMMU, pass-through eligibility, even capability counts or discovery errors. Host `inventory_admin` is owner-only through a local protected Unix socket. No remotely reachable inventory path is generated.

Overlay provider is `headscale` or `tailscale`, both via the tailscaled node. Provider state, configured prefix and policy digest in this plan are **untrusted declared facts**; integration must observe real interface addresses and verified, active, reviewed Headscale/Tailscale grants, network listener binding and host firewall rules. **Headscale's default with no policy loaded is allow-all**, so do not promote an overlay deployment without observed deny-by-default policy and negative peer tests. Tailscale Serve and identity headers are NOT admitted as automatic authentication; if introduced later, verify proxy compatibility, enforce loopback backend and independent mTLS/RBAC. No Tailscale Funnel/public WAN.

Runtime must separately enforce app identity, roles, event/response projections, guest isolation, auth token audience, CORS/CSRF/WebSocket/event/metrics/OpenAPI redaction, firewall and rollback. Guests already assigned devices can observe those devices inside their VM; membership of a tailnet or LAN may reveal reachable nodes independently of this API.

This experiment is intended to be integrated into the existing private IaC #333 TrueNAS Foundry controller and #327 recoverd, never a competing controller. No host/firmware/media/overlay mutation.

Source references: https://headscale.net/stable/ref/acls/ and https://tailscale.com/docs/features/tailscale-serve and https://tailscale.com/docs/features/access-control/grants .
