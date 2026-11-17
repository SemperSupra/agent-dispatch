# R47-A synthetic discovery-to-enrollment contract

This is an **offline-only Go stdlib validation seam** for the future universal hardware fabric. It is deliberately not a discovery listener, DHCP/ProxyDHCP service, Tailscale connector, BMC scanner or production enrollment authority.

Recognized discovery observation sources are passive DHCP evidence, an already paired node agent, an isolated approved PXE environment and an explicitly qualified BMC. Their presence **does not grant trust**: owner selection, pinned bootstrap, independently verified pairing and private G0 hardware generation are required before later commissioning/optimization/approved deployment. Stage skips, replay, fake real-world claims, absent qualification and unsigned artifact evidence fail closed. Public/tenant status is projected without raw host identity or host-device count.

Every boolean/hash in the test fixtures is **untrusted synthetic data**. Actual source signer trust, stable identity binding, anti-replay persistence, successful signed boot, authenticated approval and guest workload orchestration must be verified by the existing private controller #333, release gates #380, privacy #395/#399 and Agent Dispatch. No production network discovery/enrollment or real six-Wyse hardware action is performed.
