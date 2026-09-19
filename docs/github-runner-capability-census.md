# GitHub-hosted runner capability census

This repository contains the public-safe execution side of a bounded runner
capability experiment.

The census records facts about the ephemeral GitHub-hosted runner itself:
OS/architecture, observed CPU/RAM/storage, selected command/device/framework
presence, and GitHub image provenance. It does not dump environment variables,
addresses, hostnames, credentials, repository secrets, or private target data.

The first experiment mode is passive only. Presence is deliberately not promoted
to proof of callability or workload suitability. Active probes belong in
separate fresh jobs and are added only when passive evidence justifies them.

Receipt schema identifier: github-runner-capability/v1.

Evidence ladder:

advertised -> observed -> installed -> callable -> exercised -> oracleSatisfied

A negative observation is data and must not be converted into a harness failure.
Observed capacity describes one job and is not a GitHub service guarantee.
