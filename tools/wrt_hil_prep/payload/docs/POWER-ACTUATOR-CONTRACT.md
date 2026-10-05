# WRT Independent Power Actuator Contract

Status: R0/R2 design. Fake adapter only; no physical actuator is authorized yet.

## Purpose

R2 requires a cold power-cycle path that does not depend on the DUT network, DUT userspace, or the candidate experiment generation. Losing the DUT data plane must not remove the ability to recover it.

## Required semantics

A physical implementation must expose only bounded operations:
- read power state when supported;
- set power off;
- set power on;
- cold-cycle (off -> bounded dwell -> on).

Every actuation emits evidence to a sink independent of the DUT data plane.

## Fail closed

Deny actuation if:
- the actuator is reachable only through the DUT;
- the evidence sink is not independent;
- target device identity is ambiguous;
- an existing device lease belongs to another actor;
- R2 has not been explicitly admitted from reviewed R1 evidence.

No implementation may manipulate boot environment, MTD, or protected surfaces.

## Qualification before hardware

scripts/rdte/fake_power_adapter.py is the zero-hardware oracle for orchestration. A real smart-plug/PDU/relay adapter must implement equivalent observable semantics and then earn separate physical qualification.
