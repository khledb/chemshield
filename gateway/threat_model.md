# ChemShield Threat Model — Khalid / ICS

This threat model supports Khalid's PPR responsibilities: C2, S3, gateway/firewall, HMI build, and INT-S1 support.

## Protected assets

| Asset | Why it matters | Protection |
|---|---|---|
| Raspberry Pi gateway | Main security boundary | Gateway validation, audit log, firewall |
| Uno / PLC / pump actuator path | Physical dosing output | Only gateway can forward commands |
| Dose command JSON | Carries actuator intent | Schema, HMAC, timestamp, nonce, sequence |
| Operator/HMI session | Human command source | Session ID, role, certificate/checks |
| Audit log | Evidence and incident trace | Hash chain and reason codes |
| Recovery state | Keeps unsafe events controlled | SAFE_HOLD, heartbeat, timing log |

## Main threats and mitigations

| Threat | Entry point | Impact | Mitigation | Requirement supported |
|---|---|---|---|---|
| Direct pump/actuator bypass | Operator network or direct serial/network path | Dosing without safety checks | Disable routing/IP forwarding, firewall, actuator only accepts gateway-forwarded commands | C2 |
| Replayed command | Captured old valid command | Old dose accepted again | Timestamp freshness, nonce reuse check, command ID check, sequence number | S3 |
| Stale command | Delayed command arrives late | Wrong dose at wrong process state | ±2 s freshness window | S3 |
| Modified command | Attacker changes volume/reagent | Unsafe dose | HMAC-SHA256 over canonical JSON | C2/S3 |
| Unauthorized user role | Valid-looking command by wrong user | Unapproved operation | Role/session check | C2 |
| Oversize dose | Request over 20 mL or >50 mmol event | Unsafe chemical correction | Dose and recovery mmol checks | S2/C3 support |
| Burst commands | Repeated doses too close together | No mixing time | 15 s mixing lockout | S2 support |
| Model uncertainty | Context unsafe even if command format is valid | Wrong-direction dose | Model A call and block on harmful/uncertain context | S4 support |
| Gateway/controller failure | Heartbeat loss or reboot | Uncontrolled operation | SAFE_HOLD and manual ACK | INT-S1 support |
| Audit tampering | Change evidence after test | Unreliable report evidence | Hash-chained audit log | C2/S3 evidence |

## Assumptions

- PPR uses simulation for tank chemistry, but gateway, attack messages, HMI code, and command validation are real executable code.
- The Raspberry Pi firewall template must be reviewed with the real lab interface names before running.
- The demo HMAC secret must be replaced before a real deployment.

## Test mapping

| Test | Proves |
|---|---|
| `python gateway/khalid_ics_all_in_one.py` | C2 gateway-only path, S3 replay/stale rejection, fail-safe, INT-S1 support |
| HMI demo | Operator view, ACCEPT/REJECT reasons, counters, audit log |
| Firewall template + nmap output | Network part of C2 on real Pi |
