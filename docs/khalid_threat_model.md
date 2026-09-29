# ChemShield Cybersecurity Threat Model

## Assets
- pH neutralization tank and dosing pump.
- PLC actuator command mailbox.
- Raspberry Pi ChemShield gateway.
- Operator HMI/API.
- Audit log and recovery event records.

## Trust boundaries
1. Operator/HMI network to ChemShield gateway.
2. ChemShield gateway to private Pi-to-PLC network.
3. Gateway application to PLC actuator command interface.

## Main threats tested
- Replayed command: attacker captures a valid command and sends it again.
- Stale command: valid command arrives too late for the current process state.
- Reused nonce: one-time value is repeated.
- Out-of-order sequence: old or duplicate sequence is sent.
- Invalid HMAC: command is modified after signing.
- Wrong role/session: user or session is not authorized.
- Malformed command: command is missing required fields or has bad types.
- Replayed after reboot: old command is retried after gateway restart.
- Gateway bypass attempt: actor tries to write directly to the PLC without the ChemShield gateway.

## Controls
- HMAC-SHA256 authentication tag.
- UTC timestamp freshness window of +/-2 seconds.
- 128-bit nonce checked as one-time use.
- Strictly increasing sequence number.
- Session and role validation.
- Dose, flow, and mixing-time limits.
- Default SAFE_HOLD after reboot or heartbeat failure.
- Audit log for every accept/reject decision.
