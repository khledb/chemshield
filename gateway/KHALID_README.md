# Khalid ICS/Gateway/HMI Work

This folder contains Khalid's PPR work for ChemShield.

## Main responsibilities covered

- **C2:** Gateway is the only authorised actuator path.
- **S3:** Replayed/stale commands are rejected.
- **S2 support:** 20 mL max dose and 15 s lockout are enforced in software.
- **C3 support:** 50 mmol recovery-event limit is checked.
- **S4 support:** Gateway has a Model A decision point.
- **INT-S1 support:** Safe-recovery timing is logged.
- **HMI build:** Operator screen for command decisions, counters, and audit log.

## Run all Khalid tests

From the repository root:

```bash
python gateway/khalid_ics_all_in_one.py
```

Smaller screenshot run:

```bash
python gateway/khalid_ics_all_in_one.py --per-category 5
```

Generated files will be written to:

```text
evidence/generated/
```

## Run HMI

```bash
uvicorn hmi.app:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

## Lab firewall note

The firewall script is a template. Confirm the real Raspberry Pi interface names before running it.
