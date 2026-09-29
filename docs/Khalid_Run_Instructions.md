# ChemShield — Khalid Gateway / Firewall / Threat Model / HMI Work

SIM-mode implementation for Khalid's ChemShield work.

## Run all tests and generate evidence

```bash
python -m pip install -r requirements.txt
python -m gateway.khalid_gateway_hmi
```

Output files are generated under:

```text
evidence/generated/
```

## Run the HMI

```bash
uvicorn hmi.app:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

## What this covers

- C2: gateway is the only authorized actuator path.
- S3: replayed/stale commands are rejected.
- Dose safety: 20 mL max, 15 s mixing wait rule in the gateway logic, and recovery limit reference.
- HMI: operator dashboard with ACCEPT/REJECT, reason code, Model A result, HALT/ACK, attack counter, and audit log.
- Threat model and firewall/network notes in `docs/`.

This code does not send hardware commands. The PLC/Uno is simulated.
