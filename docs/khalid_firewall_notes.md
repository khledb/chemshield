# Khalid Network / Firewall Notes — SIM Mode First

This file is documentation for the Raspberry Pi configuration. It does **not** change your laptop or any hardware when you run the simulation.

## Design intent

- Operator network connects only to the Raspberry Pi gateway.
- Private Pi-to-PLC/Uno control link: Pi `192.168.50.1/30`, PLC/Uno `192.168.50.2/30`.
- IP forwarding is disabled.
- PLC/Uno has no route back to the operator network.
- Only gateway-approved commands reach the actuator interface.

## Raspberry Pi template for lab integration

```bash
# Disable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=0
echo "net.ipv4.ip_forward=0" | sudo tee /etc/sysctl.d/99-chemshield.conf

# Default-deny forwarding
sudo iptables -P FORWARD DROP

# Example placeholder. Replace <PLC_PORT> with the real lab protocol port.
sudo iptables -A OUTPUT -o eth1 -d 192.168.50.2 -p tcp --dport <PLC_PORT> -m owner --uid-owner chemshield -j ACCEPT
sudo iptables -A OUTPUT -o eth1 -d 192.168.50.2 -j DROP
```

## Laptop evidence

On the laptop, use:

```bash
python -m gateway.khalid_gateway_hmi
```

This proves the intended gateway-only policy in SIM mode without touching real network settings.
