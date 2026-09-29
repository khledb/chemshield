#!/usr/bin/env bash
# ChemShield Raspberry Pi firewall template — Khalid / ICS
# Purpose: support C2 by making the Raspberry Pi the only authorised path to the actuator side.
# Review interface names before running in the lab.

set -euo pipefail

# CHANGE THESE AFTER CHECKING THE REAL PI
OPERATOR_IF="wlan0"      # operator/HMI side
CONTROL_IF="eth0"       # Uno/PLC/control side, if used
HMI_PORT="443"           # use 8000 for local FastAPI testing, 443 for final HTTPS
SSH_PORT="22"

# 1) Disable IP forwarding so the Pi is not a transparent router.
sudo sysctl -w net.ipv4.ip_forward=0
sudo sysctl -w net.ipv6.conf.all.forwarding=0

# 2) Flush old rules.
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X

# 3) Default deny.
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# 4) Allow loopback and established traffic.
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 5) Allow HMI/HTTPS and SSH only from operator side.
sudo iptables -A INPUT -i "$OPERATOR_IF" -p tcp --dport "$HMI_PORT" -j ACCEPT
sudo iptables -A INPUT -i "$OPERATOR_IF" -p tcp --dport "$SSH_PORT" -j ACCEPT

# 6) Block forwarding between operator side and control side.
sudo iptables -A FORWARD -i "$OPERATOR_IF" -o "$CONTROL_IF" -j DROP
sudo iptables -A FORWARD -i "$CONTROL_IF" -o "$OPERATOR_IF" -j DROP

# 7) Show final rules for evidence screenshot.
echo "=== IP forwarding ==="
sysctl net.ipv4.ip_forward
sysctl net.ipv6.conf.all.forwarding

echo "=== iptables rules ==="
sudo iptables -S

# Evidence command examples:
#   nmap -Pn <pi-ip>
#   curl -k https://<pi-ip>/
#   attempt direct actuator route: should fail
