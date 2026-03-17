#!/bin/bash
# Helper script to start the pre-flight relay and daemon.
# Should be run with sudo for iptables and daemon.

set -e

# 1. Clean up old rules/processes
echo "[*] Cleaning up old states..."
sudo iptables -D INPUT  -p tcp --sport 443 -j NFQUEUE --queue-num 1 2>/dev/null || true
sudo iptables -D OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1 2>/dev/null || true
sudo pkill -f cloak_daemon_preflight || true
sudo pkill -f splice_proxy_preflight || true
sleep 1

# 2. Set up NFQUEUE rules
echo "[*] Setting up NFQUEUE rules for port 443..."
sudo iptables -A INPUT  -p tcp --sport 443 -j NFQUEUE --queue-num 1
sudo iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1

# 3. Start Cloak Daemon
echo "[*] Starting Pre-flight Cloak Daemon..."
sudo nohup python3 -u cloak_daemon_preflight.py > cloak.log 2>&1 &
sleep 2

# 4. Start Proxy
echo "[*] Starting Pre-flight Proxy on port 1080..."
nohup python3 -u splice_proxy_preflight.py --port 1080 > proxy.log 2>&1 &

echo "[+] Done. Logs: cloak.log, proxy.log"
