#!/bin/bash
set -euo pipefail
MODE="${1:-evasion}"   # no_evasion | evasion
SERVER_IP="${2:?need server ip}"
EXTRA_DELAY="${3:-0}"

sudo pkill -f cloak_daemon || true
sudo pkill -f splice_proxy || true
sudo fuser -k 1080/tcp 2>/dev/null || true
# Clean up potential existing rules to avoid duplicates
sudo iptables -D INPUT -p tcp -s "$SERVER_IP" -j NFQUEUE --queue-num 1 2>/dev/null || true
sudo iptables -D OUTPUT -p tcp -d "$SERVER_IP" -j NFQUEUE --queue-num 1 2>/dev/null || true
sudo iptables -D INPUT -p tcp --dport 1080 -j NFQUEUE --queue-num 1 2>/dev/null || true
sudo iptables -D OUTPUT -p tcp --sport 1080 -j NFQUEUE --queue-num 1 2>/dev/null || true

if [[ "$MODE" == "evasion" ]]; then
  sudo iptables -A INPUT  -p tcp -s "$SERVER_IP" -j NFQUEUE --queue-num 1
  sudo iptables -A OUTPUT -p tcp -d "$SERVER_IP" -j NFQUEUE --queue-num 1
  sudo iptables -A INPUT  -p tcp --dport 1080 -j NFQUEUE --queue-num 1
  sudo iptables -A OUTPUT -p tcp --sport 1080 -j NFQUEUE --queue-num 1
  sudo nohup python3 -u /home/sonya/cloak_daemon.py > /tmp/cloak.log 2>&1 < /dev/null &
fi

sudo nohup python3 -u /home/sonya/splice_proxy.py --extra-delay "$EXTRA_DELAY" > /tmp/splice.log 2>&1 < /dev/null &
echo "Started mode=$MODE with extra_delay=$EXTRA_DELAY"
