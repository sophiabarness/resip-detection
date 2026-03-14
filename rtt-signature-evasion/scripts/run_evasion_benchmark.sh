#!/bin/bash
set -euo pipefail

ZONE="us-west1-b"
SERVER="resip-server-east"
SERVER_ZONE="us-east1-b"
PROXY="resip-proxy"
PROXY_ZONE="us-west1-b"
PROXY_IP="$(gcloud compute instances describe "$PROXY" --zone="$PROXY_ZONE" --format='get(networkInterfaces[0].accessConfigs[0].natIP)')"
SERVER_IP="$(gcloud compute instances describe "$SERVER" --zone="$SERVER_ZONE" --format='get(networkInterfaces[0].accessConfigs[0].natIP)')"

COUNT=1000
DELAY=0.5
WORKERS=10
TS="$(date +%Y%m%d_%H%M%S)"
DIRECT_IP="128.12.123.170"
VENV_PYTHON="./venv/bin/python3"

mkdir -p results/benchmark

# copy launcher once
gcloud compute scp ./relay_setup.sh "$PROXY":~/relay_setup.sh --zone="$PROXY_ZONE"
gcloud compute ssh "$PROXY" --zone="$PROXY_ZONE" --command="chmod +x ~/relay_setup.sh"

# Ensure cloak_daemon.py and splice_proxy.py are on the proxy
gcloud compute scp ./cloak_daemon.py "$PROXY":~/cloak_daemon.py --zone="$PROXY_ZONE"
gcloud compute scp ./splice_proxy.py "$PROXY":~/splice_proxy.py --zone="$PROXY_ZONE"

run_mode () {
  MODE="$1"
  echo "--- Running benchmark mode: $MODE ---"

  # reset proxy host mode
  if [[ "$MODE" == "proxy_no_evasion" ]]; then
    gcloud compute ssh "$PROXY" --zone="$PROXY_ZONE" --command="~/relay_setup.sh no_evasion $SERVER_IP"
  elif [[ "$MODE" == "proxy_evasion" ]]; then
    gcloud compute ssh "$PROXY" --zone="$PROXY_ZONE" --command="~/relay_setup.sh evasion $SERVER_IP"
  fi

  # start capture on server
  gcloud compute ssh "$SERVER" --zone="$SERVER_ZONE" --command="sudo pkill tcpdump || true; sudo rm -f ~/benchmark_${MODE}.pcap; sudo nohup tcpdump -i any tcp port 443 -w ~/benchmark_${MODE}.pcap > /dev/null 2>&1 &"

  sleep 5
  if [[ "$MODE" == "direct" ]]; then
    python3 client.py direct --server-ip "$SERVER_IP" --count "$COUNT" --delay 0.5 --workers 5
  else
    python3 client.py proxy --server-ip "$SERVER_IP" --count "$COUNT" --proxy-url "socks5h://${PROXY_IP}:1080" --delay 0.5 --workers 5
  fi

  sleep 5
  gcloud compute ssh "$SERVER" --zone="$SERVER_ZONE" --command="sudo pkill tcpdump || true"
  sleep 2
  gcloud compute scp "$SERVER":~/benchmark_${MODE}.pcap "results/benchmark/benchmark_${MODE}.pcap" --zone="$SERVER_ZONE"

  $VENV_PYTHON analyze_experiment.py --pcap "results/benchmark/benchmark_${MODE}.pcap" --direct-ip "$DIRECT_IP" --output "results/benchmark/benchmark_${MODE}.png"
}

run_mode direct
run_mode proxy_no_evasion
run_mode proxy_evasion

echo "Done. Outputs in results/benchmark/"
