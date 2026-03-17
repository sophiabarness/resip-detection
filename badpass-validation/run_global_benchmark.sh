#!/bin/bash
set -e

REGIONS=( "us-west1-b" "us-east1-b" "europe-west4-a" "asia-northeast1-b" "southamerica-east1-a" )
SERVERS=( "resip-server" "resip-server-east" "resip-server-eu" "resip-server-asia" "resip-server-sa" )
# PROXY_URL should be set in the environment, e.g.:
# export PROXY_URL="http://user:pass@host:port"
if [ -z "${PROXY_URL:-}" ]; then
  echo "Error: PROXY_URL environment variable is not set."
  exit 1
fi

for i in "${!REGIONS[@]}"; do
  REGION="${REGIONS[$i]}"
  SERVER_NAME="${SERVERS[$i]}"
  
  # Fetch IP
  IP=$(gcloud compute instances describe "$SERVER_NAME" --zone="$REGION" --format="get(networkInterfaces[0].accessConfigs[0].natIP)")
  
  echo "====================================="
  echo "Starting Benchmark for Region: $REGION (IP: $IP)"
  echo "====================================="
  
  # Update client.py target IP
  sed -i '' "s/SERVER = \".*\"/SERVER = \"$IP\"/g" client.py
  
  # START PCAP ON TARGET SERVER
  gcloud compute ssh "$SERVER_NAME" --zone="$REGION" --command="sudo pkill tcpdump; sudo rm -f ~/capture.pcap; sudo screen -d -m bash -c 'sudo tcpdump -i any tcp port 443 -w capture.pcap'"
  sleep 5
  
  echo "--- Running DIRECT BASELINE (1,000 connections) ---"
  python3 client.py direct --count 1000 --delay 0.1 --workers 50
  
  sleep 5
  echo "--- Running IPROYAL PROXY (1,000 connections) ---"
  python3 client.py proxy --count 1000 --proxy-url "$PROXY_URL" --delay 0.1 --workers 50
  
  echo "--- Collecting PCAP ---"
  gcloud compute ssh "$SERVER_NAME" --zone="$REGION" --command="sudo pkill tcpdump" || true
  gcloud compute scp "$SERVER_NAME":~/capture.pcap "./results/results_${REGION}.pcap" --zone="$REGION"
  
  echo "--- Analyzing PCAP for $REGION ---"
  python3 analyze_experiment.py --pcap "./results/results_${REGION}.pcap" --direct-ip 128.12.122.232 --output "./results/results_${REGION}.png"
  
done
