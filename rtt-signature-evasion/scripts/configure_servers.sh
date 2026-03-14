#!/bin/bash
set -e

REGIONS=(
  "europe-west4"     # Netherlands
  "asia-northeast1"  # Tokyo
  "southamerica-east1" # Sao Paulo
)

ZONES=(
  "europe-west4-a"
  "asia-northeast1-b"
  "southamerica-east1-a"
)

NAMES=(
  "resip-server-eu"
  "resip-server-asia"
  "resip-server-sa"
)

for i in "${!REGIONS[@]}"; do
  REGION="${REGIONS[$i]}"
  ZONE="${ZONES[$i]}"
  NAME="${NAMES[$i]}"
  
  echo "=> Installing Nginx and setting up HTTPS on $NAME in $ZONE..."
  
  gcloud compute ssh "$NAME" --zone="$ZONE" --command="
    sudo apt-get update && sudo apt-get install -y nginx tcpdump screen;
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt -subj '/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost';
    echo 'server { listen 443 ssl; ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt; ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key; location / { return 200 \"OK\"; } }' | sudo tee /etc/nginx/sites-available/default > /dev/null;
    sudo systemctl restart nginx
  "
  
  echo "=> Done configuring $NAME"
done
