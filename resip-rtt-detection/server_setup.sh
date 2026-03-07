#!/bin/bash
# Server setup script for RESIP RTT experiment
# Run on the GCP VM: gcloud compute ssh resip-server -- 'bash -s' < server_setup.sh

set -e

echo "=== Installing dependencies ==="
sudo apt-get update -y
sudo apt-get install -y nginx tcpdump openssl

echo "=== Generating self-signed TLS certificate ==="
sudo mkdir -p /etc/nginx/ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/server.key \
  -out /etc/nginx/ssl/server.crt \
  -subj "/CN=resip-experiment"

echo "=== Configuring nginx HTTPS server ==="
sudo tee /etc/nginx/sites-available/resip-experiment > /dev/null << 'NGINX'
server {
    listen 443 ssl;
    server_name _;

    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;

    # Support both TLS 1.2 and 1.3 for the experiment
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        return 200 '{"status":"ok","server":"resip-experiment"}\n';
        add_header Content-Type application/json;
    }
}
NGINX

sudo ln -sf /etc/nginx/sites-available/resip-experiment /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl restart nginx

echo "=== Setting up tcpdump capture script ==="
sudo tee /usr/local/bin/start_capture.sh > /dev/null << 'CAPTURE'
#!/bin/bash
# Captures all port 443 traffic. Rotates every hour (3600s) to match the paper.
CAPTURE_DIR=/home/$USER/captures
mkdir -p $CAPTURE_DIR
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
echo "Starting capture at $TIMESTAMP..."
sudo tcpdump -i any -w "$CAPTURE_DIR/capture_${TIMESTAMP}.pcap" \
  port 443 -s 0 -G 3600 -W 24 &
echo $! > /tmp/tcpdump.pid
echo "tcpdump running (PID: $(cat /tmp/tcpdump.pid))"
echo "Captures saved to $CAPTURE_DIR/"
CAPTURE
sudo chmod +x /usr/local/bin/start_capture.sh

echo "=== Verifying nginx ==="
curl -sk https://localhost:443/ && echo ""

echo ""
echo "=== Setup complete ==="
echo "Server IP: $(curl -s ifconfig.me)"
echo "To start capturing: /usr/local/bin/start_capture.sh"
echo "To stop capturing:  sudo kill \$(cat /tmp/tcpdump.pid)"
echo "Captures saved to:  ~/captures/"
