#!/usr/bin/env python3
"""
Client script for the RESIP RTT experiment.
Sends repeated HTTPS connections to the experiment server,
both directly and through a RESIP proxy.

Usage:
  # Direct connections (baseline):
  python3 client.py direct --server-ip 8.8.8.8 --count 100

  # Proxied connections via RESIP:
  python3 client.py proxy --server-ip 8.8.8.8 --count 100 --proxy-url socks5h://proxy:1080
"""

import argparse
import subprocess
import time
import sys
from concurrent.futures import ThreadPoolExecutor

def make_connection(server_ip, proxy_url=None):
    """Make a single HTTPS connection using curl. Returns True on success."""
    url = f"https://{server_ip}/"
    cmd = [
        'curl', '-sk',       # -s silent, -k skip cert verify (self-signed)
        '--max-time', '5',   # timeout
        '-o', '/dev/null',   # discard body
        '-w', '%{http_code}',
        url
    ]
    if proxy_url:
        cmd += ['--proxy', proxy_url]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        status = result.stdout.strip()
        return status == '200'
    except Exception as e:
        print(f"  Error: {e}", file=sys.stderr)
        return False

def run_experiment(mode, server_ip, count, proxy_url=None, delay=0.1, workers=10):
    """Run a batch of connections in parallel."""
    print(f"\n{'='*50}")
    print(f"Mode: {mode}")
    print(f"Server: {server_ip}")
    print(f"Connections: {count}")
    print(f"Concurrency: {workers} workers")
    print(f"Delay: {delay}s")
    print(f"{'='*50}\n")

    successes = 0
    failures = 0

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        for i in range(count):
            futures.append(executor.submit(make_connection, server_ip, proxy_url))
            if delay > 0:
                time.sleep(delay)

        for i, future in enumerate(futures, 1):
            if future.result():
                successes += 1
            else:
                failures += 1

            if i % 10 == 0 or i == count:
                print(f"  [{i}/{count}] Complete (success: {successes}, failed: {failures})")

    print(f"\n--- Results ---")
    print(f"Total: {count}, Success: {successes}, Failed: {failures}")
    if count > 0:
        print(f"Success rate: {successes/count*100:.1f}%")

def main():
    parser = argparse.ArgumentParser(description='RESIP RTT Experiment Client')
    parser.add_argument('mode', choices=['direct', 'proxy'],
                        help='Connection mode: direct or proxy')
    parser.add_argument('--server-ip', '-s', type=str, required=True,
                        help='Server IP address')
    parser.add_argument('--count', '-n', type=int, default=100,
                        help='Number of connections (default: 100)')
    parser.add_argument('--proxy-url', '-p', type=str, default=None,
                        help='RESIP proxy URL (e.g., http://user:pass@host:port)')
    parser.add_argument('--delay', '-d', type=float, default=0.5,
                        help='Delay between connections in seconds (default: 0.5)')
    parser.add_argument('--workers', '-w', type=int, default=10,
                        help='Number of concurrent workers (default: 10)')
    args = parser.parse_args()

    if args.mode == 'proxy' and not args.proxy_url:
        print("Error: --proxy-url is required for proxy mode", file=sys.stderr)
        sys.exit(1)

    proxy = args.proxy_url if args.mode == 'proxy' else None
    run_experiment(args.mode, args.server_ip, args.count, proxy, args.delay, args.workers)

if __name__ == '__main__':
    main()
