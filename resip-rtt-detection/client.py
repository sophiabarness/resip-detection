#!/usr/bin/env python3
"""
Client script for the RESIP RTT experiment.
Sends repeated HTTPS connections to the experiment server,
both directly and through a RESIP proxy.

Usage:
  # Direct connections (baseline):
  python3 client.py direct --count 100

  # Proxied connections via RESIP:
  python3 client.py proxy --count 100 --proxy-url http://user:pass@proxy.example.com:port
"""

import argparse
import subprocess
import time
import sys

SERVER = "35.233.164.114"
URL = f"https://{SERVER}/"


def make_connection(proxy_url=None):
    """Make a single HTTPS connection using curl. Returns True on success."""
    cmd = [
        'curl', '-sk',       # -s silent, -k skip cert verify (self-signed)
        '--max-time', '10',  # timeout
        '-o', '/dev/null',   # discard body
        '-w', '%{http_code}',
        URL
    ]
    if proxy_url:
        cmd += ['--proxy', proxy_url]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        status = result.stdout.strip()
        return status == '200'
    except Exception as e:
        print(f"  Error: {e}", file=sys.stderr)
        return False


def run_experiment(mode, count, proxy_url=None, delay=0.5):
    """Run a batch of connections."""
    print(f"\n{'='*50}")
    print(f"Mode: {mode}")
    print(f"Server: {SERVER}")
    print(f"Connections to make: {count}")
    if proxy_url:
        # Mask password in display
        display_url = proxy_url.split('@')[-1] if '@' in proxy_url else proxy_url
        print(f"Proxy: {display_url}")
    print(f"Delay between connections: {delay}s")
    print(f"{'='*50}\n")

    successes = 0
    failures = 0

    for i in range(1, count + 1):
        ok = make_connection(proxy_url)
        if ok:
            successes += 1
            status_char = '✓'
        else:
            failures += 1
            status_char = '✗'

        if i % 10 == 0 or i == count:
            print(f"  [{i}/{count}] {status_char}  (success: {successes}, failed: {failures})")

        time.sleep(delay)

    print(f"\n--- Results ---")
    print(f"Total: {count}, Success: {successes}, Failed: {failures}")
    print(f"Success rate: {successes/count*100:.1f}%")


def main():
    parser = argparse.ArgumentParser(description='RESIP RTT Experiment Client')
    parser.add_argument('mode', choices=['direct', 'proxy'],
                        help='Connection mode: direct or proxy')
    parser.add_argument('--count', '-n', type=int, default=100,
                        help='Number of connections (default: 100)')
    parser.add_argument('--proxy-url', '-p', type=str, default=None,
                        help='RESIP proxy URL (e.g., http://user:pass@host:port)')
    parser.add_argument('--delay', '-d', type=float, default=0.5,
                        help='Delay between connections in seconds (default: 0.5)')
    args = parser.parse_args()

    if args.mode == 'proxy' and not args.proxy_url:
        print("Error: --proxy-url is required for proxy mode", file=sys.stderr)
        print("Example: python3 client.py proxy --proxy-url http://user:pass@proxy.example.com:port")
        sys.exit(1)

    proxy = args.proxy_url if args.mode == 'proxy' else None
    run_experiment(args.mode, args.count, proxy, args.delay)


if __name__ == '__main__':
    main()
