#!/usr/bin/env python3
"""
Refined analysis script for the RESIP RTT experiment.
Computes TCP RTT and TLS RTT differences from server-side PCAP.
"""

import subprocess
import csv
import io
import os
import collections
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def run_tshark(pcap, fields, display_filter=None):
    tshark_path = 'tshark'
    possible_paths = ['/Applications/Wireshark.app/Contents/MacOS/tshark', '/usr/local/bin/tshark', '/opt/homebrew/bin/tshark']
    for p in possible_paths:
        if os.path.exists(p):
            tshark_path = p
            break

    cmd = [
        tshark_path, '-r', pcap, '-T', 'fields', '-E', 'header=y',
    ]
    for f in fields:
        cmd += ['-e', f]
    if display_filter:
        cmd += ['-Y', display_filter]
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if not result.stdout:
        return []
        
    reader = csv.DictReader(io.StringIO(result.stdout), delimiter='\t')
    return list(reader)


def extract_metrics(pcap):
    """
    Extract TCP and TLS RTT info per stream.
    """
    print(f"Processing {pcap}...")
    
    # 1. Get all TCP packets for synchronization and RTT
    fields = ['tcp.stream', 'frame.time_epoch', 'tcp.flags', 'tcp.srcport', 'tcp.dstport', 'ip.src', 'ip.dst', 'tcp.len']
    all_tcp = run_tshark(pcap, fields, "tcp")
    print(f"DEBUG: Found {len(all_tcp)} TCP packets")
    if all_tcp:
        print(f"DEBUG: First row: {all_tcp[0]}")
    
    streams = collections.defaultdict(lambda: {
        'syn_ack_time': None,
        'tcp_rtt': None,
        'client_ip': None,
        'tls_start_time': None,
        'tls_end_time': None,
        'tls_rtt': None,
    })

    for row in all_tcp:
        sid = row.get('tcp.stream')
        if not sid: continue
        
        ts_str = row.get('frame.time_epoch')
        if not ts_str: continue
        ts = float(ts_str)
        
        flags_str = row.get('tcp.flags', '0x0')
        flags = int(flags_str, 16)
        srcport = row.get('tcp.srcport')
        dstport = row.get('tcp.dstport')
        
        s = streams[sid]
        
        # TCP SYN-ACK from server (port 443)
        if srcport == '443' and (flags & 0x12) == 0x12: # SYN+ACK
            if s['syn_ack_time'] is None:
                s['syn_ack_time'] = ts
                s['client_ip'] = row.get('ip.dst') or row.get('ipv6.dst')
        
        # TCP ACK from client (dest port 443) to complete handshake
        elif dstport == '443' and (flags & 0x10) == 0x10 and not (flags & 0x02): # ACK only
            if s['syn_ack_time'] is not None and s['tcp_rtt'] is None:
                s['tcp_rtt'] = ts - s['syn_ack_time']

    # 2. Get TLS Handshake info
    # We use a broader filter to catch both TLS 1.2 and 1.3
    fields = ['tcp.stream', 'frame.time_epoch', 'tls.handshake.type', 'tls.record.content_type', 'tcp.srcport', 'tcp.len']
    tls_packets = run_tshark(pcap, fields, "tls or tcp.len > 0")
    
    for row in tls_packets:
        sid = row['tcp.stream']
        ts = float(row['frame.time_epoch'])
        srcport = row['tcp.srcport']
        payload_len = int(row.get('tcp.len', '0') or '0')
        
        s = streams[sid]
        
        if srcport == '443': 
            # Packet from server
            # In TLS 1.3, ServerHello (2) is often the first significant response
            if s['tls_start_time'] is None and payload_len > 100: # Broad heuristic for ServerHello+
                s['tls_start_time'] = ts
        else:
            # Packet from client
            # The first application-data or handshake-response after ServerHello
            if s['tls_start_time'] is not None and s['tls_end_time'] is None:
                rtt = ts - s['tls_start_time']
                if 0.001 < rtt < 2.0: # Sensible RTT range
                    s['tls_end_time'] = ts
                    s['tls_rtt'] = rtt

    # 3. Aggregate results
    results = []
    for sid, s in streams.items():
        if s['tcp_rtt'] and s['tls_rtt']:
            diff = (s['tls_rtt'] - s['tcp_rtt']) * 1000 # to ms
            results.append({
                'sid': sid,
                'client_ip': s['client_ip'],
                'tcp_rtt_ms': s['tcp_rtt'] * 1000,
                'tls_rtt_ms': s['tls_rtt'] * 1000,
                'diff_ms': diff
            })
            
    print(f"Extracted {len(results)} valid streams with both TCP and TLS RTTs")
    return results


def plot_results(results, output_path, direct_ip='128.12.122.233'):
    if not results:
        print("No results to plot")
        return

    # Define a shared x-axis range and consistent bin width
    all_diffs = [r['diff_ms'] for r in results]
    x_min = -10
    x_max = min(2000, np.percentile(all_diffs, 98))
    
    # Use a fixed bin width of 5ms for consistency
    bin_width = 5
    bins = np.arange(x_min, x_max + bin_width, bin_width)

    # Group by Ground Truth (Client IP)
    direct = [r['diff_ms'] for r in results if r['client_ip'] == direct_ip]
    proxy = [r['diff_ms'] for r in results if r['client_ip'] != direct_ip]

    print(f"Ground Truth - Direct ({direct_ip}): {len(direct)}, Proxy (Other IPs): {len(proxy)}")
    
    plt.figure(figsize=(10, 6))
    
    if direct:
        plt.hist(direct, bins=bins, alpha=0.6, label=f'Direct (IP: {direct_ip}, n={len(direct)})', color='royalblue')
    if proxy:
        plt.hist(proxy, bins=bins, alpha=0.6, label=f'Proxy (Diverse RESIP IPs, n={len(proxy)})', color='crimson')
        
    plt.xlabel('RTT Difference (TLS RTT - TCP RTT) [ms]', fontsize=12)
    plt.ylabel('Connection Count', fontsize=12)
    plt.title('RESIP Experiment: RTT Difference Distribution (Standardized Bins)', fontsize=14, fontweight='bold')
    plt.legend()
    plt.grid(axis='y', alpha=0.3)
    plt.xlim(x_min, x_max)
    
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"Plot saved to {output_path}")


def export_csv(results, output_path, direct_ip):
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['sid', 'client_ip', 'tcp_rtt_ms', 'tls_rtt_ms', 'diff_ms', 'type'])
        writer.writeheader()
        for r in results:
            r_copy = r.copy()
            r_copy['type'] = 'DIRECT' if r['client_ip'] == direct_ip else 'PROXY'
            writer.writerow(r_copy)
    print(f"Detailed results exported to {output_path}")


def main():
    parser = argparse.ArgumentParser(description='Analyze RESIP PCAP for RTT differences.')
    parser.add_argument('--pcap', type=str, default='./captures/resip_final.pcap', help='Path to PCAP file')
    parser.add_argument('--direct-ip', type=str, default='128.12.122.233', help='Ground truth direct client IP')
    parser.add_argument('--output', type=str, default='experiment_results.png', help='Output plot path')
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"File {args.pcap} not found")
        return
        
    results = extract_metrics(args.pcap)
    
    plot_results(results, args.output, direct_ip=args.direct_ip)
    csv_path = args.output.replace('.png', '.csv')
    export_csv(results, csv_path, args.direct_ip)
    
    # Print some stats
    if results:
        ips = collections.Counter([r['client_ip'] for r in results])
        print("\nClient IP Distribution (Top 10):")
        for ip, count in ips.most_common(10):
            tag = "(DIRECT)" if ip == args.direct_ip else "(PROXY)"
            print(f"  {ip:15} : {count:2} connections {tag}")


if __name__ == '__main__':
    import argparse
    main()
