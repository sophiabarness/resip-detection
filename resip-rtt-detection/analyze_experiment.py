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
    cmd = [
        'tshark', '-r', pcap, '-T', 'fields', '-E', 'separator=|', '-E', 'header=y',
    ]
    for f in fields:
        cmd += ['-e', f]
    if display_filter:
        cmd += ['-Y', display_filter]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        return []
    reader = csv.DictReader(io.StringIO(result.stdout), delimiter='|')
    return list(reader)


def extract_metrics(pcap):
    """
    Extract TCP and TLS RTT info per stream.
    """
    print(f"Processing {pcap}...")
    
    # 1. Get all TCP packets for synchronization and RTT
    fields = ['tcp.stream', 'frame.time_epoch', 'tcp.flags', 'tcp.srcport', 'tcp.dstport', 'ip.src', 'ip.dst', 'tcp.len']
    all_tcp = run_tshark(pcap, fields, "tcp")
    
    streams = collections.defaultdict(lambda: {
        'syn_ack_time': None,
        'tcp_rtt': None,
        'client_ip': None,
        'tls_start_time': None,
        'tls_end_time': None,
        'tls_rtt': None,
    })

    for row in all_tcp:
        sid = row['tcp.stream']
        ts = float(row['frame.time_epoch'])
        flags_str = row.get('tcp.flags', '0x0')
        flags = int(flags_str, 16)
        srcport = row['tcp.srcport']
        dstport = row['tcp.dstport']
        
        s = streams[sid]
        
        # TCP SYN-ACK from server (port 443)
        if srcport == '443' and (flags & 0x12) == 0x12: # SYN+ACK
            if s['syn_ack_time'] is None:
                s['syn_ack_time'] = ts
                s['client_ip'] = row['ip.dst']
                print(f"DEBUG: Stream {sid} SYN-ACK at {ts} from {row['ip.dst']}")
        
        # TCP ACK from client (dest port 443) to complete handshake
        elif dstport == '443' and (flags & 0x10) == 0x10 and not (flags & 0x02): # ACK only
            if s['syn_ack_time'] is not None and s['tcp_rtt'] is None:
                # First ACK after SYN-ACK
                s['tcp_rtt'] = ts - s['syn_ack_time']
                print(f"DEBUG: Stream {sid} TCP RTT: {s['tcp_rtt']*1000:.2f}ms")

    # 2. Get TLS Handshake info
    # For TLS RTT, we'll look for:
    # TLS 1.2: ServerHelloDone (14) -> ClientKeyExchange (16)
    # TLS 1.3: ServerHello (2) -> Client Finished/App Data (23) or similar
    fields = ['tcp.stream', 'frame.time_epoch', 'tls.handshake.type', 'tls.record.content_type', 'tcp.srcport']
    tls_packets = run_tshark(pcap, fields, "tls")
    
    for row in tls_packets:
        sid = row['tcp.stream']
        ts = float(row['frame.time_epoch'])
        hs_types = row.get('tls.handshake.type', '') or ''
        content_types = row.get('tls.record.content_type', '') or ''
        srcport = row['tcp.srcport']
        
        s = streams[sid]
        
        # Simplified TLS RTT logic for this experiment:
        # P1: Last server-side handshake packet (ServerHello or similar)
        # P2: First client-side encrypted handshake response
        
        if srcport == '443': 
            # Packet from server
            if '2' in hs_types or '14' in hs_types: # ServerHello or Done
                s['tls_start_time'] = ts
                print(f"DEBUG: Stream {sid} TLS start at {ts}")
        else:
            # Packet from client
            # TLS 1.2 uses ClientKeyExchange (16)
            # TLS 1.3 typically uses ChangeCipherSpec (20) following ServerHello
            if ('16' in hs_types) or ('20' in content_types) or ('23' in content_types):
                if s['tls_start_time'] is not None and s['tls_end_time'] is None:
                    # Ignore if the time difference is too large (likely not a handshake packet)
                    rtt = ts - s['tls_start_time']
                    if rtt < 5.0: # 5 seconds timeout for handshake
                        s['tls_end_time'] = ts
                        s['tls_rtt'] = rtt
                        # print(f"DEBUG: Stream {sid} TLS RTT: {s['tls_rtt']*1000:.2f}ms")

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


def export_csv(results, output_path):
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['sid', 'client_ip', 'tcp_rtt_ms', 'tls_rtt_ms', 'diff_ms', 'type'])
        writer.writeheader()
        for r in results:
            r_copy = r.copy()
            r_copy['type'] = 'DIRECT' if r['client_ip'] == '128.12.122.233' else 'PROXY'
            writer.writerow(r_copy)
    print(f"Detailed results exported to {output_path}")


def main():
    pcap = './captures/resip_final.pcap'
    if not os.path.exists(pcap):
        print(f"File {pcap} not found")
        return
        
    results = extract_metrics(pcap)
    
    # 128.12.122.233 is the user's laptop IP (Stanford/local)
    plot_results(results, 'experiment_results_ip_grouped.png', direct_ip='128.12.122.233')
    export_csv(results, 'detailed_rtt_results.csv')
    
    # Print some stats
    if results:
        ips = collections.Counter([r['client_ip'] for r in results])
        print("\nClient IP Distribution (Top 10):")
        for ip, count in ips.most_common(10):
            tag = "(DIRECT)" if ip == '128.12.122.233' else "(PROXY)"
            print(f"  {ip:15} : {count:2} connections {tag}")


if __name__ == '__main__':
    main()
