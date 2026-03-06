#!/usr/bin/env python3
"""
Analyze a pcap file to classify and characterize residential proxy traffic.

Given a proxy IP, classifies remote IPs into gateway servers vs. proxied
destinations, then produces findings on:

  1. IP classification (gateway vs destination)
  2. Destination distribution (what services are being accessed)
  3. Geolocation of destination IPs
  4. Gateway vs destination traffic volume ratio
  5. Per-gateway connection patterns
  6. Temporal patterns (burst vs steady)
  7. Connection reuse vs one-shot per destination
  8. TLS fingerprint diversity
  9. UDP tunnel packet size distribution
  10. DNS query analysis

Usage:
  python3 analyze_pcap.py [--pcap FILE] [--proxy-ip IP] [--no-geo]
"""

import argparse
import json
import math
import subprocess
import sys
import urllib.request
import urllib.error
from collections import Counter, defaultdict
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# tshark helpers
# ---------------------------------------------------------------------------

def run_tshark(pcap, fields, display_filter=None):
    """Run tshark and return rows of tab-separated field values."""
    cmd = ["tshark", "-r", pcap, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    if display_filter:
        cmd += ["-Y", display_filter]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        fatal = [l for l in result.stderr.strip().splitlines()
                 if l and "cut short" not in l]
        if fatal and not result.stdout.strip():
            print(f"tshark error: {result.stderr}", file=sys.stderr)
            sys.exit(1)
    rows = []
    for line in result.stdout.strip().split("\n"):
        if line:
            rows.append(line.split("\t"))
    return rows


# ---------------------------------------------------------------------------
# Finding 1: IP classification
# ---------------------------------------------------------------------------

def classify_ips(pcap, proxy_ip):
    """Classify all remote IPs into gateway, destination, dns, or other."""
    rows = run_tshark(
        pcap,
        ["ip.src", "ip.dst", "ip.proto", "udp.srcport", "udp.dstport",
         "tcp.srcport", "tcp.dstport"],
        display_filter=f"ip.addr == {proxy_ip}",
    )

    ip_stats = defaultdict(lambda: {
        "tcp_packets": 0, "udp_packets": 0,
        "tcp_ports": set(), "udp_ports": set(),
        "total_packets": 0, "tcp_syns": 0,
    })

    for row in rows:
        row += [""] * (7 - len(row))
        src, dst, proto, usrc, udst, tsrc, tdst = row
        remote = dst if src == proxy_ip else src
        if remote == proxy_ip:
            continue
        stats = ip_stats[remote]
        stats["total_packets"] += 1
        if proto == "6":
            stats["tcp_packets"] += 1
            for p in (tsrc, tdst):
                if p:
                    stats["tcp_ports"].add(p)
        elif proto == "17":
            stats["udp_packets"] += 1
            for p in (usrc, udst):
                if p:
                    stats["udp_ports"].add(p)

    # TCP SYNs from proxy
    for row in run_tshark(pcap, ["ip.dst"],
                          f"ip.src == {proxy_ip} && tcp.flags.syn == 1 && tcp.flags.ack == 0"):
        if row[0] in ip_stats:
            ip_stats[row[0]]["tcp_syns"] += 1

    # TCP SYNs to proxy
    for row in run_tshark(pcap, ["ip.src"],
                          f"ip.dst == {proxy_ip} && tcp.flags.syn == 1 && tcp.flags.ack == 0"):
        if row[0] in ip_stats:
            ip_stats[row[0]]["tcp_syns"] += 1

    # TLS SNI
    sni_rows = run_tshark(pcap,
                          ["ip.dst", "tls.handshake.extensions_server_name"],
                          "tls.handshake.type == 1")
    ip_sni = {}
    for row in sni_rows:
        row += [""] * (2 - len(row))
        ip, sni = row
        if sni and ip not in ip_sni:
            ip_sni[ip] = sni

    gateways, destinations, dns_servers, other = {}, {}, {}, {}
    for ip, stats in ip_stats.items():
        entry = {
            "ip": ip,
            "total_packets": stats["total_packets"],
            "tcp_packets": stats["tcp_packets"],
            "udp_packets": stats["udp_packets"],
            "tcp_ports": sorted(stats["tcp_ports"]),
            "udp_ports": sorted(stats["udp_ports"]),
            "tcp_syns": stats["tcp_syns"],
            "sni": ip_sni.get(ip, ""),
        }
        if stats["udp_packets"] > 0 and "53" in stats["udp_ports"] and stats["tcp_packets"] == 0:
            dns_servers[ip] = entry
        elif stats["udp_packets"] > 0 and stats["tcp_packets"] == 0 and "53" not in stats["udp_ports"]:
            gateways[ip] = entry
        elif stats["tcp_packets"] > 0 and stats["udp_packets"] == 0:
            destinations[ip] = entry
        else:
            other[ip] = entry

    return gateways, destinations, dns_servers, other


# ---------------------------------------------------------------------------
# Finding 2: Destination distribution (services)
# ---------------------------------------------------------------------------

def analyze_destination_distribution(destinations):
    """Summarize destination IPs by known service/CDN based on IP ranges."""
    # Simple heuristic mapping of well-known IP ranges to services
    known_prefixes = [
        ("142.250.", "Google"),
        ("172.217.", "Google"),
        ("216.58.", "Google"),
        ("104.16.", "Cloudflare"),
        ("104.26.", "Cloudflare"),
        ("172.64.", "Cloudflare"),
        ("172.67.", "Cloudflare"),
        ("151.101.", "Fastly (Reddit/StackOverflow/etc)"),
        ("23.67.", "Akamai"),
        ("23.37.", "Akamai"),
        ("23.40.", "Akamai"),
        ("23.227.", "Shopify"),
        ("96.16.", "Akamai"),
        ("69.192.", "Akamai"),
        ("13.249.", "Amazon CloudFront"),
        ("52.223.", "Amazon"),
        ("98.82.", "Amazon"),
        ("173.234.", "Proxy/VPN provider range"),
        ("162.251.", "Hosting provider"),
    ]

    service_counts = Counter()
    service_packets = Counter()
    service_ips = defaultdict(list)
    unmatched = []

    for ip, entry in sorted(destinations.items(), key=lambda x: -x[1]["total_packets"]):
        matched = False
        for prefix, service in known_prefixes:
            if ip.startswith(prefix):
                service_counts[service] += 1
                service_packets[service] += entry["total_packets"]
                service_ips[service].append(ip)
                matched = True
                break
        if not matched:
            unmatched.append(entry)

    return service_counts, service_packets, service_ips, unmatched


# ---------------------------------------------------------------------------
# Finding 3: Geolocation
# ---------------------------------------------------------------------------

def geolocate_ips(ips):
    """Geolocate a list of IPs using ip-api.com batch endpoint (free, no key)."""
    # ip-api.com allows batches of up to 100
    payload = json.dumps([{"query": ip} for ip in ips]).encode()
    req = urllib.request.Request(
        "http://ip-api.com/batch?fields=query,country,countryCode,city,org,as",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"  (geolocation failed: {e})", file=sys.stderr)
        return []


# ---------------------------------------------------------------------------
# Finding 4: Traffic volume ratio
# ---------------------------------------------------------------------------

def analyze_traffic_ratio(pcap, proxy_ip, gateways, destinations):
    """Compare bytes on gateway (UDP) vs destination (TCP) links."""
    gw_ips = list(gateways.keys())
    dst_ips = list(destinations.keys())

    gw_bytes = 0
    dst_bytes = 0

    rows = run_tshark(
        pcap,
        ["ip.src", "ip.dst", "ip.proto", "frame.len"],
        display_filter=f"ip.addr == {proxy_ip}",
    )
    for row in rows:
        row += [""] * (4 - len(row))
        src, dst, proto, flen = row
        remote = dst if src == proxy_ip else src
        try:
            length = int(flen)
        except ValueError:
            continue
        if remote in gw_ips:
            gw_bytes += length
        elif remote in dst_ips:
            dst_bytes += length

    return gw_bytes, dst_bytes


# ---------------------------------------------------------------------------
# Finding 5: Per-gateway patterns
# ---------------------------------------------------------------------------

def analyze_gateway_patterns(pcap, proxy_ip, gateways):
    """Analyze timing and volume per gateway."""
    rows = run_tshark(
        pcap,
        ["frame.time_epoch", "ip.src", "ip.dst", "frame.len"],
        display_filter=f"ip.addr == {proxy_ip} && udp && !dns",
    )

    gw_data = defaultdict(lambda: {"timestamps": [], "sizes": [], "bytes": 0, "packets": 0})
    for row in rows:
        row += [""] * (4 - len(row))
        ts, src, dst, flen = row
        remote = dst if src == proxy_ip else src
        if remote not in gateways:
            continue
        try:
            gw_data[remote]["timestamps"].append(float(ts))
            gw_data[remote]["sizes"].append(int(flen))
            gw_data[remote]["bytes"] += int(flen)
            gw_data[remote]["packets"] += 1
        except ValueError:
            continue

    results = {}
    for ip, data in gw_data.items():
        ts = sorted(data["timestamps"])
        duration = ts[-1] - ts[0] if len(ts) > 1 else 0
        # Check for overlap with other gateways
        results[ip] = {
            "packets": data["packets"],
            "bytes": data["bytes"],
            "duration_s": round(duration, 2),
            "pps": round(data["packets"] / duration, 1) if duration > 0 else 0,
            "first_seen": ts[0] if ts else 0,
            "last_seen": ts[-1] if ts else 0,
        }
    return results


# ---------------------------------------------------------------------------
# Finding 6: Temporal patterns (burstiness)
# ---------------------------------------------------------------------------

def analyze_temporal_patterns(pcap, proxy_ip):
    """Analyze TCP SYN timing to detect bursts vs steady connections."""
    rows = run_tshark(
        pcap,
        ["frame.time_epoch", "ip.dst"],
        display_filter=f"ip.src == {proxy_ip} && tcp.flags.syn == 1 && tcp.flags.ack == 0",
    )

    timestamps = []
    for row in rows:
        row += [""] * (2 - len(row))
        ts, dst = row
        try:
            timestamps.append(float(ts))
        except ValueError:
            continue

    if len(timestamps) < 2:
        return None

    timestamps.sort()
    total_duration = timestamps[-1] - timestamps[0]
    n = len(timestamps)

    # Inter-arrival times
    iats = [timestamps[i+1] - timestamps[i] for i in range(n - 1)]
    mean_iat = sum(iats) / len(iats)
    variance_iat = sum((x - mean_iat) ** 2 for x in iats) / len(iats)
    std_iat = math.sqrt(variance_iat)
    cv = std_iat / mean_iat if mean_iat > 0 else 0  # coefficient of variation

    # Bucket into 5-second windows
    bucket_size = 5
    buckets = Counter()
    for ts in timestamps:
        bucket = int((ts - timestamps[0]) / bucket_size)
        buckets[bucket] += 1

    return {
        "total_syns": n,
        "duration_s": round(total_duration, 2),
        "syns_per_second": round(n / total_duration, 2) if total_duration > 0 else 0,
        "mean_inter_arrival_s": round(mean_iat, 3),
        "std_inter_arrival_s": round(std_iat, 3),
        "cv_inter_arrival": round(cv, 2),
        "bucket_size_s": bucket_size,
        "connections_per_bucket": dict(sorted(buckets.items())),
    }


# ---------------------------------------------------------------------------
# Finding 7: Connection reuse vs one-shot
# ---------------------------------------------------------------------------

def analyze_connection_reuse(destinations):
    """Categorize destinations by number of TCP SYNs (connections)."""
    heavy = []   # many connections
    single = []  # exactly 1 SYN

    for ip, entry in sorted(destinations.items(), key=lambda x: -x[1]["tcp_syns"]):
        if entry["tcp_syns"] > 1:
            heavy.append(entry)
        elif entry["tcp_syns"] == 1:
            single.append(entry)
        # tcp_syns == 0 means we didn't see the SYN (capture started mid-flow)

    return heavy, single


# ---------------------------------------------------------------------------
# Finding 8: TLS fingerprint diversity
# ---------------------------------------------------------------------------

def analyze_tls_fingerprints(pcap):
    """Extract TLS Client Hello fingerprint variations."""
    rows = run_tshark(
        pcap,
        ["ip.dst", "tls.handshake.version", "tls.handshake.ciphersuite",
         "tls.handshake.extensions_server_name"],
        display_filter="tls.handshake.type == 1",
    )

    fingerprints = defaultdict(list)
    for row in rows:
        row += [""] * (4 - len(row))
        dst, version, ciphers, sni = row
        fp = ciphers if ciphers else "(truncated)"
        fingerprints[fp].append({"dst": dst, "sni": sni, "version": version})

    return dict(fingerprints)


# ---------------------------------------------------------------------------
# Finding 9: UDP tunnel packet sizes
# ---------------------------------------------------------------------------

def analyze_udp_sizes(pcap, proxy_ip, gateways):
    """Analyze UDP payload size distribution on gateway tunnel traffic."""
    gw_filter = " || ".join(f"ip.addr == {ip}" for ip in gateways)
    rows = run_tshark(
        pcap,
        ["ip.src", "ip.dst", "udp.length"],
        display_filter=f"udp && ip.addr == {proxy_ip} && ({gw_filter})",
    )

    sizes = []
    for row in rows:
        row += [""] * (3 - len(row))
        src, dst, length = row
        try:
            sizes.append(int(length))
        except ValueError:
            continue

    if not sizes:
        return None

    sizes.sort()
    n = len(sizes)
    mean_sz = sum(sizes) / n
    median_sz = sizes[n // 2]
    mode_sz = Counter(sizes).most_common(5)

    # Check for padding (many identical sizes)
    unique_ratio = len(set(sizes)) / n

    return {
        "count": n,
        "min": min(sizes),
        "max": max(sizes),
        "mean": round(mean_sz, 1),
        "median": median_sz,
        "top_5_sizes": mode_sz,
        "unique_sizes": len(set(sizes)),
        "unique_ratio": round(unique_ratio, 3),
        "likely_padded": unique_ratio < 0.1,
    }


# ---------------------------------------------------------------------------
# Finding 11: Connection security (TLS vs plaintext vs no-data)
# ---------------------------------------------------------------------------

def analyze_connection_security(pcap, proxy_ip, destinations):
    """Classify each TCP stream as TLS-confirmed, plaintext, or no-data."""
    # Get all TCP streams involving the proxy
    all_stream_rows = run_tshark(
        pcap,
        ["tcp.stream", "ip.src", "ip.dst", "tcp.dstport", "tcp.len"],
        display_filter=f"ip.addr == {proxy_ip} && tcp",
    )

    # Build per-stream info
    streams = defaultdict(lambda: {
        "remote_ip": None, "dst_port": None, "total_tcp_payload": 0,
    })
    for row in all_stream_rows:
        row += [""] * (5 - len(row))
        stream_id, src, dst, dstport, tcp_len = row
        if not stream_id:
            continue
        s = streams[stream_id]
        remote = dst if src == proxy_ip else src
        if s["remote_ip"] is None:
            s["remote_ip"] = remote
        if dstport and dstport != "0" and s["dst_port"] is None:
            # Use the server-side port (the one that isn't ephemeral)
            try:
                p = int(dstport)
                if p < 1024 or s["dst_port"] is None:
                    s["dst_port"] = dstport
            except ValueError:
                pass
        try:
            s["total_tcp_payload"] += int(tcp_len)
        except ValueError:
            pass

    # Get streams that contain TLS records
    tls_stream_rows = run_tshark(
        pcap,
        ["tcp.stream"],
        display_filter="tls",
    )
    tls_streams = set()
    for row in tls_stream_rows:
        if row[0]:
            tls_streams.add(row[0])

    # Classify
    tls_confirmed = []
    no_data = []
    plaintext = []

    for stream_id, info in sorted(streams.items(), key=lambda x: x[0]):
        remote = info["remote_ip"]
        port = info["dst_port"] or "?"
        entry = {
            "stream": stream_id,
            "remote_ip": remote,
            "dst_port": port,
            "sni": destinations.get(remote, {}).get("sni", ""),
        }
        if stream_id in tls_streams:
            tls_confirmed.append(entry)
        elif info["total_tcp_payload"] == 0:
            no_data.append(entry)
        else:
            plaintext.append(entry)

    return tls_confirmed, no_data, plaintext


# ---------------------------------------------------------------------------
# Finding 10: DNS query analysis
# ---------------------------------------------------------------------------

def analyze_dns(pcap):
    """Extract DNS queries and responses."""
    rows = run_tshark(
        pcap,
        ["dns.qry.name", "dns.flags.response", "dns.a"],
        display_filter="dns",
    )

    queries = defaultdict(lambda: {"query_count": 0, "resolved_ips": set()})
    for row in rows:
        row += [""] * (3 - len(row))
        name, is_response, addrs = row
        if not name:
            continue
        if is_response == "False":
            queries[name]["query_count"] += 1
        elif addrs:
            for a in addrs.split(","):
                queries[name]["resolved_ips"].add(a.strip())

    return dict(queries)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def hr(title):
    print(f"\n{'=' * 70}")
    print(f" {title}")
    print(f"{'=' * 70}")


def fmt_bytes(b):
    if b >= 1_000_000:
        return f"{b / 1_000_000:.1f} MB"
    if b >= 1_000:
        return f"{b / 1_000:.1f} KB"
    return f"{b} B"


def fmt_ts(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Analyze residential proxy pcap traffic")
    parser.add_argument("--pcap", default="capture.pcap", help="Path to pcap file")
    parser.add_argument("--proxy-ip", default="172.17.0.2", help="IP address of the proxy")
    parser.add_argument("--no-geo", action="store_true", help="Skip geolocation lookups")
    args = parser.parse_args()

    pcap = args.pcap
    proxy_ip = args.proxy_ip

    print(f"Analyzing {pcap} (proxy IP: {proxy_ip})...\n")

    # === Finding 1: Classification ===
    gateways, destinations, dns_servers, other = classify_ips(pcap, proxy_ip)

    hr(f"FINDING 1: IP CLASSIFICATION")
    print(f"\n  Gateway servers: {len(gateways)}  |  Destinations: {len(destinations)}"
          f"  |  DNS: {len(dns_servers)}  |  Other: {len(other)}")

    print(f"\n  --- Gateway servers (UDP tunnel) ---")
    for e in sorted(gateways.values(), key=lambda x: -x["total_packets"]):
        ports = ", ".join(e["udp_ports"])
        print(f"    {e['ip']:<22} {e['total_packets']:>6} pkts  UDP ports: {ports}")

    print(f"\n  --- Destination servers (TCP/HTTPS) ---")
    for e in sorted(destinations.values(), key=lambda x: -x["total_packets"]):
        sni = f"  ({e['sni']})" if e["sni"] else ""
        print(f"    {e['ip']:<22} {e['total_packets']:>6} pkts  {e['tcp_syns']} conn(s){sni}")

    if dns_servers:
        print(f"\n  --- DNS ---")
        for e in dns_servers.values():
            print(f"    {e['ip']:<22} {e['total_packets']:>6} pkts")

    # === Finding 2: Destination distribution ===
    hr("FINDING 2: DESTINATION SERVICE DISTRIBUTION")
    svc_counts, svc_packets, svc_ips, unmatched = analyze_destination_distribution(destinations)
    for svc, cnt in svc_counts.most_common():
        ips_str = ", ".join(svc_ips[svc])
        print(f"  {svc:<35} {cnt:>2} IP(s)  {svc_packets[svc]:>6} pkts  [{ips_str}]")
    if unmatched:
        print(f"\n  Unmatched IPs:")
        for e in unmatched:
            print(f"    {e['ip']:<22} {e['total_packets']:>6} pkts")

    # === Finding 3: Geolocation ===
    hr("FINDING 3: DESTINATION GEOLOCATION")
    if args.no_geo:
        print("  (skipped with --no-geo)")
    else:
        all_ips = list(destinations.keys()) + list(gateways.keys())
        geo_results = geolocate_ips(all_ips)
        if geo_results:
            country_counts = Counter()
            print(f"\n  {'IP':<22} {'Country':<20} {'City':<20} {'Org/AS'}")
            print(f"  {'-'*22} {'-'*20} {'-'*20} {'-'*40}")

            # Print gateways first
            gw_geo = [g for g in geo_results if g.get("query") in gateways]
            dst_geo = [g for g in geo_results if g.get("query") in destinations]

            if gw_geo:
                print(f"\n  Gateways:")
                for g in gw_geo:
                    cc = g.get("countryCode", "?")
                    country = g.get("country", "?")
                    city = g.get("city", "?")
                    org = g.get("org", "?")
                    print(f"    {g['query']:<22} {country:<20} {city:<20} {org}")

            print(f"\n  Destinations:")
            for g in dst_geo:
                cc = g.get("countryCode", "?")
                country = g.get("country", "?")
                city = g.get("city", "?")
                org = g.get("org", "?")
                country_counts[country] += 1
                print(f"    {g['query']:<22} {country:<20} {city:<20} {org}")

            print(f"\n  Destination countries summary:")
            for country, cnt in country_counts.most_common():
                print(f"    {country:<30} {cnt} IP(s)")
        else:
            print("  (no geolocation data available)")

    # === Finding 4: Traffic volume ratio ===
    hr("FINDING 4: TRAFFIC VOLUME — GATEWAY (TUNNEL) vs DESTINATION")
    gw_bytes, dst_bytes = analyze_traffic_ratio(pcap, proxy_ip, gateways, destinations)
    total = gw_bytes + dst_bytes
    gw_pct = (gw_bytes / total * 100) if total else 0
    dst_pct = (dst_bytes / total * 100) if total else 0
    print(f"\n  Gateway (UDP tunnel):  {fmt_bytes(gw_bytes):>12}  ({gw_pct:.1f}%)")
    print(f"  Destination (TCP):     {fmt_bytes(dst_bytes):>12}  ({dst_pct:.1f}%)")
    print(f"  Total:                 {fmt_bytes(total):>12}")
    if dst_bytes > 0:
        print(f"\n  Tunnel overhead ratio: {gw_bytes / dst_bytes:.2f}x the destination traffic")

    # === Finding 5: Per-gateway patterns ===
    hr("FINDING 5: PER-GATEWAY CONNECTION PATTERNS")
    gw_patterns = analyze_gateway_patterns(pcap, proxy_ip, gateways)
    for ip, p in sorted(gw_patterns.items(), key=lambda x: -x[1]["packets"]):
        print(f"\n  {ip}:")
        print(f"    Packets: {p['packets']}  |  Bytes: {fmt_bytes(p['bytes'])}  |  Duration: {p['duration_s']}s")
        print(f"    Rate: {p['pps']} pkt/s  |  Active: {fmt_ts(p['first_seen'])} — {fmt_ts(p['last_seen'])}")

    # Check concurrency
    all_ranges = [(ip, p["first_seen"], p["last_seen"]) for ip, p in gw_patterns.items()]
    if len(all_ranges) >= 2:
        r = sorted(all_ranges, key=lambda x: x[1])
        overlap_start = max(r[0][1], r[1][1])
        overlap_end = min(r[0][2], r[1][2])
        if overlap_start < overlap_end:
            print(f"\n  Gateways are CONCURRENT — overlapping for {overlap_end - overlap_start:.1f}s")
        else:
            print(f"\n  Gateways are SEQUENTIAL — no time overlap")

    # === Finding 6: Temporal patterns ===
    hr("FINDING 6: TEMPORAL PATTERNS (TCP SYN TIMING)")
    temporal = analyze_temporal_patterns(pcap, proxy_ip)
    if temporal:
        print(f"\n  Total new connections (SYNs): {temporal['total_syns']}")
        print(f"  Capture duration: {temporal['duration_s']}s")
        print(f"  Rate: {temporal['syns_per_second']} SYNs/s")
        print(f"\n  Inter-arrival time: mean={temporal['mean_inter_arrival_s']}s, "
              f"std={temporal['std_inter_arrival_s']}s, CV={temporal['cv_inter_arrival']}")
        if temporal["cv_inter_arrival"] > 1.5:
            print(f"  → High CV indicates BURSTY traffic (scraping/automation pattern)")
        elif temporal["cv_inter_arrival"] < 0.5:
            print(f"  → Low CV indicates STEADY traffic (regular browsing pattern)")
        else:
            print(f"  → Moderate CV — mixed or mildly bursty")

        print(f"\n  Connections per {temporal['bucket_size_s']}s window:")
        for bucket, count in temporal["connections_per_bucket"].items():
            t0 = bucket * temporal["bucket_size_s"]
            bar = "█" * count
            print(f"    t+{t0:>4}s: {count:>3} {bar}")
    else:
        print("  (insufficient SYN data)")

    # === Finding 7: Connection reuse ===
    hr("FINDING 7: CONNECTION REUSE vs ONE-SHOT")
    heavy, single = analyze_connection_reuse(destinations)
    if heavy:
        print(f"\n  Repeated-connection destinations ({len(heavy)} IPs):")
        for e in heavy:
            sni = f"  ({e['sni']})" if e["sni"] else ""
            print(f"    {e['ip']:<22} {e['tcp_syns']:>3} connections  {e['total_packets']:>5} pkts{sni}")
    if single:
        print(f"\n  Single-connection destinations ({len(single)} IPs):")
        for e in single:
            sni = f"  ({e['sni']})" if e["sni"] else ""
            print(f"    {e['ip']:<22}   1 connection   {e['total_packets']:>5} pkts{sni}")
    total_conns = sum(e["tcp_syns"] for e in heavy) + len(single)
    if total_conns > 0:
        reuse_pct = sum(e["tcp_syns"] for e in heavy) / total_conns * 100
        print(f"\n  {reuse_pct:.0f}% of connections target repeatedly-accessed IPs")

    # === Finding 8: TLS fingerprints ===
    hr("FINDING 8: TLS CLIENT HELLO FINGERPRINT DIVERSITY")
    tls_fps = analyze_tls_fingerprints(pcap)
    n_fp = len(tls_fps)
    total_hellos = sum(len(v) for v in tls_fps.values())
    print(f"\n  {total_hellos} Client Hellos observed, {n_fp} distinct cipher suite fingerprint(s)")
    for fp, entries in sorted(tls_fps.items(), key=lambda x: -len(x[1])):
        dsts = set(e["dst"] for e in entries)
        snis = set(e["sni"] for e in entries if e["sni"])
        print(f"\n  Fingerprint ({len(entries)} hellos, {len(dsts)} unique dests):")
        if fp == "(truncated)":
            print(f"    Cipher suites: (not captured — pcap snaplen too short)")
        else:
            suites = fp.split(",")
            # Check for GREASE values (0x?a?a pattern)
            has_grease = any(s.strip().endswith("a") and len(s.strip()) == 6
                            and s.strip()[2] == s.strip()[4] for s in suites)
            print(f"    Cipher suites: {', '.join(suites[:6])}{'...' if len(suites) > 6 else ''}")
            if has_grease:
                print(f"    → Contains GREASE values (Chromium-based TLS stack)")
            print(f"    Suite count: {len(suites)}")
        if snis:
            print(f"    SNIs seen: {', '.join(snis)}")
        print(f"    Destinations: {', '.join(sorted(dsts)[:5])}{'...' if len(dsts) > 5 else ''}")

    if n_fp > 1:
        real_fps = {k: v for k, v in tls_fps.items() if k != "(truncated)"}
        if len(real_fps) > 1:
            print(f"\n  → Multiple distinct TLS fingerprints suggest DIFFERENT CLIENTS behind the proxy")
        elif len(real_fps) == 1:
            print(f"\n  → Only 1 visible fingerprint (most hellos truncated) — inconclusive")
    elif n_fp == 1 and "(truncated)" not in tls_fps:
        print(f"\n  → Single fingerprint suggests ONE CLIENT or uniform automation tool")

    # === Finding 9: UDP packet sizes ===
    hr("FINDING 9: UDP TUNNEL PACKET SIZE DISTRIBUTION")
    if gateways:
        udp_stats = analyze_udp_sizes(pcap, proxy_ip, gateways)
        if udp_stats:
            print(f"\n  Packets analyzed: {udp_stats['count']}")
            print(f"  Size range: {udp_stats['min']} — {udp_stats['max']} bytes (UDP payload)")
            print(f"  Mean: {udp_stats['mean']} bytes  |  Median: {udp_stats['median']} bytes")
            print(f"  Unique sizes: {udp_stats['unique_sizes']} ({udp_stats['unique_ratio']:.1%} of packets)")
            print(f"\n  Most common sizes:")
            for size, count in udp_stats["top_5_sizes"]:
                pct = count / udp_stats["count"] * 100
                print(f"    {size:>6} bytes  ×{count:>4}  ({pct:.1f}%)")
            if udp_stats["likely_padded"]:
                print(f"\n  → Low size diversity suggests PADDING (traffic obfuscation)")
            else:
                print(f"\n  → High size diversity suggests NO PADDING (variable payload sizes)")
        else:
            print("  (no UDP tunnel data)")

    # === Finding 10: DNS ===
    hr("FINDING 10: DNS QUERY ANALYSIS")
    dns_data = analyze_dns(pcap)
    if dns_data:
        print(f"\n  {len(dns_data)} unique domain(s) queried:\n")
        for name, info in sorted(dns_data.items(), key=lambda x: -x[1]["query_count"]):
            resolved = ", ".join(sorted(info["resolved_ips"])) if info["resolved_ips"] else "(no response captured)"
            print(f"  {name}")
            print(f"    Queries: {info['query_count']}  |  Resolved to: {resolved}")

            # Cross-reference with destination list
            matched = [ip for ip in info["resolved_ips"] if ip in destinations]
            unmatched = [ip for ip in info["resolved_ips"] if ip not in destinations and ip not in gateways]
            if matched:
                print(f"    → Traffic observed to: {', '.join(matched)}")
            if unmatched:
                print(f"    → Resolved but NO traffic to: {', '.join(unmatched)} (queried but not connected)")
    else:
        print("  (no DNS data in capture)")

    # === Finding 11: Connection security ===
    hr("FINDING 11: CONNECTION SECURITY (TLS vs PLAINTEXT)")
    tls_confirmed, no_data, plaintext = analyze_connection_security(
        pcap, proxy_ip, destinations)

    total_streams = len(tls_confirmed) + len(no_data) + len(plaintext)
    print(f"\n  {total_streams} TCP streams total:\n")
    print(f"    TLS-confirmed:     {len(tls_confirmed):>3}  (encrypted data exchanged)")
    print(f"    No data exchanged: {len(no_data):>3}  (TCP handshake only, then closed)")
    print(f"    Plaintext:         {len(plaintext):>3}  (unencrypted data exchanged)")

    if plaintext:
        print(f"\n  ⚠ PLAINTEXT connections:")
        for e in plaintext:
            sni = f"  ({e['sni']})" if e["sni"] else ""
            print(f"    stream {e['stream']:<4}  {e['remote_ip']:<22} port {e['dst_port']}{sni}")

    if no_data:
        print(f"\n  Aborted/no-data connections:")
        for e in no_data:
            sni = f"  ({e['sni']})" if e["sni"] else ""
            print(f"    stream {e['stream']:<4}  {e['remote_ip']:<22} port {e['dst_port']}{sni}")

    if total_streams > 0 and not plaintext:
        print(f"\n  → ALL connections that exchanged data used TLS — no plaintext observed")

    print(f"\n{'=' * 70}")
    print(f" ANALYSIS COMPLETE")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
