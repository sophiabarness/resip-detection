#!/usr/bin/env python3
"""
Pre-flight Cloak Daemon
=======================
Intercepts server-bound ACKs and delays them by the end-to-end RTT
measured by the pre-flight proxy probe.
"""

import time
import threading
import logging
import socket
import json
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

NFQUEUE_NUM = 1
SERVER_PORT = 443

class PreflightCloakDaemon:
    def __init__(self):
        self.flow_info = {} # Maps proxy_ephemeral_port -> client_rtt_ms
        self.server_flows = {} # Tracks server SYN timing
        self.lock = threading.Lock()
        
        # Start UDP listener for IPC mappings
        self.ipc_thread = threading.Thread(target=self.ipc_listener, daemon=True)
        self.ipc_thread.start()

    def ipc_listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 10053))
        logger.info("IPC UDP Listener started on 127.0.0.1:10053")
        while True:
            try:
                data, _ = sock.recvfrom(2048)
                mapping = json.loads(data.decode('utf-8'))
                
                proxy_sport = mapping['proxy_sport']
                client_rtt = mapping.get('client_rtt_ms', 0)
                
                with self.lock:
                    self.flow_info[proxy_sport] = {
                        'client_rtt': client_rtt,
                        'client_id': (mapping['client_ip'], mapping['client_port'])
                    }
                    logger.info(f"[IPC] Mapped proxy sport {proxy_sport} to Client RTT {client_rtt:.1f}ms")
            except Exception as e:
                logger.error(f"[IPC] Error reading mapping: {e}")

    def delayed_release(self, pkt, target_ms, desc):
        now = time.time() * 1000.0
        delay = target_ms - now
        if delay > 0:
            time.sleep(delay / 1000.0)
        try:
            pkt.accept()
            logger.info(f"[CLOAK] Released {desc} at target {target_ms:.1f} (delay: {max(0, delay):.1f}ms)")
        except Exception as e:
            logger.error(f"Error accepting packet: {e}")

    def packet_callback(self, pkt):
        data = pkt.get_payload()
        try:
            ip_pkt = IP(data)
            if not ip_pkt.haslayer(TCP):
                pkt.accept()
                return
        except Exception:
            pkt.accept()
            return
        
        tcp_pkt = ip_pkt[TCP]
        now = time.time() * 1000.0

        # 1. SYN to server
        if tcp_pkt.dport == SERVER_PORT and (tcp_pkt.flags & 0x02) and not (tcp_pkt.flags & 0x10):
            flow_id = (ip_pkt.dst, tcp_pkt.dport, tcp_pkt.sport)
            with self.lock:
                self.server_flows[flow_id] = {'t1': now}

        # 2. SYN-ACK from server -> APPLY DELAY HERE
        elif tcp_pkt.sport == SERVER_PORT and (tcp_pkt.flags & 0x12) == 0x12:
            flow_id = (ip_pkt.src, tcp_pkt.sport, tcp_pkt.dport)
            proxy_ephemeral_port = tcp_pkt.dport
            
            with self.lock:
                if flow_id in self.server_flows:
                    t1 = self.server_flows[flow_id]['t1']
                    # Local relay-to-server RTT (Segment B)
                    server_rtt = now - t1
                    
                    info = self.flow_info.get(proxy_ephemeral_port)
                    reported_rtt = info['client_rtt'] if info else 0
                    
                    # Target time: t1 + end_to_end_rtt + server_rtt
                    # Note: reported_rtt is the full client-to-relay distance measured by probe.
                    # We want server to see: handshake_completion - t1 = reported_rtt + server_rtt
                    target = t1 + reported_rtt + server_rtt
                    
                    logger.info(f"[CLOAK] Holding SYN-ACK for {flow_id} until {target:.1f} (Probe RTT: {reported_rtt:.1f}ms, Server RTT: {server_rtt:.1f}ms)")
                    threading.Thread(target=self.delayed_release, args=(pkt, target, f"SYN-ACK({flow_id})")).start()
                    return

        pkt.accept()

    def run(self):
        nfqueue = NetfilterQueue()
        nfqueue.bind(NFQUEUE_NUM, self.packet_callback)
        logger.info(f"Pre-flight Cloak Daemon started on NFQUEUE {NFQUEUE_NUM}")
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            pass
        finally:
            nfqueue.unbind()

if __name__ == "__main__":
    PreflightCloakDaemon().run()
