#!/usr/bin/env python3
"""
Standalone Cloaking Daemon
Intercepts packets via NFQUEUE and delays server-bound ACKs (Zero-Gap).
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
CLIENT_PORT = 1080
SERVER_PORT = 443

class CloakDaemon:
    def __init__(self):
        self.client_rtts = {} 
        self.server_flows = {}
        self.flow_mappings = {} # Maps proxy_ephemeral_port -> client_id
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
                data, _ = sock.recvfrom(1024)
                mapping = json.loads(data.decode('utf-8'))
                
                # Unpack the mapping
                client_ip = mapping['client_ip']
                client_port = mapping['client_port']
                proxy_sport = mapping['proxy_sport']
                extra_delay = mapping.get('extra_delay', 0)
                
                client_id = (client_ip, client_port)
                
                with self.lock:
                    self.flow_mappings[proxy_sport] = {'client_id': client_id, 'extra_delay': extra_delay}
                    logger.debug(f"[IPC] Mapped proxy sport {proxy_sport} to client {client_id} (extra: {extra_delay}ms)")
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
                    rtt_2b = now - t1
                    
                    target_info = self.flow_mappings.get(proxy_ephemeral_port)
                    target_client = target_info['client_id'] if target_info else None
                    extra_delay = target_info['extra_delay'] if target_info else 0
                    
                    latest_2a = 0
                    if target_client and target_client in self.client_rtts and 'rtt_2a' in self.client_rtts[target_client]:
                        latest_2a = self.client_rtts[target_client]['rtt_2a']
                    else:
                        for cid, c_data in self.client_rtts.items():
                            if 'rtt_2a' in c_data: latest_2a = c_data['rtt_2a']

                    # The target time is t1 + 2a + 2b + extra
                    target = t1 + latest_2a + rtt_2b + extra_delay
                    logger.info(f"[CLOAK] Holding SYN-ACK for {flow_id} until {target:.1f} (2a={latest_2a:.1f}, 2b={rtt_2b:.1f}, extra={extra_delay:.1f})")
                    threading.Thread(target=self.delayed_release, args=(pkt, target, f"SYN-ACK({flow_id})")).start()
                    return

        # 3. SYN-ACK to client
        elif tcp_pkt.sport == CLIENT_PORT and (tcp_pkt.flags & 0x12) == 0x12:
            client_id = (ip_pkt.dst, tcp_pkt.dport)
            with self.lock:
                self.client_rtts[client_id] = {'sa_time': now}

        # 4. ACK from client
        elif tcp_pkt.dport == CLIENT_PORT and (tcp_pkt.flags & 0x10) and not (tcp_pkt.flags & 0x02) and len(tcp_pkt.payload) == 0:
            client_id = (ip_pkt.src, tcp_pkt.sport)
            with self.lock:
                if client_id in self.client_rtts and 'sa_time' in self.client_rtts[client_id]:
                    if 'rtt_2a' not in self.client_rtts[client_id]:
                        self.client_rtts[client_id]['rtt_2a'] = now - self.client_rtts[client_id]['sa_time']

        pkt.accept()

    def run(self):
        nfqueue = NetfilterQueue()
        nfqueue.bind(NFQUEUE_NUM, self.packet_callback)
        logger.info(f"Cloak Daemon started on NFQUEUE {NFQUEUE_NUM}")
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            pass
        finally:
            nfqueue.unbind()

if __name__ == "__main__":
    CloakDaemon().run()
