#!/usr/bin/env python3
"""
Pre-flight RTT Splicing Proxy
=============================
Measures the end-to-end RTT (Client -> Relay) by sending a fake SOCKS success
reply and measuring the time until the Client sends its first data packet (TLS ClientHello).
"""

import os
import socket
import threading
import struct
import sys
import json
import time

IPC_DAEMON_ADDR = ('127.0.0.1', 10053)

def notify_cloak_daemon(client_addr, proxy_ephemeral_port, target_host, target_port, measured_rtt_ms=0):
    """Send a UDP JSON payload to the cloak daemon."""
    try:
        mapping = {
            'client_ip': client_addr[0],
            'client_port': client_addr[1],
            'proxy_sport': proxy_ephemeral_port,
            'target_host': target_host,
            'target_port': target_port,
            'client_rtt_ms': measured_rtt_ms
        }
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(json.dumps(mapping).encode('utf-8'), IPC_DAEMON_ADDR)
        sock.close()
    except Exception as e:
        print(f"Failed to notify IPC daemon: {e}")

def recv_exact(sock, count):
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise Exception("connection closed prematurely")
        buf.extend(chunk)
    return bytes(buf)

def socks5_handshake(client_sock):
    try:
        data = recv_exact(client_sock, 2)
        if data[0] != 0x05: return None
        n_methods = data[1]
        recv_exact(client_sock, n_methods)
        client_sock.sendall(b'\x05\x00')

        data = recv_exact(client_sock, 4)
        if data[0] != 0x05 or data[1] != 0x01: return None

        atype = data[3]
        if atype == 0x01:
            addr_data = recv_exact(client_sock, 4)
            target_host = socket.inet_ntoa(addr_data)
        elif atype == 0x03:
            domain_len = recv_exact(client_sock, 1)[0]
            domain = recv_exact(client_sock, domain_len).decode()
            target_host = domain
        elif atype == 0x04:
            addr_data = recv_exact(client_sock, 16)
            target_host = socket.inet_ntop(socket.AF_INET6, addr_data)
        else:
            return None

        port_data = recv_exact(client_sock, 2)
        target_port = struct.unpack('!H', port_data)[0]
        return (target_host, target_port)
    except Exception:
        return None

def splice_loop(src_sock, dst_sock, initial_data=None):
    if initial_data:
        dst_sock.sendall(initial_data)

    has_splice = hasattr(os, 'splice')
    if has_splice:
        src_fd = src_sock.fileno()
        dst_fd = dst_sock.fileno()
        r, w = os.pipe()
        try:
            while True:
                flags = getattr(os, 'SPLICE_F_MOVE', 1)
                n = os.splice(src_fd, w, 65536, flags=flags)
                if n == 0: break
                remain = n
                while remain > 0:
                    written = os.splice(r, dst_fd, remain, flags=flags)
                    remain -= written
        except Exception:
            pass
        finally:
            os.close(r)
            os.close(w)
    else:
        try:
            while True:
                data = src_sock.recv(65536)
                if not data: break
                dst_sock.sendall(data)
        except Exception:
            pass
    
    try: src_sock.shutdown(socket.SHUT_RD)
    except: pass
    try: dst_sock.shutdown(socket.SHUT_WR)
    except: pass

def handle_connection(client_sock, addr):
    server_sock = None
    try:
        client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        target = socks5_handshake(client_sock)
        if target is None:
            client_sock.close()
            return
        
        target_host, target_port = target
        
        # --- PRE-FLIGHT PROBE START ---
        t_start = time.time()
        # Send Fake SOCKS Success
        reply = b'\x05\x00\x00\x01' + b'\x00\x00\x00\x00' + b'\x00\x00'
        client_sock.sendall(reply)
        
        # Wait for the first data packet (e.g., TLS ClientHello)
        # We read it into memory to measure RTT, then forward it later.
        initial_data = client_sock.recv(16384)
        t_end = time.time()
        
        measured_rtt_ms = (t_end - t_start) * 1000.0
        print(f"[*] Pre-flight RTT for {addr}: {measured_rtt_ms:.2f} ms")
        # --- PRE-FLIGHT PROBE END ---
        
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        server_sock.bind(('0.0.0.0', 0))
        proxy_sport = server_sock.getsockname()[1]
        
        # Notify daemon with the measured RTT
        notify_cloak_daemon(addr, proxy_sport, target_host, target_port, measured_rtt_ms=measured_rtt_ms)
        
        # Now connect to real server
        server_sock.connect((target_host, target_port))
        
        # Start splicing
        t1 = threading.Thread(target=splice_loop, args=(client_sock, server_sock, initial_data), daemon=True)
        t2 = threading.Thread(target=splice_loop, args=(server_sock, client_sock), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
    except Exception as e:
        pass
    finally:
        try: client_sock.close()
        except: pass
        if server_sock:
            try: server_sock.close()
            except: pass

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=1080)
    args = parser.parse_args()

    print(f"Pre-flight RTT Proxy started on port {args.port}")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('0.0.0.0', args.port))
    listener.listen(128)

    try:
        while True:
            client_sock, addr = listener.accept()
            t = threading.Thread(target=handle_connection, args=(client_sock, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        listener.close()

if __name__ == '__main__':
    main()
