#!/usr/bin/env python3
"""
Python Zero-Copy Proxy (os.splice)
==================================
Uses the Linux `splice` system call natively available in Python 3.10+
to achieve true zero-copy relaying without eBPF or Rust complexities.

Data flows: Socket Buffer -> Kernel Pipe -> Socket Buffer
It never enters Python user-space memory.
"""

import os
import socket
import threading
import struct
import sys
import json

IPC_DAEMON_ADDR = ('127.0.0.1', 10053)

def notify_cloak_daemon(client_addr, proxy_ephemeral_port, target_host, target_port):
    """Send a UDP JSON payload to the cloak daemon mapping the server flow back to the client."""
    try:
        mapping = {
            'client_ip': client_addr[0],
            'client_port': client_addr[1],
            'proxy_sport': proxy_ephemeral_port,
            'target_host': target_host,
            'target_port': target_port
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
    except Exception as e:
        return None

def splice_loop(src_sock, dst_sock):
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
        # Fallback for Python < 3.10 or non-Linux
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
    try:
        client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        target = socks5_handshake(client_sock)
        if target is None:
            client_sock.close()
            return
        
        target_host, target_port = target
        
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # Reserve the local ephemeral port before the handshake starts so the
        # daemon has the mapping when it sees the server SYN-ACK.
        server_sock.bind(('0.0.0.0', 0))
        proxy_sport = server_sock.getsockname()[1]
        notify_cloak_daemon(addr, proxy_sport, target_host, target_port, extra_delay=EXTRA_DELAY)
        server_sock.connect((target_host, target_port))
        
        reply = b'\x05\x00\x00\x01' + b'\x00\x00\x00\x00' + b'\x00\x00'
        client_sock.sendall(reply)
        
        # Start zero-copy splice threads
        t1 = threading.Thread(target=splice_loop, args=(client_sock, server_sock), daemon=True)
        t2 = threading.Thread(target=splice_loop, args=(server_sock, client_sock), daemon=True)
        
        t1.start()
        t2.start()
        
        t1.join()
        t2.join()
        
    except Exception as e:
        import traceback
        pass
    finally:
        try:
            client_sock.close()
        except:
            pass
        try:
            server_sock.close()
        except:
            pass

def notify_cloak_daemon(client_addr, proxy_ephemeral_port, target_host, target_port, extra_delay=0):
    """Send a UDP JSON payload to the cloak daemon mapping the server flow back to the client."""
    try:
        mapping = {
            'client_ip': client_addr[0],
            'client_port': client_addr[1],
            'proxy_sport': proxy_ephemeral_port,
            'target_host': target_host,
            'target_port': target_port,
            'extra_delay': extra_delay
        }
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(json.dumps(mapping).encode('utf-8'), IPC_DAEMON_ADDR)
        sock.close()
    except Exception as e:
        print(f"Failed to notify IPC daemon: {e}")

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=1080)
    parser.add_argument('--extra-delay', type=float, default=0.0, help='Extra RTT offset in ms')
    args = parser.parse_args()

    global EXTRA_DELAY
    EXTRA_DELAY = args.extra_delay

    print(f"Python Zero-Copy Splicing Proxy on port {args.port} (Extra Delay: {EXTRA_DELAY}ms)")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    listener.bind(('0.0.0.0', 1080))
    listener.listen(128)

    try:
        while True:
            client_sock, addr = listener.accept()
            client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            t = threading.Thread(target=handle_connection, args=(client_sock, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        listener.close()

if __name__ == '__main__':
    main()
