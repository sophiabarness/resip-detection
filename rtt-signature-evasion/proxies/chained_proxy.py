#!/usr/bin/env python3
"""
Chained Zero-Copy Proxy
=======================
Extends the splice proxy to support an optional upstream SOCKS5 proxy.
Topology: Client -> Superproxy (Local) -> Exit Relay (Upstream) -> Target
"""

import os
import socket
import threading
import struct
import sys
import argparse

def recv_exact(sock, count):
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise Exception("connection closed prematurely")
        buf.extend(chunk)
    return bytes(buf)

def socks5_handshake_client(client_sock):
    """Receive SOCKS5 request from the client and return (host, port)."""
    try:
        data = recv_exact(client_sock, 2)
        if data[0] != 0x05: return None
        n_methods = data[1]
        recv_exact(client_sock, n_methods)
        client_sock.sendall(b'\x05\x00') # No auth

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

def socks5_handshake_upstream(upstream_sock, target_host, target_port):
    """Perform a SOCKS5 CONNECT request to an upstream proxy."""
    try:
        # Handshake
        upstream_sock.sendall(b'\x05\x01\x00')
        resp = recv_exact(upstream_sock, 2)
        if resp[0] != 0x05 or resp[1] != 0x00: return False

        # Connect request
        req = b'\x05\x01\x00\x03' + bytes([len(target_host)]) + target_host.encode() + struct.pack('!H', target_port)
        upstream_sock.sendall(req)
        
        resp = recv_exact(upstream_sock, 4)
        if resp[0] != 0x05 or resp[1] != 0x00: return False 
        
        # Skip binding addr/port
        atype = resp[3]
        if atype == 0x01: recv_exact(upstream_sock, 6)
        elif atype == 0x03:
            alen = recv_exact(upstream_sock, 1)[0]
            recv_exact(upstream_sock, alen + 2)
        elif atype == 0x04: recv_exact(upstream_sock, 18)
        
        return True
    except Exception:
        return False

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

def handle_connection(client_sock, addr, upstream_proxy=None):
    try:
        client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        target = socks5_handshake_client(client_sock)
        if target is None:
            client_sock.close()
            return
        
        target_host, target_port = target
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        if upstream_proxy:
            u_host, u_port = upstream_proxy
            server_sock.connect((u_host, u_port))
            if not socks5_handshake_upstream(server_sock, target_host, target_port):
                client_sock.close()
                server_sock.close()
                return
        else:
            server_sock.connect((target_host, target_port))
        
        # SOCKS5 Success response to client
        client_sock.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        
        t1 = threading.Thread(target=splice_loop, args=(client_sock, server_sock), daemon=True)
        t2 = threading.Thread(target=splice_loop, args=(server_sock, client_sock), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
    except Exception:
        pass
    finally:
        try: client_sock.close()
        except: pass
        try: server_sock.close()
        except: pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=1080)
    parser.add_argument('--upstream', type=str, help='Upstream SOCKS5 proxy (host:port)')
    args = parser.parse_args()

    upstream = None
    if args.upstream:
        h, p = args.upstream.split(':')
        upstream = (h, int(p))

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('0.0.0.0', args.port))
    listener.listen(128)
    
    print(f"Chained Splice Proxy on port {args.port}")
    if upstream:
        print(f"Forwarding to upstream: {upstream[0]}:{upstream[1]}")

    try:
        while True:
            client_sock, addr = listener.accept()
            t = threading.Thread(target=handle_connection, args=(client_sock, addr, upstream), daemon=True)
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        listener.close()

if __name__ == '__main__':
    main()
