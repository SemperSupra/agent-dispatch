#!/usr/bin/env python3
"""Disposable netfilter enforcement oracle, not USB/IP or broker proof."""
import socket
import subprocess
import threading

def tcp_server(family, address):
    sock = socket.socket(family, socket.SOCK_STREAM)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((address, 3240))
    sock.listen(4)
    sock.settimeout(2.0)
    return sock

a=tcp_server(socket.AF_INET, "127.0.0.1")
b=tcp_server(socket.AF_INET6, "::1")
accepted=[]
def accept_once(sock):
    try:
        conn,_=sock.accept()
        accepted.append(True)
        conn.close()
    except socket.timeout:
        pass
thread=threading.Thread(target=accept_once,args=(a,),daemon=True)
thread.start()

def attempt(family, dst, src=None):
    c=socket.socket(family,socket.SOCK_STREAM)
    c.settimeout(0.35)
    try:
        if src is not None:
            c.bind((src,0))
        c.connect((dst,3240))
        return True
    except (OSError,TimeoutError):
        return False
    finally:
        c.close()

try:
    if not attempt(socket.AF_INET,"127.0.0.1","127.0.0.1"):
        raise SystemExit("N2_NFT_APPROVED_IPV4=RED")
    thread.join(1.0)
    if not accepted:
        raise SystemExit("N2_NFT_APPROVED_SOCKET_NOT_ACCEPTED=RED")
    print("N2_NFT_APPROVED_IPV4=PASS", flush=True)
    if attempt(socket.AF_INET,"127.0.0.1","127.0.0.2"):
        raise SystemExit("N2_NFT_DENY_UNAPPROVED_IPV4=RED")
    print("N2_NFT_DENY_UNAPPROVED_IPV4=PASS",flush=True)
    if attempt(socket.AF_INET6,"::1"):
        raise SystemExit("N2_NFT_DENY_IPV6_BYPASS=RED")
    print("N2_NFT_DENY_IPV6_BYPASS=PASS",flush=True)
    subprocess.run(["nft","flush","chain","inet","usbnet_n2_test","input"],check=True)
    subprocess.run(["nft","add","rule","inet","usbnet_n2_test","input","tcp","dport","3240","drop"],check=True)
    if attempt(socket.AF_INET,"127.0.0.1","127.0.0.1"):
        raise SystemExit("N2_NFT_POLICY_WITHDRAWAL=RED")
    print("N2_NFT_POLICY_WITHDRAWAL=PASS",flush=True)
finally:
    a.close()
    b.close()
