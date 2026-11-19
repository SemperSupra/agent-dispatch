#!/usr/bin/env python3
"""Network revocation safety oracle: established sessions survive naive ACL withdrawal."""
import socket, subprocess, threading, struct, time

def nft(script):
    subprocess.run(["nft", "-f", "-"], input=script, text=True, check=True)

nft("""table inet usbnet_n3 {
 chain input {
   type filter hook input priority 0; policy accept;
   tcp dport 3240 ct state established accept
   tcp dport 3240 ip saddr 127.0.0.1 accept
   tcp dport 3240 drop
 }
}""")
srv=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1",3240))
srv.listen(2)
srv.settimeout(5)
control=threading.Event()
accepted=[]
def serve():
    c,_=srv.accept()
    accepted.append(c)
    c.settimeout(5)
    try:
        while not control.is_set():
            block=c.recv(1)
            if not block: break
            c.sendall(block)
    except OSError:
        pass
thread=threading.Thread(target=serve,daemon=True)
thread.start()
client=socket.create_connection(("127.0.0.1",3240), timeout=3)
client.settimeout(2)
def exchange(v):
    client.sendall(v)
    if client.recv(1)!=v: raise RuntimeError("exchange differs")
try:
    exchange(b"A")
    print("N3_ESTABLISHED_TCP_BASELINE=PASS",flush=True)
    # Removing the source allow rule does not revoke established sockets if
    # an earlier ct established accept is still present.
    nft("""flush chain inet usbnet_n3 input
add rule inet usbnet_n3 input tcp dport 3240 ct state established accept
add rule inet usbnet_n3 input tcp dport 3240 drop""")
    exchange(b"B")
    print("N3_EXISTING_SOCKET_SURVIVES_ACL_WITHDRAWAL=PASS",flush=True)
    bad=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    bad.settimeout(.4)
    try:
        bad.connect(("127.0.0.1",3240))
        raise RuntimeError("new socket opened after withdrawal")
    except (ConnectionError, TimeoutError, OSError):
        print("N3_NEW_SOCKET_DENIED=PASS",flush=True)
    finally: bad.close()
    # Broker-side active teardown is mandatory; use RST to make it
    # independently observable at consumer. Does not substitute for USB detach.
    if not accepted: raise RuntimeError("missing accepted socket")
    control.set()
    accepted[0].setsockopt(socket.SOL_SOCKET,socket.SO_LINGER, struct.pack("ii",1,0))
    accepted[0].close()
    time.sleep(.05)
    try:
        client.sendall(b"C")
        got=client.recv(1)
        if got: raise RuntimeError("revoked socket still carried payload")
    except (ConnectionError, TimeoutError, OSError):
        pass
    print("N3_EXPLICIT_SOCKET_TEARDOWN=PASS",flush=True)
finally:
    control.set()
    client.close()
    srv.close()
    nft("delete table inet usbnet_n3")
print("N3_NFT_REVOKE_AND_CLEANUP=PASS",flush=True)
print("N3_REAL_USBIP_BROKER_LEASE_FENCING=NOT_TESTED",flush=True)
