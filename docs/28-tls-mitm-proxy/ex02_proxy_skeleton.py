"""
Exercise 02 — HTTP CONNECT MITM Proxy (asyncio)
-------------------------------------------------
Build a proxy that:
  1. Listens for HTTP CONNECT requests (standard HTTPS proxy protocol).
  2. Responds "200 Connection established".
  3. Upgrades the client connection to TLS using a dynamically generated
     fake cert (signed by the CA from ex01).
  4. Opens a real TLS connection to the target server.
  5. Relays data bidirectionally, printing plaintext to stdout.

Install:
  pip install cryptography

Tasks:
1. Implement handle_connect(reader, writer) — parses the CONNECT line,
   generates a leaf cert, does TLS handshake with the client.
2. Implement connect_to_server(host, port) — opens an SSL connection.
3. Implement relay(src, dst, label) — asyncio pipe loop.
4. Implement log_http(data, direction) — detect HTTP in the relayed data
   and pretty-print the method, URL, and response code.
5. Start the proxy on port 8080.

Test:
  python ex02_proxy_skeleton.py &
  curl --proxy http://127.0.0.1:8080 --cacert mitmproxy_ca.crt.pem https://httpbin.org/get

BONUS:
- Cache generated leaf certs to avoid regenerating for the same host.
- Add --dump-body flag to also log response bodies.
- Save all traffic to a HAR file for later replay.
"""

import asyncio
import ssl
import sys
import os
import io
import datetime
import tempfile

PROXY_PORT = 8080
CA_KEY_PEM  = "mitmproxy_ca.key.pem"
CA_CERT_PEM = "mitmproxy_ca.crt.pem"

# ---------- Load CA from ex01 ----------
def load_ca():
    # YOUR CODE HERE:
    # from cryptography.hazmat.primitives.serialization import load_pem_private_key
    # from cryptography import x509
    # with open(CA_KEY_PEM, "rb") as f:  ca_key  = load_pem_private_key(f.read(), None)
    # with open(CA_CERT_PEM, "rb") as f: ca_cert = x509.load_pem_x509_certificate(f.read())
    # return ca_key, ca_cert
    return None, None  # replace


# ---------- TODO 1: handle_connect ----------
async def handle_connect(reader, writer):
    line = await reader.readline()
    if not line:
        writer.close(); return
    parts = line.decode().strip().split()
    if len(parts) < 2 or parts[0].upper() != "CONNECT":
        writer.close(); return

    # Drain remaining headers
    while True:
        hdr = await reader.readline()
        if hdr in (b"\r\n", b"\n", b""):
            break

    host_port = parts[1]
    host, _, port_str = host_port.rpartition(":")
    port = int(port_str) if port_str else 443

    writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
    await writer.drain()

    ca_key, ca_cert = load_ca()
    if not ca_key:
        print(f"[-] CA not loaded — cannot intercept {host}")
        writer.close(); return

    # YOUR CODE HERE:
    # 1. from ex01 import generate_leaf
    # 2. leaf_key, leaf_cert = generate_leaf(ca_key, ca_cert, host)
    # 3. Write key+cert to temp files
    # 4. Build ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), load cert chain
    # 5. Upgrade writer transport to TLS
    # (asyncio SSLContext upgrade is done via start_tls or by creating a new SSL transport)

    print(f"[+] CONNECT {host}:{port}  (TLS intercept not fully implemented)")
    writer.close()


# ---------- TODO 2: connect_to_server ----------
async def connect_to_server(host, port):
    # YOUR CODE HERE:
    # ctx = ssl.create_default_context()
    # return await asyncio.open_connection(host, port, ssl=ctx)
    raise NotImplementedError("connect_to_server not implemented")


# ---------- TODO 3: relay ----------
async def relay(src_reader, dst_writer, label):
    # YOUR CODE HERE:
    # while True:
    #     data = await src_reader.read(4096)
    #     if not data: break
    #     log_http(data, label)
    #     dst_writer.write(data)
    #     await dst_writer.drain()
    pass


# ---------- TODO 4: log_http ----------
def log_http(data, direction):
    try:
        text = data.decode("utf-8", errors="replace")
        first_line = text.split("\r\n")[0] if "\r\n" in text else text.split("\n")[0]
        if first_line.startswith(("GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS")):
            print(f"  [{direction}] {first_line}")
        elif first_line.startswith("HTTP/"):
            print(f"  [{direction}] {first_line}")
    except Exception:
        pass


async def handle_client(reader, writer):
    await handle_connect(reader, writer)


async def main():
    server = await asyncio.start_server(handle_client, "127.0.0.1", PROXY_PORT)
    print(f"[*] MITM Proxy listening on 127.0.0.1:{PROXY_PORT}")
    print(f"[*] Configure your HTTP proxy to 127.0.0.1:{PROXY_PORT}")
    print(f"[*] Install CA: certutil -addstore Root {CA_CERT_PEM}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    if not os.path.exists(CA_KEY_PEM):
        print(f"[-] CA not found. Run ex01_ca_generator.py first.")
        sys.exit(1)
    asyncio.run(main())
