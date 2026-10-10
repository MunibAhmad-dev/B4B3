#!/usr/bin/env python3
"""
mitm_proxy.py — asyncio TLS MITM CONNECT proxy
Requires: pip install cryptography
Usage:
  python mitm_proxy.py gen-ca
  python mitm_proxy.py [--port 8080] [--ca-cert ca.crt] [--ca-key ca.key] [--log-file out.log]
"""

import argparse
import asyncio
import datetime
import ipaddress
import logging
import ssl
import sys
import tempfile
import os

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    print("Install cryptography: pip install cryptography", file=sys.stderr)
    sys.exit(1)

CA_CERT_FILE = "ca.crt"
CA_KEY_FILE  = "ca.key"
LOG_FILE     = None

# ─── CA generation ────────────────────────────────────────────────────────────

def gen_rsa_key(bits=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)

def save_key(key, path):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))

def save_cert(cert, path):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def load_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def gen_ca(cert_path=CA_CERT_FILE, key_path=CA_KEY_FILE):
    key  = gen_rsa_key()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "MITMProxy CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Lab CA"),
    ])
    now = datetime.datetime.utcnow()
    cert = (x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
    save_key(key, key_path)
    save_cert(cert, cert_path)
    print(f"[+] CA cert: {cert_path}")
    print(f"[+] CA key:  {key_path}")
    print(f"    Add {cert_path} to your OS/browser trust store to avoid cert warnings.")

def gen_leaf_cert(hostname: str, ca_cert, ca_key):
    """Generate a leaf cert signed by our CA for the given hostname."""
    key = gen_rsa_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.utcnow()

    # SAN extension
    try:
        san = x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(hostname))])
    except ValueError:
        san = x509.SubjectAlternativeName([x509.DNSName(hostname)])

    cert = (x509.CertificateBuilder()
        .subject_name(name).issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(san, critical=False)
        .sign(ca_key, hashes.SHA256()))
    return cert, key

# ─── Logging ──────────────────────────────────────────────────────────────────

log = logging.getLogger("mitm")

def log_traffic(direction: str, host: str, data: bytes):
    line = f"[{direction}] {host}  {len(data)} bytes"
    if data[:4].isascii():
        preview = data[:120].decode("utf-8", errors="replace").replace("\r\n", " | ")
        line += f"  {preview}"
    log.info(line)
    if LOG_FILE:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")

# ─── Proxy core ───────────────────────────────────────────────────────────────

async def relay(reader, writer, label, host):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            log_traffic(label, host, data)
            writer.write(data)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
        pass
    finally:
        writer.close()

async def handle_client(reader, writer, ca_cert, ca_key):
    try:
        first = await reader.readuntil(b"\r\n")
    except asyncio.IncompleteReadError:
        writer.close(); return

    line = first.decode("utf-8", errors="replace").strip()
    log.debug(f"First line: {line}")

    # Drain headers
    while True:
        try:
            h = await reader.readuntil(b"\r\n")
        except asyncio.IncompleteReadError:
            break
        if h == b"\r\n":
            break

    if not line.startswith("CONNECT "):
        writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await writer.drain()
        writer.close()
        return

    host_port = line.split()[1]
    host, _, port_str = host_port.rpartition(":")
    port = int(port_str) if port_str.isdigit() else 443
    host = host.strip("[]")

    # Connect to real server
    try:
        up_reader, up_writer = await asyncio.open_connection(host, port)
    except OSError as e:
        log.warning(f"Cannot connect to {host}:{port}: {e}")
        writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await writer.drain()
        writer.close()
        return

    # Tell client tunnel is established
    writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
    await writer.drain()

    # Wrap client side with leaf cert (TLS termination)
    leaf_cert, leaf_key = gen_leaf_cert(host, ca_cert, ca_key)

    # Write leaf cert+key to temp files (ssl.SSLContext needs file paths)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf, \
         tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        cf.write(leaf_cert.public_bytes(serialization.Encoding.PEM))
        cf.write(ca_cert.public_bytes(serialization.Encoding.PEM))  # chain
        kf.write(leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        cert_tmp, key_tmp = cf.name, kf.name

    try:
        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        client_ctx.load_cert_chain(cert_tmp, key_tmp)

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        server_ctx.check_hostname = False
        server_ctx.verify_mode    = ssl.CERT_NONE

        tls_reader, tls_writer = await asyncio.open_connection(
            sock=writer.transport.get_extra_info("socket"),
            ssl=client_ctx,
            server_side=True)

        up_tls_reader, up_tls_writer = await asyncio.open_connection(
            host, port,
            ssl=server_ctx,
            server_hostname=host)

        log.info(f"TLS MITM active: {host}:{port}")

        await asyncio.gather(
            relay(tls_reader,    up_tls_writer, f"C->{host}", host),
            relay(up_tls_reader, tls_writer,    f"S->{host}", host),
        )
    except ssl.SSLError as e:
        log.debug(f"SSL error for {host}: {e}")
    finally:
        os.unlink(cert_tmp)
        os.unlink(key_tmp)
        try: up_writer.close()
        except Exception: pass

# ─── Entry point ─────────────────────────────────────────────────────────────

async def main_serve(port, ca_cert_path, ca_key_path):
    ca_cert = load_cert(ca_cert_path)
    ca_key  = load_key(ca_key_path)

    async def handler(reader, writer):
        await handle_client(reader, writer, ca_cert, ca_key)

    server = await asyncio.start_server(handler, "0.0.0.0", port)
    log.info(f"MITM proxy listening on 0.0.0.0:{port}")
    log.info(f"Configure your browser proxy: 127.0.0.1:{port}")
    async with server:
        await server.serve_forever()

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "gen-ca":
        gen_ca()
        return

    ap = argparse.ArgumentParser(description="TLS MITM CONNECT proxy")
    ap.add_argument("--port",     type=int, default=8080)
    ap.add_argument("--ca-cert",  default=CA_CERT_FILE)
    ap.add_argument("--ca-key",   default=CA_KEY_FILE)
    ap.add_argument("--log-file", default=None)
    ap.add_argument("--debug",    action="store_true")
    args = ap.parse_args()

    global LOG_FILE
    LOG_FILE = args.log_file
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(message)s",
        datefmt="%H:%M:%S")

    if not os.path.exists(args.ca_cert) or not os.path.exists(args.ca_key):
        print(f"[!] CA files not found. Run: python mitm_proxy.py gen-ca", file=sys.stderr)
        sys.exit(1)

    try:
        asyncio.run(main_serve(args.port, args.ca_cert, args.ca_key))
    except KeyboardInterrupt:
        print("\n[*] Stopped")

if __name__ == "__main__":
    main()
