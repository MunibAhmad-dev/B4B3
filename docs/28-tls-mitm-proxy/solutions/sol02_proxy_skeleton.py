"""
Solution 02 — Asyncio HTTPS MITM Proxy
----------------------------------------
Intercepts HTTPS CONNECT tunnels, presents a dynamically generated leaf
certificate (signed by our CA), and relays decrypted traffic to the real
server while logging HTTP requests/responses.

Prerequisites:
    pip install cryptography

Setup (run once):
    python sol01_ca_generator.py      # generates mitmproxy_ca.crt.pem + key
    certutil -addstore Root mitmproxy_ca.crt.pem   # trust CA (admin prompt)

Then configure your browser/app to use 127.0.0.1:8080 as HTTP proxy.

Usage:
    python sol02_proxy_skeleton.py [port]    # default port 8080
"""

import asyncio
import ssl
import os
import sys
import datetime
import ipaddress
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

# ── Load CA from PEM files ────────────────────────────────────────────────────
def load_ca(cert_path="mitmproxy_ca.crt.pem", key_path="mitmproxy_ca.key.pem"):
    """Load CA certificate and private key from PEM files."""
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        raise FileNotFoundError(
            f"CA files not found: {cert_path}, {key_path}\n"
            "Run: python sol01_ca_generator.py"
        )
    with open(cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    return ca_cert, ca_key


# ── Generate a leaf certificate signed by our CA ──────────────────────────────
def generate_leaf_cert(ca_cert, ca_key, hostname):
    """
    Generate a fresh RSA-2048 cert for `hostname`, signed by the CA.
    Returns (cert_pem_bytes, key_pem_bytes).
    """
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Build SAN — handle IP addresses and DNS names
    try:
        ip = ipaddress.ip_address(hostname)
        san = x509.SubjectAlternativeName([
            x509.IPAddress(ip),
        ])
    except ValueError:
        san = x509.SubjectAlternativeName([
            x509.DNSName(hostname),
            x509.DNSName(f"*.{hostname}"),
        ])

    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(seconds=60))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(san, critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem  = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


# ── Bidirectional relay ───────────────────────────────────────────────────────
async def relay(reader, writer, label=""):
    """Relay bytes from reader to writer until EOF."""
    try:
        while True:
            data = await reader.read(16384)
            if not data:
                break
            writer.write(data)
            await writer.drain()
            # Log first line of HTTP traffic
            await log_http(data, label)
    except (asyncio.IncompleteReadError, ConnectionResetError, ssl.SSLError, BrokenPipeError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


# ── Log first line of HTTP request/response ───────────────────────────────────
async def log_http(data: bytes, direction: str):
    """Extract and print the first HTTP line (request line or status line)."""
    try:
        text = data.decode("utf-8", errors="replace")
        first_line = text.split("\r\n")[0]
        if first_line.strip():
            print(f"  {direction} {first_line}")
    except Exception:
        pass


# ── Handle a CONNECT tunnel ───────────────────────────────────────────────────
async def handle_connect(client_reader, client_writer):
    """
    Handle an HTTP CONNECT request:
      1. Parse CONNECT host:port HTTP/1.x
      2. Respond with 200 Connection established
      3. Perform TLS handshake with client using a fake cert
      4. Connect to the real server with TLS
      5. Relay traffic bidirectionally, logging HTTP lines
    """
    try:
        # 1. Read CONNECT line
        line = await asyncio.wait_for(client_reader.readline(), timeout=10)
        line = line.decode("utf-8", errors="replace").strip()
        if not line.upper().startswith("CONNECT "):
            client_writer.close()
            return

        parts = line.split()           # ['CONNECT', 'example.com:443', 'HTTP/1.1']
        if len(parts) < 2:
            client_writer.close()
            return

        host_port = parts[1]
        if ":" in host_port:
            host, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        else:
            host, port = host_port, 443

        # Drain remaining request headers
        while True:
            hdr = await asyncio.wait_for(client_reader.readline(), timeout=5)
            if hdr in (b"\r\n", b"\n", b""):
                break

        # 2. Tell client the tunnel is open
        client_writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await client_writer.drain()

        print(f"[+] CONNECT {host}:{port}")

        # 3. Generate leaf cert and wrap client connection in TLS
        ca_cert, ca_key = _ca_cache
        cert_pem, key_pem = generate_leaf_cert(ca_cert, ca_key, host)

        # Write cert+key to temp files (ssl.SSLContext needs file paths or wrap_socket)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf:
            cf.write(cert_pem); certfile = cf.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
            kf.write(key_pem); keyfile = kf.name

        try:
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(certfile, keyfile)

            tls_client_reader, tls_client_writer = await asyncio.wait_for(
                asyncio.get_event_loop().create_connection(
                    lambda: asyncio.StreamReaderProtocol(asyncio.StreamReader()),
                    ssl=server_ctx,
                    sock=client_writer.transport.get_extra_info("socket"),
                ),
                timeout=10,
            )
        except Exception:
            # Simpler approach: upgrade the existing transport
            tls_client_reader, tls_client_writer = await _upgrade_to_tls_server(
                client_reader, client_writer, certfile, keyfile
            )
        finally:
            os.unlink(certfile)
            os.unlink(keyfile)

        # 4. Connect to real upstream server with TLS
        try:
            upstream_ctx = ssl.create_default_context()
            # For interception, we verify upstream certificate normally
            srv_reader, srv_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=upstream_ctx,
                                        server_hostname=host),
                timeout=10,
            )
        except Exception as e:
            print(f"  [-] Upstream connect failed: {e}")
            tls_client_writer.close()
            return

        # 5. Relay in both directions
        await asyncio.gather(
            relay(tls_client_reader, srv_writer, f"→ {host}"),
            relay(srv_reader, tls_client_writer, f"← {host}"),
            return_exceptions=True,
        )
        srv_writer.close()

    except Exception as e:
        print(f"  [!] Error: {e}")
    finally:
        try:
            client_writer.close()
        except Exception:
            pass


async def _upgrade_to_tls_server(client_reader, client_writer, certfile, keyfile):
    """
    Upgrade an existing plaintext asyncio connection to TLS (server-side).
    Returns new (reader, writer) over TLS.
    """
    loop = asyncio.get_event_loop()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)

    sock = client_writer.transport.get_extra_info("socket")
    client_writer.transport.pause_reading()

    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    transport, _ = await loop.create_connection(
        lambda: protocol, ssl=ctx, sock=sock, server_side=True
    )
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
    return reader, writer


# ── Shared CA cache ───────────────────────────────────────────────────────────
_ca_cache = None


# ── Main ──────────────────────────────────────────────────────────────────────
async def main(port: int):
    global _ca_cache
    _ca_cache = load_ca()

    server = await asyncio.start_server(handle_connect, "127.0.0.1", port)
    print(f"[*] MITM proxy listening on 127.0.0.1:{port}")
    print(f"[*] Configure browser proxy: 127.0.0.1:{port}")
    print(f"[*] CA cert: mitmproxy_ca.crt.pem  (trust it in your browser/OS)")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    try:
        asyncio.run(main(port))
    except KeyboardInterrupt:
        print("\n[*] Proxy stopped")
