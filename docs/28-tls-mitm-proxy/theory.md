# Module 28 — TLS MITM Proxy

## What it is and why it matters

A TLS MITM (Man-in-the-Middle) proxy intercepts HTTPS traffic between a client
and server. Security uses:

- **Pentest / Red team**: intercept and modify HTTPS API calls during an engagement.
- **Bug bounty**: inspect traffic of thick clients that don't have a browser devtools.
- **Blue team / SOC**: SSL inspection at the perimeter (decrypt then re-encrypt).
- **Malware analysis**: understand what an implant sends even though it uses HTTPS.
- **Fuzzing web APIs**: replay + mutate intercepted requests.

---

## 2. How TLS MITM Works

```
Normal HTTPS:
  Client ──── TLS(server cert) ──── Server

MITM proxy:
  Client ──── TLS(fake cert) ──── PROXY ──── TLS(real server) ──── Server
                                    ↑ sees plaintext here
```

The proxy generates a **fake certificate** for the target domain, signed by a
**custom CA cert** that the client trusts (installed into the OS/browser trust store).

---

## 3. Certificate Generation

The proxy must dynamically generate a cert for each destination host.

```python
# Using Python cryptography library
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
import datetime

def generate_ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MITMProxyCA")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert

def generate_leaf(ca_key, ca_cert, hostname):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return key, cert
```

---

## 4. Proxy Architecture (Python asyncio)

```python
import asyncio, ssl

class MitmProxy:
    async def handle_client(self, reader, writer):
        # 1. Read CONNECT request: "CONNECT api.example.com:443 HTTP/1.1"
        req = await reader.readline()
        host, port = parse_connect(req)
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()

        # 2. Upgrade client connection to TLS with fake cert for `host`
        leaf_key, leaf_cert = generate_leaf(ca_key, ca_cert, host)
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(...)
        # ... do_handshake_on_connect

        # 3. Open TLS connection to real server
        server_ctx = ssl.create_default_context()
        server_reader, server_writer = await asyncio.open_connection(host, port, ssl=server_ctx)

        # 4. Relay, logging plaintext
        await asyncio.gather(relay(client_reader, server_writer, "→"),
                             relay(server_reader, client_writer, "←"))

async def relay(src, dst, direction):
    while True:
        data = await src.read(4096)
        if not data: break
        print(f"{direction} {len(data)} bytes: {data[:80]}")
        dst.write(data)
        await dst.drain()
```

---

## 5. Installing the CA Certificate

```cmd
# Windows: trust store
certutil -addstore Root ca_cert.pem

# Verify it's there:
certmgr.msc → Trusted Root CAs

# Remove:
certutil -delstore Root "MITMProxyCA"
```

After installation, any HTTPS request from browsers or Windows HTTP APIs
will trust your fake certificates.

---

## 6. certificate pinning bypass

Some apps use **certificate pinning** — they only accept one specific cert/key,
ignoring the OS trust store.

Bypass approaches:
- Hook `ssl_verify_callback` / `SSPI` in the target process (API hooking).
- Patch the binary to remove the pin check.
- Use Frida to hook SSL_get_verify_result or similar.
- On Android/iOS: install Magisk + TrustMeAlready.

---

## 7. Tools to know

| Tool | What it does |
|------|-------------|
| mitmproxy | Python-based, scriptable, command-line |
| Burp Suite | Industry standard, Java, excellent for web |
| Charles Proxy | GUI, popular on macOS |
| Fiddler | Windows, built by Telerik |
| Wireshark + SSLKEYLOGFILE | Decrypt if you have the session keys |

---

## Exercises

- `ex01_ca_generator.py` — generate a CA cert and a leaf cert for a domain
- `ex02_proxy_skeleton.py` — HTTP CONNECT proxy that decrypts and prints bodies
- `ex03_request_modifier.py` — intercept and modify a specific JSON field
- `ex04_pinning_analysis.cpp` — detect if a Windows binary does cert pinning
  (check imports: CertVerifyCertificateChainPolicy, WinHttpSetOption, ssl_ctx_set_verify)
