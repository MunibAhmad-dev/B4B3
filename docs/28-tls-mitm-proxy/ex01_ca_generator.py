"""
Exercise 01 — CA + Leaf Certificate Generator
-----------------------------------------------
Build the certificate infrastructure for a MITM proxy.
You need two things:
  1. A CA (Certificate Authority) cert + key — installed into the OS trust store.
  2. Per-domain leaf certs — signed by the CA, generated on demand.

Install:
  pip install cryptography

Tasks:
1. Implement generate_ca() — returns (ca_key, ca_cert).
   The CA cert must have BasicConstraints(ca=True) so it can sign leaf certs.
2. Implement generate_leaf(ca_key, ca_cert, hostname) — returns (leaf_key, leaf_cert).
   Must include SubjectAlternativeName with the hostname.
3. Implement save_pem(key, cert, basename) — write <basename>.key.pem and <basename>.crt.pem.
4. Implement verify_chain(ca_cert, leaf_cert) — verify leaf is signed by CA.
5. Generate a CA for "MITMProxyCA" and a leaf for "api.example.com", save both.

BONUS:
- Add wildcard SAN: *.example.com (useful so one cert covers all subdomains).
- Set the CA key usage to keyCertSign + cRLSign.
- Implement a cert cache: don't regenerate for the same hostname.

Run:
  python ex01_ca_generator.py
  openssl x509 -in api.example.com.crt.pem -text -noout  # verify
"""

import datetime
import os

# TODO: uncomment when cryptography is installed
# from cryptography import x509
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives import hashes, serialization
# from cryptography.x509.oid import NameOID


def generate_ca():
    """
    Generate a self-signed CA certificate.
    Returns: (ca_private_key, ca_certificate)

    Steps:
    1. Generate RSA-2048 key
    2. Build x509 cert with:
       - subject = issuer = { CN: "MITMProxyCA" }
       - BasicConstraints(ca=True)
       - valid for 10 years
       - KeyUsage: keyCertSign, cRLSign
    3. Sign with the key itself (self-signed)
    """
    # YOUR CODE HERE
    # key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MITMProxyCA")])
    # cert = (x509.CertificateBuilder()
    #         .subject_name(name).issuer_name(name)
    #         .public_key(key.public_key())
    #         .serial_number(x509.random_serial_number())
    #         .not_valid_before(datetime.datetime.utcnow())
    #         .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    #         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    #         .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True,
    #                                       crl_sign=True, content_commitment=False,
    #                                       key_encipherment=False, data_encipherment=False,
    #                                       key_agreement=False, encipher_only=False,
    #                                       decipher_only=False), critical=True)
    #         .sign(key, hashes.SHA256()))
    # return key, cert
    raise NotImplementedError("generate_ca not implemented")


def generate_leaf(ca_key, ca_cert, hostname):
    """
    Generate a leaf cert for `hostname`, signed by the CA.
    Returns: (leaf_private_key, leaf_certificate)

    Steps:
    1. Generate RSA-2048 key
    2. Build cert with:
       - subject { CN: hostname }
       - issuer = ca_cert.subject
       - SubjectAlternativeName: DNSName(hostname)
       - Valid for 1 year
    3. Sign with ca_key
    """
    # YOUR CODE HERE
    raise NotImplementedError("generate_leaf not implemented")


def save_pem(key, cert, basename):
    """
    Save key to <basename>.key.pem (PEM, private, no encryption).
    Save cert to <basename>.crt.pem (PEM).
    """
    # YOUR CODE HERE
    # key_pem = key.private_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PrivateFormat.TraditionalOpenSSL,
    #     encryption_algorithm=serialization.NoEncryption())
    # cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    # with open(basename + ".key.pem", "wb") as f: f.write(key_pem)
    # with open(basename + ".crt.pem", "wb") as f: f.write(cert_pem)
    raise NotImplementedError("save_pem not implemented")


def verify_chain(ca_cert, leaf_cert):
    """
    Verify that leaf_cert was signed by ca_cert.
    Returns True/False.
    """
    # YOUR CODE HERE
    # ca_cert.public_key().verify(
    #     leaf_cert.signature,
    #     leaf_cert.tbs_certificate_bytes,
    #     padding.PKCS1v15(),
    #     leaf_cert.signature_hash_algorithm)
    # return True  # no exception = valid
    raise NotImplementedError("verify_chain not implemented")


if __name__ == "__main__":
    print("[*] Generating CA...")
    ca_key, ca_cert = generate_ca()
    save_pem(ca_key, ca_cert, "mitmproxy_ca")
    print("[+] CA saved: mitmproxy_ca.key.pem / mitmproxy_ca.crt.pem")
    print("    Install CA: certutil -addstore Root mitmproxy_ca.crt.pem")

    hostname = "api.example.com"
    print(f"\n[*] Generating leaf for {hostname}...")
    leaf_key, leaf_cert = generate_leaf(ca_key, ca_cert, hostname)
    save_pem(leaf_key, leaf_cert, hostname)
    print(f"[+] Leaf saved: {hostname}.key.pem / {hostname}.crt.pem")

    print("\n[*] Verifying chain...")
    ok = verify_chain(ca_cert, leaf_cert)
    print(f"[{'+'  if ok else '-'}] Chain valid: {ok}")
