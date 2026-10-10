"""
Solution 01 — CA + Leaf Certificate Generator (complete)
"""

import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID


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
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False), critical=True)
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
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(hostname),
                    x509.DNSName(f"*.{hostname}"),
                ]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


def save_pem(key, cert, basename):
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(basename + ".key.pem", "wb") as f: f.write(key_pem)
    with open(basename + ".crt.pem", "wb") as f: f.write(cert_pem)


def verify_chain(ca_cert, leaf_cert):
    try:
        ca_cert.public_key().verify(
            leaf_cert.signature,
            leaf_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            leaf_cert.signature_hash_algorithm)
        return True
    except Exception:
        return False


if __name__ == "__main__":
    print("[*] Generating CA...")
    ca_key, ca_cert = generate_ca()
    save_pem(ca_key, ca_cert, "mitmproxy_ca")
    print("[+] CA saved")
    print("    Install: certutil -addstore Root mitmproxy_ca.crt.pem")

    hostname = "api.example.com"
    print(f"\n[*] Generating leaf for {hostname}...")
    leaf_key, leaf_cert = generate_leaf(ca_key, ca_cert, hostname)
    save_pem(leaf_key, leaf_cert, hostname)
    print(f"[+] Leaf saved")

    ok = verify_chain(ca_cert, leaf_cert)
    print(f"[{'+'  if ok else '-'}] Chain valid: {ok}")
