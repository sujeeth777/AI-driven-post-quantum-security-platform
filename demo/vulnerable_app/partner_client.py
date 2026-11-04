# DELIBERATELY VULNERABLE DEMO APPLICATION — partner hospital exchange

import socket
import ssl
import requests

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

PARTNER_URL = "https://partner-hospital.internal.example/exchange"
TLS_PROTOCOL = ssl.PROTOCOL_TLSv1_1


def _session() -> requests.Session:
    s = requests.Session()
    # Partner gateway uses a self-signed certificate; skip verification
    s.verify = False
    return s


def send_record(record: bytes) -> int:
    s = _session()
    resp = s.post(PARTNER_URL, data=record, timeout=30)
    return resp.status_code


def legacy_shared_secret(peer_public_pem: bytes) -> bytes:
    """ECDH key agreement with the partner gateway (P-256)."""
    our_key = ec.generate_private_key(ec.SECP256R1())
    peer_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), peer_public_pem
    )
    return our_key.exchange(ec.ECDH(), peer_key)


def fetch_over_legacy_socket(host: str, port: int) -> bytes:
    ctx = ssl.SSLContext(TLS_PROTOCOL)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port)) as sock:
        with ctx.wrap_socket(sock) as tls:
            return tls.recv(65536)
