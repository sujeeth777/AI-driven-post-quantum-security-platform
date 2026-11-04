"""Q-SHIELD hybrid secure channel — the Stage-2 migration construction.

Combines classical and post-quantum key establishment so the channel stays
secure as long as EITHER primitive holds (mirrors real hybrid deployments
such as X25519MLKEM768 in TLS 1.3):

    key agreement : X25519 (classical) + ML-KEM-768 (PQC)  -> HKDF-SHA-256 -> 32-byte session key
    bulk cipher   : AES-256-GCM
    authentication: ML-DSA-65 signature over the package transcript

Trust model for Milestone 1 (store-and-forward exchange):
  * Long-term endpoint identities are pre-distributed out of band
    (demo/keys/). A full TLS-style ephemeral handshake with forward secrecy
    is Milestone 2.
  * The sender signs the package metadata + KEM ciphertext. The receiver
    MUST verify before decapsulating/decrypting — this is what defeats a
    MITM who swaps in their own KEM ciphertext.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from backend.crypto import kem, signatures, symmetric
from backend.crypto.agility import CryptoPolicy, DEFAULT_POLICY
from backend.crypto.classical import x25519_keygen, x25519_load_public

PACKAGE_VERSION = "qshield-package-v1"
KDF_INFO = b"Q-SHIELD hybrid key derivation v1"


class PackageError(Exception):
    """Structural/version problem with a package."""


class AuthenticationError(PackageError):
    """Signature verification failed — possible forgery or MITM."""


class ReplayError(PackageError):
    """Package msg_id was already processed."""


@dataclass
class EndpointKeys:
    """A Q-SHIELD endpoint's long-term hybrid identity keys."""

    name: str
    kem_sk: Any
    sig_sk: Any
    x25519_sk: X25519PrivateKey
    kem_alg: str = DEFAULT_POLICY.kem
    sig_alg: str = DEFAULT_POLICY.sig

    @classmethod
    def generate(cls, name: str, policy: CryptoPolicy = DEFAULT_POLICY) -> "EndpointKeys":
        """Generate a fresh identity under the given policy."""
        return cls(
            name=name,
            kem_sk=kem.keygen(policy.kem),
            sig_sk=signatures.keygen(policy.sig),
            x25519_sk=x25519_keygen(),
            kem_alg=policy.kem,
            sig_alg=policy.sig,
        )

    @property
    def kem_pk(self):
        return self.kem_sk.public_key()

    @property
    def sig_pk(self):
        return self.sig_sk.public_key()


def derive_session_key(ss_kem: bytes, ss_ecdh: bytes) -> bytes:
    """Combine both shared secrets with HKDF-SHA-256.

    The channel is broken only if BOTH X25519 AND ML-KEM fall. HKDF
    extraction treats the concatenation as one IKM, matching the
    concatenate-then-derive pattern used by hybrid TLS groups.
    """
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=KDF_INFO)
    return hkdf.derive(ss_kem + ss_ecdh)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _canonical(meta: dict) -> bytes:
    """Stable byte encoding of package metadata (also used as AEAD AAD)."""
    return json.dumps(meta, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_package(
    message: bytes,
    sender: EndpointKeys,
    receiver: EndpointKeys,
    msg_id: str | None = None,
    policy: CryptoPolicy = DEFAULT_POLICY,
) -> dict:
    """Encrypt + authenticate a message from sender to receiver.

    Pipeline (matches the Q-SHIELD design doc, section 13):
        message -> AES-256-GCM with hybrid-derived session key
                -> KEM ciphertext carries the key material
                -> ML-DSA signature over (metadata || KEM ciphertext)

    The parameter sets come from `policy` (crypto agility layer); the
    policy's algorithm table is signed into the package.
    """
    # 1. Hybrid key establishment (sender side).
    ss_kem, kem_ct = kem.encapsulate(receiver.kem_pk)
    ss_ecdh = sender.x25519_sk.exchange(receiver.x25519_sk.public_key())
    session_key = derive_session_key(ss_kem, ss_ecdh)

    # 2. Metadata -> canonical AAD (algorithm table included = downgrade protection).
    meta = {
        "version": PACKAGE_VERSION,
        "from": sender.name,
        "to": receiver.name,
        "msg_id": msg_id or secrets.token_hex(8),
        "algorithms": policy.algorithms,
    }
    aad = _canonical(meta)

    # 3. Encrypt payload, bound to the metadata.
    nonce, ciphertext = symmetric.encrypt(session_key, message, aad)

    # 4. Authenticate the whole transcript (metadata + KEM ciphertext).
    transcript = aad + kem_ct
    signature = signatures.sign(sender.sig_sk, transcript)

    return {
        **meta,
        "kem_ct": _b64(kem_ct),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
        "signature": _b64(signature),
    }


def open_package(
    package: dict,
    receiver: EndpointKeys,
    sender_sig_pk,
    sender_x25519_pk_bytes: bytes,
    seen_msg_ids: set[str] | None = None,
    policy: CryptoPolicy = DEFAULT_POLICY,
) -> bytes:
    """Verify, decapsulate, and decrypt a package. Raises on any violation.

    Order of operations is the security argument:
      1. structural + version checks
      2. replay check on msg_id
      3. ML-DSA verify over (metadata || KEM ciphertext)  <- before any secret op
      4. ML-KEM decapsulate + X25519, derive session key
      5. AES-256-GCM decrypt (raises InvalidTag on tampering)
    """
    # 1. Structure.
    for field in ("version", "from", "to", "msg_id", "algorithms",
                  "kem_ct", "nonce", "ciphertext", "signature"):
        if field not in package:
            raise PackageError(f"missing field: {field}")
    if package["version"] != PACKAGE_VERSION:
        raise PackageError(f"unsupported version: {package['version']}")
    if package["to"] != receiver.name:
        raise PackageError(f"package addressed to '{package['to']}', not us")
    if package["algorithms"] != policy.algorithms:
        raise PackageError("algorithm mismatch — possible downgrade attempt")

    # 2. Replay.
    msg_id = package["msg_id"]
    if seen_msg_ids is not None:
        if msg_id in seen_msg_ids:
            raise ReplayError(f"replayed msg_id: {msg_id}")
        seen_msg_ids.add(msg_id)

    # 3. Authenticate BEFORE decapsulating (MITM defense).
    aad = _canonical({k: package[k] for k in
                      ("version", "from", "to", "msg_id", "algorithms")})
    kem_ct = _unb64(package["kem_ct"])
    transcript = aad + kem_ct
    if not signatures.verify(sender_sig_pk, _unb64(package["signature"]), transcript):
        raise AuthenticationError(
            "ML-DSA signature invalid — package forged or modified"
        )

    # 4. Hybrid key establishment (receiver side).
    ss_kem = kem.decapsulate(receiver.kem_sk, kem_ct)
    ss_ecdh = receiver.x25519_sk.exchange(x25519_load_public(sender_x25519_pk_bytes))
    session_key = derive_session_key(ss_kem, ss_ecdh)

    # 5. Decrypt.
    try:
        return symmetric.decrypt(
            session_key, _unb64(package["nonce"]), _unb64(package["ciphertext"]), aad
        )
    except symmetric.InvalidTag as exc:
        raise PackageError("decryption failed — ciphertext or metadata tampered") from exc
