"""Classical cryptography baseline — for benchmarks and comparison.

These are the quantum-VULNERABLE (RSA, for Shor's algorithm) and
quantum-AFFECTED-KEY-AGREEMENT (X25519/Ed25519, elliptic-curve) primitives
Q-SHIELD measures post-quantum candidates against. Also used as the
classical half of Q-SHIELD's hybrid constructions.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

RSA_KEY_SIZE = 2048


# --- X25519 (classical key agreement; hybrid partner of ML-KEM) -----------


def x25519_keygen() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def x25519_shared_secret(
    private_key: X25519PrivateKey, peer_public: X25519PublicKey
) -> bytes:
    return private_key.exchange(peer_public)


def x25519_public_bytes(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes_raw()


def x25519_load_public(data: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(data)


def x25519_load_private(data: bytes) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(data)


def x25519_private_bytes(key: X25519PrivateKey) -> bytes:
    return key.private_bytes_raw()


# --- Ed25519 (classical signatures) ---------------------------------------


def ed25519_keygen() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def ed25519_sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    return private_key.sign(message)


def ed25519_verify(public_key, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


# --- RSA-2048 (quantum-vulnerable baseline; Shor's algorithm) --------------


def rsa_keygen() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)


def rsa_sign(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    """RSA-PSS signature (used for the benchmark baseline)."""
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=PSS_SALT_LEN),
        hashes.SHA256(),
    )


PSS_SALT_LEN = padding.PSS.MAX_LENGTH


def rsa_verify(public_key: rsa.RSAPublicKey, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=PSS_SALT_LEN),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def rsa_encrypt(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    """RSA-OAEP encryption (used for the benchmark baseline)."""
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
