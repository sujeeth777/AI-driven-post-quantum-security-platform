"""AES-256-GCM authenticated encryption — Q-SHIELD's symmetric primitive.

AES-256 remains quantum-resistant under Grover's algorithm (effectively
halved key search cost: 2^256 -> 2^128, still infeasible), so Q-SHIELD
keeps it as the bulk-data cipher per NIST/CNSA 2.0 guidance.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AEAD_ALGORITHM = "AES-256-GCM"

KEY_SIZE = 32
NONCE_SIZE = 12


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM.

    Args:
        key: 32-byte session key.
        plaintext: data to encrypt.
        aad: additional authenticated data (authenticated but not encrypted).

    Returns:
        (nonce, ciphertext) — a fresh random 12-byte nonce per message.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")
    nonce = os.urandom(NONCE_SIZE)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad or None)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """Decrypt AES-256-GCM ciphertext; raises InvalidTag on any tampering."""
    return AESGCM(key).decrypt(nonce, ciphertext, aad or None)


__all__ = ["AEAD_ALGORITHM", "KEY_SIZE", "NONCE_SIZE", "encrypt", "decrypt", "InvalidTag"]
