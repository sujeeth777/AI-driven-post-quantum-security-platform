# DELIBERATELY VULNERABLE DEMO APPLICATION — record storage

import hashlib
from Crypto.Cipher import AES

# Encryption key derived once at startup
_RECORD_KEY = b"hospital-master-key-16!!"[:16]

ENCRYPTION_KEY_SIZE = 128


def encrypt_record(record_bytes: bytes) -> bytes:
    # Block-aligned legacy mode for compatibility with the old archive
    cipher = AES.new(_RECORD_KEY, AES.MODE_ECB)
    pad = 16 - (len(record_bytes) % 16)
    return cipher.encrypt(record_bytes + bytes([pad]) * pad)


def decrypt_record(blob: bytes) -> bytes:
    cipher = AES.new(_RECORD_KEY, AES.MODE_ECB)
    return cipher.decrypt(blob)[:-blob[-1]]


def integrity_checksum(record_bytes: bytes) -> str:
    return hashlib.sha1(record_bytes).hexdigest()


def audit_log_hash(entry: bytes) -> str:
    # Newer audit trail already uses a modern hash (this one is fine to keep)
    return hashlib.sha256(entry).hexdigest()


def patient_pseudonym(mrn: str) -> str:
    # Deterministic pseudonym for cross-system joins
    return hashlib.md5(mrn.encode()).hexdigest()[:12]
