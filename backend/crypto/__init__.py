"""Q-SHIELD cryptographic primitives.

Thin wrappers over vetted implementations (pyca/cryptography, backed by
OpenSSL). Q-SHIELD never implements cryptographic mathematics itself.
"""

from backend.crypto.kem import (
    KEM_ALGORITHM,
    decapsulate,
    encapsulate,
    keygen,
    load_private_key,
    load_public_key,
    private_key_bytes,
    public_key_bytes,
)
from backend.crypto.signatures import (
    SIG_ALGORITHM,
    keygen as sig_keygen,
    load_private_key as sig_load_private_key,
    load_public_key as sig_load_public_key,
    private_key_bytes as sig_private_key_bytes,
    public_key_bytes as sig_public_key_bytes,
    sign,
    verify,
)
from backend.crypto.symmetric import (
    AEAD_ALGORITHM,
    decrypt,
    encrypt,
)

__all__ = [
    "KEM_ALGORITHM",
    "SIG_ALGORITHM",
    "AEAD_ALGORITHM",
    "keygen",
    "encapsulate",
    "decapsulate",
    "public_key_bytes",
    "private_key_bytes",
    "load_public_key",
    "load_private_key",
    "sig_keygen",
    "sign",
    "verify",
    "sig_public_key_bytes",
    "sig_private_key_bytes",
    "sig_load_public_key",
    "sig_load_private_key",
    "encrypt",
    "decrypt",
]
