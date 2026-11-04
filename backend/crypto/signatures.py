"""ML-DSA-65 digital signatures (FIPS 204) — Q-SHIELD's signature primitive.

ML-DSA (Module-Lattice Digital Signature Algorithm, formerly Dilithium) is
NIST's standardized post-quantum signature scheme. ML-DSA-65 is NIST
security category 3.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

SIG_ALGORITHM = "ML-DSA-65"

# Domain-separation context for Q-SHIELD transcripts (max 255 bytes).
SIG_CONTEXT = b"Q-SHIELD package transcript v1"

# Parameter sets selectable via the crypto agility layer.
SIG_REGISTRY: dict[str, type[mldsa.MLDSA65PrivateKey]] = {
    "ML-DSA-44": mldsa.MLDSA44PrivateKey,
    "ML-DSA-65": mldsa.MLDSA65PrivateKey,
    "ML-DSA-87": mldsa.MLDSA87PrivateKey,
}


def keygen(algorithm: str = SIG_ALGORITHM) -> mldsa.MLDSA65PrivateKey:
    """Generate a new ML-DSA keypair of the requested parameter set."""
    try:
        sk_cls = SIG_REGISTRY[algorithm]
    except KeyError:
        raise ValueError(f"unsupported signature parameter set: {algorithm}") from None
    return sk_cls.generate()


def sign(private_key: mldsa.MLDSA65PrivateKey, message: bytes,
         context: bytes = SIG_CONTEXT) -> bytes:
    """Sign a message with a domain-separated context."""
    return private_key.sign(message, context=context)


def verify(public_key: mldsa.MLDSA65PublicKey, signature: bytes, message: bytes,
           context: bytes = SIG_CONTEXT) -> bool:
    """Verify a signature. Returns False instead of raising on failure."""
    try:
        public_key.verify(signature, message, context=context)
        return True
    except InvalidSignature:
        return False


def public_key_bytes(public_key: mldsa.MLDSA65PublicKey) -> bytes:
    """Serialize a public key (DER SubjectPublicKeyInfo; raw form is 1952 B)."""
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def private_key_bytes(private_key: mldsa.MLDSA65PrivateKey) -> bytes:
    """Serialize a private key (DER PKCS8; raw seed form is 32 B)."""
    return private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def load_public_key(data: bytes) -> mldsa.MLDSA65PublicKey:
    return serialization.load_der_public_key(data)


def load_private_key(data: bytes) -> mldsa.MLDSA65PrivateKey:
    return serialization.load_der_private_key(data, password=None)
