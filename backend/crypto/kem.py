"""ML-KEM-768 key encapsulation (FIPS 203) — Q-SHIELD's KEM primitive.

ML-KEM (Module-Lattice Key Encapsulation Mechanism, formerly Kyber) is
NIST's standardized post-quantum KEM. Security against quantum attackers
relies on the hardness of the Module-LWE problem.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mlkem

KEM_ALGORITHM = "ML-KEM-768"
"""The default parameter set (NIST security category 3, ~AES-192 class)."""

# Parameter sets selectable via the crypto agility layer.
KEM_REGISTRY: dict[str, type[mlkem.MLKEM768PrivateKey]] = {
    "ML-KEM-768": mlkem.MLKEM768PrivateKey,
    "ML-KEM-1024": mlkem.MLKEM1024PrivateKey,
}


def keygen(algorithm: str = KEM_ALGORITHM) -> mlkem.MLKEM768PrivateKey:
    """Generate a new ML-KEM keypair of the requested parameter set."""
    try:
        sk_cls = KEM_REGISTRY[algorithm]
    except KeyError:
        raise ValueError(f"unsupported KEM parameter set: {algorithm}") from None
    return sk_cls.generate()


def encapsulate(public_key: mlkem.MLKEM768PublicKey) -> tuple[bytes, bytes]:
    """Encapsulate a shared secret to a recipient's public key.

    Returns:
        (shared_secret, ciphertext). The sender transmits the ciphertext;
        both sides end up with the same 32-byte shared secret.
    """
    shared_secret, ciphertext = public_key.encapsulate()
    return shared_secret, ciphertext


def decapsulate(private_key: mlkem.MLKEM768PrivateKey, ciphertext: bytes) -> bytes:
    """Recover the shared secret from a ciphertext.

    On a malformed/tampered ciphertext ML-KEM performs implicit rejection:
    a pseudorandom secret is returned instead of raising, so callers must
    bind key derivation to authenticated data (see backend.crypto.hybrid).
    """
    return private_key.decapsulate(ciphertext)


def public_key_bytes(public_key: mlkem.MLKEM768PublicKey) -> bytes:
    """Serialize a public key (DER SubjectPublicKeyInfo; raw form is 1184 B)."""
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def private_key_bytes(private_key: mlkem.MLKEM768PrivateKey) -> bytes:
    """Serialize a private key (DER PKCS8; raw seed form is 64 B)."""
    return private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def load_public_key(data: bytes) -> mlkem.MLKEM768PublicKey:
    return serialization.load_der_public_key(data)


def load_private_key(data: bytes) -> mlkem.MLKEM768PrivateKey:
    return serialization.load_der_private_key(data, password=None)
