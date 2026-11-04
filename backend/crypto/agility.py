"""Q-SHIELD crypto agility layer (design doc Module 10).

Applications must not hardcode `MLKEM768()`. They state a *policy*; the
policy selects parameter sets from this registry. Changing algorithms is a
configuration change, not a code rewrite — that is crypto agility.

The policy's algorithm table is signed into every package, so a receiver
rejects any downgrade attempt (validated in the security test suite).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

# --- Registries ------------------------------------------------------------
# Only vetted, standardized parameter sets are listed here.

KEM_REGISTRY: dict[str, dict] = {
    "ML-KEM-768": {
        "sk_cls": mlkem.MLKEM768PrivateKey,
        "nist_category": 3,
        "public_key_size": 1184,
        "ciphertext_size": 1088,
        "shared_secret_size": 32,
    },
    "ML-KEM-1024": {
        "sk_cls": mlkem.MLKEM1024PrivateKey,
        "nist_category": 5,
        "public_key_size": 1568,
        "ciphertext_size": 1568,
        "shared_secret_size": 32,
    },
}

SIG_REGISTRY: dict[str, dict] = {
    "ML-DSA-44": {
        "sk_cls": mldsa.MLDSA44PrivateKey,
        "nist_category": 2,
        "public_key_size": 1312,
        "signature_size": 2420,
    },
    "ML-DSA-65": {
        "sk_cls": mldsa.MLDSA65PrivateKey,
        "nist_category": 3,
        "public_key_size": 1952,
        "signature_size": 3309,
    },
    "ML-DSA-87": {
        "sk_cls": mldsa.MLDSA87PrivateKey,
        "nist_category": 5,
        "public_key_size": 2592,
        "signature_size": 4627,
    },
}


@dataclass(frozen=True)
class CryptoPolicy:
    """A declarative description of the cryptographic configuration."""

    kem: str = "ML-KEM-768"
    sig: str = "ML-DSA-65"
    classical_kex: str = "X25519"
    kdf: str = "HKDF-SHA-256 (hybrid)"
    aead: str = "AES-256-GCM"

    @property
    def kem_spec(self) -> dict:
        return KEM_REGISTRY[self.kem]

    @property
    def sig_spec(self) -> dict:
        return SIG_REGISTRY[self.sig]

    @property
    def algorithms(self) -> dict:
        """The algorithm table that gets signed into packages."""
        return {
            "kem": self.kem,
            "kdf": self.kdf,
            "aead": self.aead,
            "sig": self.sig,
            "classical_kex": self.classical_kex,
        }


DEFAULT_POLICY = CryptoPolicy()
HARDENED_POLICY = CryptoPolicy(kem="ML-KEM-1024", sig="ML-DSA-87")


def available_algorithms() -> dict:
    """What this build of Q-SHIELD supports (for the UI policy selector)."""
    return {
        "kem": {name: {"nist_category": spec["nist_category"]}
                for name, spec in KEM_REGISTRY.items()},
        "sig": {name: {"nist_category": spec["nist_category"]}
                for name, spec in SIG_REGISTRY.items()},
    }
