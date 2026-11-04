"""Persistent endpoint identities for the Q-SHIELD demo.

Each hospital gets long-term hybrid identity keys. Keys are cached per
parameter set (the crypto agility layer), so switching policy in the web UI
just loads (or lazily generates) that policy's keys. In a real deployment
these would live in an HSM/KMS and be distributed via a PKI — out of scope
for the milestone demos.
"""

from __future__ import annotations

from pathlib import Path

from backend.crypto import classical, kem, signatures
from backend.crypto.agility import CryptoPolicy, DEFAULT_POLICY
from backend.crypto.hybrid import EndpointKeys

KEYS_DIR = Path("keys")


def _read(path: Path) -> bytes | None:
    return path.read_bytes() if path.exists() else None


def ensure_identity(name: str, policy: CryptoPolicy = DEFAULT_POLICY) -> EndpointKeys:
    """Load the hospital's identity keys for a policy, generating on first run."""
    directory = KEYS_DIR / name
    directory.mkdir(parents=True, exist_ok=True)

    kem_path = directory / f"kem-{policy.kem}.der"
    sig_path = directory / f"sig-{policy.sig}.der"
    x_path = directory / "x25519.raw"

    kem_raw = _read(kem_path)
    if kem_raw is None:
        kem_sk = kem.keygen(policy.kem)
        kem_path.write_bytes(kem.private_key_bytes(kem_sk))
        print(f"[identities] generated new {policy.kem} identity for {name}")
    else:
        kem_sk = kem.load_private_key(kem_raw)

    sig_raw = _read(sig_path)
    if sig_raw is None:
        sig_sk = signatures.keygen(policy.sig)
        sig_path.write_bytes(signatures.private_key_bytes(sig_sk))
        print(f"[identities] generated new {policy.sig} identity for {name}")
    else:
        sig_sk = signatures.load_private_key(sig_raw)

    x_raw = _read(x_path)
    if x_raw is None:
        x_sk = classical.x25519_keygen()
        x_path.write_bytes(classical.x25519_private_bytes(x_sk))
        print(f"[identities] generated new X25519 identity for {name}")
    else:
        x_sk = classical.x25519_load_private(x_raw)

    return EndpointKeys(name=name, kem_sk=kem_sk, sig_sk=sig_sk, x25519_sk=x_sk,
                        kem_alg=policy.kem, sig_alg=policy.sig)
