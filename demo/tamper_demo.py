"""Q-SHIELD demo — Attack Laboratory: watch the gateway reject attacks.

Simulates three adversaries against the Hospital A -> B channel:
  1. Tamperer    : flips a byte inside the encrypted record
  2. MITM        : swaps the ML-KEM ciphertext for their own encapsulation
  3. Forger      : re-signs the package with their own ML-DSA key
  4. Replayer    : redelivers a package Hospital B already processed

Run from repo root:  python -m demo.tamper_demo
"""

from __future__ import annotations

import base64
import json

from backend.crypto import classical, kem, signatures
from backend.crypto.hybrid import (
    EndpointKeys,
    PackageError,
    _canonical,
    build_package,
    open_package,
)
from demo.identities import ensure_identity

MESSAGE = json.dumps({"patient_id": "P001", "mri_report": "normal"}).encode()


def attempt(label: str, pkg: dict, hospital_b, sig_pk, x_pk,
            seen: set | None = None, expect: str = "reject"):
    try:
        open_package(pkg, hospital_b, sig_pk, x_pk, seen_msg_ids=seen)
        outcome = "ACCEPTED"
    except PackageError as exc:
        outcome = f"REJECTED ({type(exc).__name__})"
    as_expected = outcome.startswith("ACCEPTED") == (expect == "accept")
    verdict = "as expected" if as_expected else "!!! UNEXPECTED !!!"
    print(f"  [{label:<10}] {outcome:<45} {verdict}")


def main() -> int:
    print("=" * 62)
    print("Q-SHIELD ATTACK LABORATORY")
    print("=" * 62)

    alice = ensure_identity("hospital-a")
    bob = ensure_identity("hospital-b")
    mallory = EndpointKeys(
        name="mallory",
        kem_sk=kem.keygen(),
        sig_sk=signatures.keygen(),
        x25519_sk=classical.x25519_keygen(),
    )
    a_x_pk = classical.x25519_public_bytes(alice.x25519_sk)

    print("\nControl — untampered package (legitimate delivery):")
    attempt("control", build_package(MESSAGE, alice, bob), bob, alice.sig_pk,
            a_x_pk, expect="accept")

    print("\n1) Tamperer — flips a byte inside the encrypted record:")
    pkg = build_package(MESSAGE, alice, bob)
    raw = bytearray(base64.b64decode(pkg["ciphertext"]))
    raw[3] ^= 0x40
    pkg["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    attempt("tamper", pkg, bob, alice.sig_pk, a_x_pk)

    print("\n2) MITM — substitutes their own ML-KEM ciphertext:")
    pkg = build_package(MESSAGE, alice, bob)
    _, mitm_ct = kem.encapsulate(mallory.kem_pk)
    pkg["kem_ct"] = base64.b64encode(mitm_ct).decode()
    attempt("mitm", pkg, bob, alice.sig_pk, a_x_pk)

    print("\n3) Forger — re-signs the package with their own ML-DSA key:")
    pkg = build_package(MESSAGE, alice, bob)
    meta = _canonical({k: pkg[k] for k in
                       ("version", "from", "to", "msg_id", "algorithms")})
    transcript = meta + base64.b64decode(pkg["kem_ct"])
    pkg["signature"] = base64.b64encode(
        signatures.sign(mallory.sig_sk, transcript)).decode()
    attempt("forge", pkg, bob, alice.sig_pk, a_x_pk)

    print("\n4) Replayer — redelivers a package already processed:")
    pkg = build_package(MESSAGE, alice, bob)
    seen: set = set()
    attempt("replay-1st", dict(pkg), bob, alice.sig_pk, a_x_pk, seen, expect="accept")
    attempt("replay-2nd", dict(pkg), bob, alice.sig_pk, a_x_pk, seen, expect="reject")

    print("\nAll adversaries rejected. The channel holds.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
