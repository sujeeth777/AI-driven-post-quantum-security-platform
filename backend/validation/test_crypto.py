"""Q-SHIELD Security Validation Engine — Milestone 1.

Runs positive (correctness) and negative (attack) tests against every
cryptographic primitive and the hybrid secure channel. Run from repo root:

    python -m backend.validation.test_crypto

Exit code 0 = all validations passed.
"""

from __future__ import annotations

import base64
import secrets
import sys
import traceback

from backend.crypto import classical, kem, signatures, symmetric
from backend.crypto.agility import DEFAULT_POLICY, HARDENED_POLICY
from backend.crypto import session as session_mod
from backend.crypto.hybrid import (
    AuthenticationError,
    EndpointKeys,
    PackageError,
    ReplayError,
    _canonical,
    build_package,
    derive_session_key,
    open_package,
)


def make_endpoint(name: str) -> EndpointKeys:
    return EndpointKeys(
        name=name,
        kem_sk=kem.keygen(),
        sig_sk=signatures.keygen(),
        x25519_sk=classical.x25519_keygen(),
    )


ALICE = make_endpoint("hospital-a")
BOB = make_endpoint("hospital-b")

MESSAGE = b"Patient P001: MRI report + blood test + prescription"


# --- test implementations --------------------------------------------------
# Each returns (passed: bool, detail: str).

def t_kem_roundtrip():
    ss1, ct = kem.encapsulate(BOB.kem_pk)
    ss2 = kem.decapsulate(BOB.kem_sk, ct)
    return ss1 == ss2, f"shared secrets match ({len(ss1)} B, ct {len(ct)} B)"


def t_sig_roundtrip():
    sig = signatures.sign(BOB.sig_sk, MESSAGE)
    ok = signatures.verify(BOB.sig_pk, sig, MESSAGE)
    return ok, f"signature verified ({len(sig)} B)"


def t_x25519_agreement():
    a = classical.x25519_keygen()
    b = classical.x25519_keygen()
    sa = classical.x25519_shared_secret(a, b.public_key())
    sb = classical.x25519_shared_secret(b, a.public_key())
    return sa == sb, f"both sides derive the same {len(sa)}-byte secret"


def t_aes_roundtrip():
    key = secrets.token_bytes(32)
    nonce, ct = symmetric.encrypt(key, MESSAGE, b"aad")
    pt = symmetric.decrypt(key, nonce, ct, b"aad")
    return pt == MESSAGE, f"{len(MESSAGE)} B round-tripped"


def t_hybrid_roundtrip():
    pkg = build_package(MESSAGE, ALICE, BOB)
    out = open_package(pkg, BOB, ALICE.sig_pk,
                       classical.x25519_public_bytes(ALICE.x25519_sk))
    return out == MESSAGE, f"message recovered ({len(pkg['ciphertext'])} B ct)"


def t_key_serialization():
    pk_b, sk_b = kem.public_key_bytes(BOB.kem_pk), kem.private_key_bytes(BOB.kem_sk)
    ss1, ct = kem.encapsulate(kem.load_public_key(pk_b))
    ss2 = kem.decapsulate(kem.load_private_key(sk_b), ct)
    spk_b, ssk_b = (signatures.public_key_bytes(BOB.sig_pk),
                    signatures.private_key_bytes(BOB.sig_sk))
    sig = signatures.sign(signatures.load_private_key(ssk_b), MESSAGE)
    ok = signatures.verify(signatures.load_public_key(spk_b), sig, MESSAGE)
    return ok and ss1 == ss2, "KEM + signature keys survive raw serialization"


def t_kem_wrong_key():
    ss1, ct = kem.encapsulate(BOB.kem_pk)
    other = kem.keygen()
    ss2 = kem.decapsulate(other, ct)
    return ss1 != ss2, "wrong recipient derives a different secret"


def t_kem_tampered_ct():
    ss1, ct = kem.encapsulate(BOB.kem_pk)
    bad = ct[:-1] + bytes([ct[-1] ^ 0x01])
    try:
        ss2 = kem.decapsulate(BOB.kem_sk, bad)
        ok = ss1 != ss2
        return ok, ("implicit rejection: pseudorandom secret returned"
                    if ok else "UNSAFE: tampered ct produced the same secret")
    except Exception as exc:  # noqa: BLE001 - behavior is implementation-defined
        return True, f"raises {type(exc).__name__} (explicit rejection)"


def t_sig_tampered_msg():
    sig = signatures.sign(BOB.sig_sk, MESSAGE)
    return not signatures.verify(BOB.sig_pk, sig, MESSAGE + b"X"), "modified message rejected"


def t_sig_tampered_sig():
    sig = bytearray(signatures.sign(BOB.sig_sk, MESSAGE))
    sig[100] ^= 0x01
    return not signatures.verify(BOB.sig_pk, bytes(sig), MESSAGE), "flipped signature bit rejected"


def t_sig_wrong_key():
    sig = signatures.sign(ALICE.sig_sk, MESSAGE)
    return not signatures.verify(BOB.sig_pk, sig, MESSAGE), "cross-key verification rejected"


def t_aes_tampered_ct():
    key = secrets.token_bytes(32)
    nonce, ct = symmetric.encrypt(key, MESSAGE)
    bad = ct[:-1] + bytes([ct[-1] ^ 0x01])
    try:
        symmetric.decrypt(key, nonce, bad)
        return False, "tampered ciphertext decrypted!"
    except symmetric.InvalidTag:
        return True, "InvalidTag raised on tampered ciphertext"


def t_aes_tampered_aad():
    key = secrets.token_bytes(32)
    nonce, ct = symmetric.encrypt(key, MESSAGE, b"original-aad")
    try:
        symmetric.decrypt(key, nonce, ct, b"tampered-aad")
        return False, "tampered AAD accepted!"
    except symmetric.InvalidTag:
        return True, "InvalidTag raised on AAD mismatch"


def t_aes_wrong_key():
    key = secrets.token_bytes(32)
    nonce, ct = symmetric.encrypt(key, MESSAGE)
    try:
        symmetric.decrypt(secrets.token_bytes(32), nonce, ct)
        return False, "wrong key decrypted!"
    except symmetric.InvalidTag:
        return True, "InvalidTag raised on wrong key"


def t_hybrid_tampered_ct():
    pkg = build_package(MESSAGE, ALICE, BOB)
    raw = bytearray(base64.b64decode(pkg["ciphertext"]))
    raw[len(raw) // 2] ^= 0x01
    pkg["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    try:
        open_package(pkg, BOB, ALICE.sig_pk,
                     classical.x25519_public_bytes(ALICE.x25519_sk))
        return False, "tampered payload accepted!"
    except PackageError as exc:
        return True, f"rejected: {exc}"


def t_hybrid_tampered_meta():
    pkg = build_package(MESSAGE, ALICE, BOB)
    pkg["msg_id"] = "attacker-chosen-id"  # metadata no longer covered by signature
    try:
        open_package(pkg, BOB, ALICE.sig_pk,
                     classical.x25519_public_bytes(ALICE.x25519_sk))
        return False, "modified metadata accepted!"
    except AuthenticationError:
        return True, "metadata tampering breaks the transcript signature"


def t_hybrid_forged_signature():
    """Attacker re-signs the original transcript with their OWN key."""
    pkg = build_package(MESSAGE, ALICE, BOB)
    mallory = make_endpoint("mallory")
    aad = _canonical({k: pkg[k] for k in
                      ("version", "from", "to", "msg_id", "algorithms")})
    transcript = aad + base64.b64decode(pkg["kem_ct"])
    pkg["signature"] = base64.b64encode(
        signatures.sign(mallory.sig_sk, transcript)
    ).decode()
    try:
        open_package(pkg, BOB, ALICE.sig_pk,
                     classical.x25519_public_bytes(ALICE.x25519_sk))
        return False, "forged signature accepted!"
    except AuthenticationError:
        return True, "attacker re-signing rejected (Mallory is not Hospital A)"


def t_hybrid_mitm():
    """Attacker intercepts and re-encapsulates to their own key."""
    pkg = build_package(MESSAGE, ALICE, BOB)
    mallory = make_endpoint("mallory")
    _, mitm_ct = kem.encapsulate(mallory.kem_pk)  # attacker's own encapsulation
    pkg["kem_ct"] = base64.b64encode(mitm_ct).decode()
    try:
        open_package(pkg, BOB, ALICE.sig_pk,
                     classical.x25519_public_bytes(ALICE.x25519_sk))
        return False, "MITM ciphertext accepted!"
    except AuthenticationError:
        return True, "KEM ciphertext substitution caught by ML-DSA transcript signature"


def t_hybrid_replay():
    pkg = build_package(MESSAGE, ALICE, BOB)
    seen: set[str] = set()
    open_package(pkg, BOB, ALICE.sig_pk,
                 classical.x25519_public_bytes(ALICE.x25519_sk), seen_msg_ids=seen)
    try:
        open_package(pkg, BOB, ALICE.sig_pk,
                     classical.x25519_public_bytes(ALICE.x25519_sk), seen_msg_ids=seen)
        return False, "replayed package accepted!"
    except ReplayError:
        return True, "second delivery of same msg_id rejected"


def t_hybrid_wrong_recipient():
    pkg = build_package(MESSAGE, ALICE, BOB)
    try:
        open_package(pkg, ALICE, ALICE.sig_pk,   # wrong receiver object
                     classical.x25519_public_bytes(ALICE.x25519_sk))
        return False, "misdelivered package accepted!"
    except PackageError as exc:
        return True, f"rejected: {exc}"


# --- Milestone 2: crypto agility + forward secrecy -------------------------

def t_agility_hardened():
    """Same code path, stronger parameter sets — agility in action."""
    pol = HARDENED_POLICY
    a = EndpointKeys.generate("lab-a", pol)
    b = EndpointKeys.generate("lab-b", pol)
    pkg = build_package(MESSAGE, a, b, policy=pol)
    ok_table = pkg["algorithms"] == pol.algorithms
    out = open_package(pkg, b, a.sig_pk,
                       classical.x25519_public_bytes(a.x25519_sk), policy=pol)
    return (out == MESSAGE and ok_table,
            f"ML-KEM-1024 + ML-DSA-87 exchange works "
            f"(ct {len(pkg['kem_ct'])} B, sig {len(pkg['signature'])} B)")


def t_agility_downgrade_rejected():
    """A package under the default policy must not pass a stricter policy."""
    a = make_endpoint("dg-a")
    b = make_endpoint("dg-b")
    pkg = build_package(MESSAGE, a, b)          # ML-KEM-768 + ML-DSA-65
    try:
        open_package(pkg, b, a.sig_pk,
                     classical.x25519_public_bytes(a.x25519_sk),
                     policy=HARDENED_POLICY)
        return False, "downgraded algorithm table accepted!"
    except PackageError as exc:
        return True, f"downgrade rejected: {exc}"


def t_session_roundtrip():
    offer, responder_state = session_mod.create_offer(BOB)
    smsg = session_mod.respond_to_offer(offer, ALICE, MESSAGE, BOB.sig_pk)
    out = session_mod.complete_session(smsg, responder_state, BOB, ALICE.sig_pk)
    return out == MESSAGE, "TLS-style ephemeral session delivered the record"


def t_session_tampered():
    offer, responder_state = session_mod.create_offer(BOB)
    smsg = session_mod.respond_to_offer(offer, ALICE, MESSAGE, BOB.sig_pk)
    raw = bytearray(base64.b64decode(smsg["ciphertext"]))
    raw[2] ^= 0x20
    smsg["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    try:
        session_mod.complete_session(smsg, responder_state, BOB, ALICE.sig_pk)
        return False, "tampered session accepted!"
    except session_mod.SessionError:
        return True, "tampered session payload rejected"


def t_session_forged():
    """Mallory initiates a session claiming to be Alice."""
    offer, responder_state = session_mod.create_offer(BOB)
    mallory = make_endpoint("mallory-2")
    smsg = session_mod.respond_to_offer(offer, mallory, MESSAGE, BOB.sig_pk)
    try:
        session_mod.complete_session(smsg, responder_state, BOB, ALICE.sig_pk)
        return False, "forged session accepted!"
    except AuthenticationError:
        return True, "Mallory cannot initiate sessions as Alice (ML-DSA identity)"


def t_session_forward_secrecy():
    """THE forward-secrecy proof: after the session, an attacker who steals
    BOTH static identity keys still cannot decrypt the captured traffic."""
    offer, responder_state = session_mod.create_offer(BOB)
    smsg = session_mod.respond_to_offer(offer, ALICE, MESSAGE, BOB.sig_pk)
    session_mod.complete_session(smsg, responder_state, BOB, ALICE.sig_pk)

    import base64 as b64mod
    kem_ct = b64mod.b64decode(smsg["kem_ct"])
    a_eph_pk = b64mod.b64decode(smsg["x25519_pk"])
    # Attacker's best attempt with stolen static keys:
    ss_kem_stolen = kem.decapsulate(BOB.kem_sk, kem_ct)          # ephemeral KEM needed
    ss_ecdh_stolen = classical.x25519_shared_secret(BOB.x25519_sk,
                                                    classical.x25519_load_public(a_eph_pk))
    stolen_key = derive_session_key(ss_kem_stolen, ss_ecdh_stolen)
    try:
        symmetric.decrypt(stolen_key, base64.b64decode(smsg["nonce"]),
                          base64.b64decode(smsg["ciphertext"]),
                          _canonical({k: smsg[k] for k in
                                      ("version", "from", "to", "offer_id",
                                       "msg_id", "algorithms", "x25519_pk")}))
        return False, "stolen static keys decrypted the session!"
    except symmetric.InvalidTag:
        return True, "stolen static keys CANNOT decrypt past session (FS holds)"


def t_session_single_use():
    offer, responder_state = session_mod.create_offer(BOB)
    smsg = session_mod.respond_to_offer(offer, ALICE, MESSAGE, BOB.sig_pk)
    session_mod.complete_session(smsg, responder_state, BOB, ALICE.sig_pk)
    smsg2 = session_mod.respond_to_offer(offer, ALICE, MESSAGE, BOB.sig_pk)
    try:
        session_mod.complete_session(smsg2, responder_state, BOB, ALICE.sig_pk)
        return False, "offer reused!"
    except session_mod.SessionError as exc:
        return True, f"offer reuse blocked: {exc}"


TESTS = [
    # (name, category, function)
    ("ML-KEM-768 encapsulate/decapsulate round-trip", "positive", t_kem_roundtrip),
    ("ML-DSA-65 sign/verify round-trip", "positive", t_sig_roundtrip),
    ("X25519 shared-secret agreement", "positive", t_x25519_agreement),
    ("AES-256-GCM encrypt/decrypt round-trip", "positive", t_aes_roundtrip),
    ("Hybrid package build/open round-trip", "positive", t_hybrid_roundtrip),
    ("Raw key serialization round-trip", "positive", t_key_serialization),
    ("ML-KEM wrong private key", "negative", t_kem_wrong_key),
    ("ML-KEM tampered ciphertext", "negative", t_kem_tampered_ct),
    ("ML-DSA tampered message", "negative", t_sig_tampered_msg),
    ("ML-DSA tampered signature", "negative", t_sig_tampered_sig),
    ("ML-DSA wrong public key", "negative", t_sig_wrong_key),
    ("AES-GCM tampered ciphertext", "negative", t_aes_tampered_ct),
    ("AES-GCM tampered AAD", "negative", t_aes_tampered_aad),
    ("AES-GCM wrong key", "negative", t_aes_wrong_key),
    ("Hybrid tampered payload", "negative", t_hybrid_tampered_ct),
    ("Hybrid tampered metadata", "negative", t_hybrid_tampered_meta),
    ("Hybrid forged signature", "negative", t_hybrid_forged_signature),
    ("Hybrid MITM (KEM substitution)", "negative", t_hybrid_mitm),
    ("Hybrid replay detection", "negative", t_hybrid_replay),
    ("Hybrid wrong recipient", "negative", t_hybrid_wrong_recipient),
    ("Agility: hardened parameter sets (ML-KEM-1024/ML-DSA-87)", "positive", t_agility_hardened),
    ("Agility: downgrade attempt rejected", "negative", t_agility_downgrade_rejected),
    ("FS session: full round-trip", "positive", t_session_roundtrip),
    ("FS session: tampered payload", "negative", t_session_tampered),
    ("FS session: forged initiator", "negative", t_session_forged),
    ("FS session: stolen static keys cannot decrypt past session", "negative", t_session_forward_secrecy),
    ("FS session: offers are single-use", "negative", t_session_single_use),
]


def main() -> int:
    width = 56
    print("=" * width)
    print("Q-SHIELD SECURITY VALIDATION ENGINE — Milestone 1")
    print("=" * width)

    passed = 0
    for name, category, fn in TESTS:
        try:
            ok, detail = fn()
        except Exception as exc:  # noqa: BLE001 - a crashing test is a failure
            ok, detail = False, f"crashed: {type(exc).__name__}: {exc}"
            if "--debug" in sys.argv:
                traceback.print_exc()
        passed += ok
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] ({category:<8}) {name}\n        {detail}")

    print("-" * width)
    print(f"RESULT: {passed}/{len(TESTS)} passed")
    if passed != len(TESTS):
        print("Some validations FAILED — do not deploy.", file=sys.stderr)
    return 0 if passed == len(TESTS) else 1


if __name__ == "__main__":
    sys.exit(main())
