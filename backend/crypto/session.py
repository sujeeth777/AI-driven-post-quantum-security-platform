"""Q-SHIELD ephemeral secure session — Milestone 2 forward secrecy.

The store-and-forward package flow (hybrid.py) uses long-term keys: if a
static private key is stolen later, past packages are decryptable. This
module implements the TLS-1.3-style alternative:

    Responder (B) publishes a SIGNED OFFER with fresh ephemeral keys
        (ephemeral ML-KEM pk + ephemeral X25519 pk).
    Initiator (A) encapsulates to the ephemeral KEM key, performs ECDH
        against the ephemeral X25519 key with its OWN fresh ephemeral key,
        derives the session key (HKDF), encrypts, and signs the transcript
        with its static ML-DSA identity key.
    Responder verifies, decapsulates, decrypts — then DESTROYS both
        ephemeral secret keys. Offers are strictly single-use.

Forward secrecy: after the handshake, even an attacker who later steals
BOTH static identity keys cannot recover the session key — the ephemeral
secrets no longer exist. (Python cannot guarantee zeroized memory, so the
guarantee here is 'secrets are dropped and offers are single-use'; an HSM-
backed deployment makes this a hard guarantee.)

NOTE: this demo exchanges both directions in one process. On a network,
`offer` travels B -> A and `session message` travels A -> B.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from backend.crypto import kem, signatures, symmetric
from backend.crypto.agility import CryptoPolicy, DEFAULT_POLICY
from backend.crypto.hybrid import (
    AuthenticationError,
    EndpointKeys,
    PackageError,
    ReplayError,
    derive_session_key,
)
from backend.crypto.classical import x25519_load_public

SESSION_VERSION = "qshield-session-v1"
OFFER_SIG_CONTEXT = b"Q-SHIELD session offer v1"
SESSION_SIG_CONTEXT = b"Q-SHIELD session transcript v1"


class SessionError(PackageError):
    """Session protocol violation."""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _canonical(meta: dict) -> bytes:
    return json.dumps(meta, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class ResponderSession:
    """Responder-side state. Contains ephemeral secrets — never serialize it."""

    offer_id: str
    kem_sk: object            # ephemeral ML-KEM private key
    x25519_sk: X25519PrivateKey  # ephemeral
    consumed: bool = False

    def destroy(self) -> None:
        """Release ephemeral secrets (forward secrecy step)."""
        self.kem_sk = None
        self.x25519_sk = None
        self.consumed = True


def create_offer(
    responder: EndpointKeys, policy: CryptoPolicy = DEFAULT_POLICY
) -> tuple[dict, ResponderSession]:
    """Responder side, step 1: publish a signed offer with fresh ephemeral keys."""
    eph_kem_sk = kem.keygen(policy.kem)
    eph_x_sk = X25519PrivateKey.generate()
    offer_id = secrets.token_hex(8)

    offer_meta = {
        "version": SESSION_VERSION,
        "responder": responder.name,
        "offer_id": offer_id,
        "algorithms": policy.algorithms,
        "kem_pk": _b64(eph_kem_sk.public_key().public_bytes_raw()),
        "x25519_pk": _b64(eph_x_sk.public_key().public_bytes_raw()),
    }
    offer_meta["signature"] = _b64(
        signatures.sign(responder.sig_sk, _canonical(offer_meta),
                        context=OFFER_SIG_CONTEXT)
    )
    return offer_meta, ResponderSession(offer_id=offer_id, kem_sk=eph_kem_sk,
                                        x25519_sk=eph_x_sk)


def verify_offer(offer: dict, responder_sig_pk, policy: CryptoPolicy = DEFAULT_POLICY) -> None:
    """Verify the responder's signature on an offer (initiator side)."""
    for field in ("version", "responder", "offer_id", "algorithms",
                  "kem_pk", "x25519_pk", "signature"):
        if field not in offer:
            raise SessionError(f"offer missing field: {field}")
    if offer["version"] != SESSION_VERSION:
        raise SessionError(f"unsupported session version: {offer['version']}")
    if offer["algorithms"] != policy.algorithms:
        raise SessionError("offer algorithm table mismatch — downgrade attempt")
    meta = {k: offer[k] for k in
            ("version", "responder", "offer_id", "algorithms", "kem_pk", "x25519_pk")}
    if not signatures.verify(responder_sig_pk, _unb64(offer["signature"]),
                             _canonical(meta), context=OFFER_SIG_CONTEXT):
        raise AuthenticationError("offer signature invalid — responder identity forged")


def respond_to_offer(
    offer: dict,
    initiator: EndpointKeys,
    message: bytes,
    responder_sig_pk,
    policy: CryptoPolicy = DEFAULT_POLICY,
    msg_id: str | None = None,
) -> dict:
    """Initiator side: verify offer, establish hybrid session, send message.

    The initiator's ephemeral X25519 secret is destroyed before returning —
    only the responder's copy of ephemeral secrets survives until completion.
    """
    verify_offer(offer, responder_sig_pk, policy)

    # Hybrid key establishment against the RESPONDER'S EPHEMERAL keys.
    ss_kem, kem_ct = kem.encapsulate(_load_kem_public(_unb64(offer["kem_pk"])))
    eph_x_sk = X25519PrivateKey.generate()  # initiator's fresh ephemeral
    ss_ecdh = eph_x_sk.exchange(x25519_load_public(_unb64(offer["x25519_pk"])))
    session_key = derive_session_key(ss_kem, ss_ecdh)

    meta = {
        "version": SESSION_VERSION,
        "from": initiator.name,
        "to": offer["responder"],
        "offer_id": offer["offer_id"],
        "msg_id": msg_id or secrets.token_hex(8),
        "algorithms": policy.algorithms,
        "x25519_pk": _b64(eph_x_sk.public_key().public_bytes_raw()),
    }
    aad = _canonical(meta)
    nonce, ciphertext = symmetric.encrypt(session_key, message, aad)
    transcript = aad + kem_ct
    signature = signatures.sign(initiator.sig_sk, transcript,
                                context=SESSION_SIG_CONTEXT)

    # Forward secrecy on the initiator side: drop the ephemeral secret.
    del eph_x_sk

    return {**meta, "kem_ct": _b64(kem_ct), "nonce": _b64(nonce),
            "ciphertext": _b64(ciphertext), "signature": _b64(signature)}


def complete_session(
    session_message: dict,
    responder_session: ResponderSession,
    responder: EndpointKeys,
    initiator_sig_pk,
    policy: CryptoPolicy = DEFAULT_POLICY,
) -> bytes:
    """Responder side, step 2: verify, decrypt, then destroy ephemeral secrets."""
    if responder_session.consumed or responder_session.kem_sk is None:
        raise SessionError("offer already used — sessions are single-use")

    required = ("version", "from", "to", "offer_id", "msg_id", "algorithms",
                "x25519_pk", "kem_ct", "nonce", "ciphertext", "signature")
    for field in required:
        if field not in session_message:
            raise SessionError(f"session message missing field: {field}")
    if session_message["version"] != SESSION_VERSION:
        raise SessionError("unsupported session version")
    if session_message["offer_id"] != responder_session.offer_id:
        raise SessionError("session message does not match this offer")
    if session_message["to"] != responder.name:
        raise SessionError("session message addressed to someone else")
    if session_message["algorithms"] != policy.algorithms:
        raise SessionError("session algorithm table mismatch — downgrade attempt")

    aad = _canonical({k: session_message[k] for k in required[:7]})
    kem_ct = _unb64(session_message["kem_ct"])

    # Authenticate the transcript BEFORE any secret operation.
    transcript = aad + kem_ct
    if not signatures.verify(initiator_sig_pk, _unb64(session_message["signature"]),
                             transcript, context=SESSION_SIG_CONTEXT):
        raise AuthenticationError("session signature invalid — possible MITM")

    ss_kem = kem.decapsulate(responder_session.kem_sk, kem_ct)
    ss_ecdh = responder_session.x25519_sk.exchange(
        x25519_load_public(_unb64(session_message["x25519_pk"]))
    )
    session_key = derive_session_key(ss_kem, ss_ecdh)
    try:
        plaintext = symmetric.decrypt(session_key, _unb64(session_message["nonce"]),
                                      _unb64(session_message["ciphertext"]), aad)
    except symmetric.InvalidTag as exc:
        raise SessionError("session decryption failed") from exc
    finally:
        # Forward secrecy: the ephemeral secrets are destroyed after this
        # point regardless of the decryption outcome.
        responder_session.destroy()

    return plaintext


def _load_kem_public(data: bytes):
    """Load a raw ML-KEM public key of the size implied by the data."""
    from cryptography.hazmat.primitives.asymmetric import mlkem
    # Raw public keys are length-distinct per parameter set.
    sizes = {1184: mlkem.MLKEM768PublicKey, 1568: mlkem.MLKEM1024PublicKey}
    try:
        pk_cls = sizes[len(data)]
    except KeyError:
        raise SessionError(f"unknown KEM public key size: {len(data)}") from None
    return pk_cls.from_public_bytes(data)
