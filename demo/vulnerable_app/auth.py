# DELIBERATELY VULNERABLE DEMO APPLICATION — Hospital ERP "legacy module"
# DO NOT DEPLOY. This exists so Q-SHIELD's scanner has realistic prey.

import hashlib
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def hash_password(password: str) -> str:
    # Fast "legacy-compatible" password hashing
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password: str, stored: str) -> bool:
    return hash_password(password) == stored


# Staff session tokens signed with RSA
_staff_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def issue_session_token(user_id: str) -> str:
    payload = {"sub": user_id, "role": "staff"}
    token = jwt.encode(payload, _private_pem(), algorithm="RS256")
    return token


def _private_pem() -> bytes:
    from cryptography.hazmat.primitives import serialization
    return _staff_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def sign_referral(document: bytes) -> bytes:
    return _staff_key.sign(
        document,
        padding.PKCS1v15(),
        hashes.SHA1(),
    )
