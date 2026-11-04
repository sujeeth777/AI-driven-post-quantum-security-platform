"""Q-SHIELD AI Security Architect — requirements analyzer (Module 1).

Turns a natural-language description into a formal security specification.
Milestone implementation: deterministic rule-based extraction with a
provider-independent interface — an LLM gateway can replace `extract`
later without touching callers (the AI gateway pattern from the design doc).

Every extracted field carries the evidence that produced it, so the
"AI proposes, engine validates" principle is auditable.
"""

from __future__ import annotations

import re

ORG_RULES = [
    ("Healthcare", r"hospital|clinic|patient|medical|mri|prescription|doctor|health"),
    ("Finance", r"bank|payment|transaction|fintech|trading"),
    ("Government", r"government|agency|defense|military|public sector"),
    ("Industrial", r"factory|manufactur|industrial|scada|iot device"),
    ("SaaS/Cloud", r"saas|cloud|multi[- ]tenant|api platform"),
]
DATA_RULES = [
    ("Patient records", r"patient record|medical record|health record|patient data"),
    ("Medical images", r"mri|ct scan|x-?ray|medical image"),
    ("Lab results", r"lab|blood test|diagnostic"),
    ("Prescriptions", r"prescription|medication"),
    ("Financial records", r"payment|transaction|financial"),
    ("Internal documents", r"document|file|report"),
]
DURATION_RE = re.compile(r"(\d+)\s*\+?\s*(years?|decades?|months?)", re.IGNORECASE)
CRYPTO_RULES = [
    ("RSA-2048", r"rsa[- ]?2048|\brsa\b"),
    ("ECDSA", r"ecdsa|elliptic curve signature"),
    ("ECDH", r"ecdh|diffie[- ]hellman|\bdh\b"),
    ("AES", r"\baes\b"),
    ("TLS", r"\btls\b|https|ssl"),
    ("JWT", r"\bjwt\b|json web token"),
]

REQ_TRIGGERS = {
    "long_term_secrecy": r"long[- ]term|decades|years|archive|harvest",
    "forward_secrecy": r"forward secrec|session key|ephemeral",
    "authentication": r"authenticat|sign|identity|verify",
    "legacy_compatibility": r"cannot (immediately )?(remove|replace)|existing (infrastructure|system)|legacy|compatib|gradual",
    "crypto_agility": r"agility|swap|change algorithm|future[- ]proof",
    "high_availability": r"24/7|always available|uptime|availability",
}


def extract_requirements(text: str) -> dict:
    """Extract a structured security specification from free text."""
    low = text.lower()

    org = next((name for name, pat in ORG_RULES if re.search(pat, low)), "General")
    data_types = [name for name, pat in DATA_RULES if re.search(pat, low)]

    duration_years = 10.0
    duration_evidence = "default (10y) — no explicit duration found"
    m = DURATION_RE.search(low)
    if m:
        value, unit = int(m.group(1)), m.group(2).lower()
        if "decade" in unit:
            duration_years = value * 10
        elif "month" in unit:
            duration_years = round(value / 12, 1)
        else:
            duration_years = value
        duration_evidence = f'"{m.group(0)}"'

    sensitive = bool(data_types) or org in ("Healthcare", "Finance", "Government")
    level = "HIGH" if sensitive else "MEDIUM"

    requirements = {
        "confidentiality": level,
        "integrity": level,
        "authentication": "REQUIRED" if re.search(REQ_TRIGGERS["authentication"], low) or sensitive else "RECOMMENDED",
        "availability": "HIGH" if re.search(REQ_TRIGGERS["high_availability"], low) else "STANDARD",
        "forward_secrecy": "REQUIRED" if re.search(REQ_TRIGGERS["forward_secrecy"], low) or sensitive else "RECOMMENDED",
        "long_term_secrecy": "REQUIRED" if re.search(REQ_TRIGGERS["long_term_secrecy"], low) or duration_years >= 10 else "OPTIONAL",
        "crypto_agility": "REQUIRED" if re.search(REQ_TRIGGERS["crypto_agility"], low) else "RECOMMENDED",
        "legacy_compatibility": "REQUIRED" if re.search(REQ_TRIGGERS["legacy_compatibility"], low) else "NOT REQUIRED",
    }

    current_crypto = sorted({name for name, pat in CRYPTO_RULES if re.search(pat, low)})

    threat = "quantum + classical" if re.search(r"quantum|future|harvest", low) else "classical"

    # Deterministic recommendation derived from the spec (the engine's voice).
    recommendation = {
        "kem": "ML-KEM-768" if duration_years < 40 else "ML-KEM-1024",
        "sig": "ML-DSA-65" if duration_years < 40 else "ML-DSA-87",
        "aead": "AES-256-GCM",
        "deployment": ("hybrid (classical + PQC) first — legacy compatibility required"
                       if requirements["legacy_compatibility"] == "REQUIRED"
                       else "PQC-first with classical fallback"),
    }

    return {
        "organization": org,
        "data_types": data_types or ["unspecified"],
        "confidentiality_duration_years": duration_years,
        "duration_evidence": duration_evidence,
        "requirements": requirements,
        "current_crypto": current_crypto or ["none detected"],
        "threat_model": threat,
        "recommendation": recommendation,
        "extractor": "rule-based v1 (LLM-ready gateway)",
    }
