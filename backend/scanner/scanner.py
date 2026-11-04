"""Q-SHIELD Cryptographic Discovery Engine (design doc Module 3).

Scans a source tree for cryptographic usage and produces a structured
inventory. Milestone 3 implementation: deterministic pattern rules with
key-size extraction and usage heuristics. Known limitations (documented,
not hidden): no data-flow analysis, so variable indirection can be missed
and false positives are possible — the risk engine consumes findings with
that caveat.

Run from repo root:
    python -m backend.scanner.scanner [path]     (default: demo/vulnerable_app)
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist",
             "build", "data", "keys", "transfer", "results", ".zcode"}
SCANNABLE_SUFFIXES = {
    ".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".c", ".cpp", ".h",
    ".cs", ".conf", ".cfg", ".ini", ".cnf", ".env", ".yml", ".yaml", ".json",
    ".xml", ".properties", ".txt", ".pem", ".cert",
}
MAX_FILE_BYTES = 512_000


@dataclass
class Rule:
    rule_id: str
    pattern: re.Pattern
    algorithm: str
    category: str          # shor_vulnerable | grover_weak | broken_classical
                           # | legacy_protocol | implementation_risk | quantum_resistant
    severity: int          # 0-10 algorithmic severity (risk engine input)
    description: str
    fix: str


def _r(rule_id, pattern, algorithm, category, severity, description, fix):
    return Rule(rule_id, re.compile(pattern, re.IGNORECASE), algorithm,
                category, severity, description, fix)


RULES: list[Rule] = [
    # --- Shor-vulnerable public key cryptography ---------------------------
    _r("RSA-KEYGEN", r"rsa\.generate_private_key|RSAGeneration|generateKey\(\s*['\"]rsa", "RSA", "shor_vulnerable", 10,
       "RSA key generation — broken by Shor's algorithm on a cryptographically relevant quantum computer (CRQC).", "Migrate to ML-KEM (key establishment) and ML-DSA (signatures); run hybrid during transition."),
    _r("RSA-NAME", r"\bRSA[-_ ]?(\d{3,4})\b", "RSA", "shor_vulnerable", 10,
       "RSA key material or configuration referenced by name.", "Plan migration to ML-DSA (signatures) / hybrid ML-KEM (encryption)."),
    _r("RSA-JWT", r"['\"]?alg['\"]?\s*[:=]\s*['\"]RS(256|384|512)['\"]|algorithm\s*=\s*['\"]RS(256|384|512)['\"]", "RSA (JWT RS*)", "shor_vulnerable", 10,
       "JWT signed with RSA — signatures fail against Shor's algorithm.", "Use ML-DSA-based tokens or hybrid signatures."),
    _r("RSA-PKCS1", r"padding\.PKCS1v15|PKCS1v15|RSA_PKCS1_PADDING", "RSA (PKCS#1 v1.5)", "shor_vulnerable", 10,
       "RSA PKCS#1 v1.5 — Shor-vulnerable and also padding-oracle-prone.", "Move to ML-DSA for signatures."),
    _r("ECDSA", r"\bECDSA\b|['\"]ES(256|384|512)['\"]|algorithm\s*=\s*['\"]ES(256|384|512)['\"]|SECP256K1", "ECDSA", "shor_vulnerable", 10,
       "Elliptic-curve signatures — broken by Shor's algorithm.", "Replace with ML-DSA."),
    _r("ECC-KEYGEN", r"ec\.generate_private_key|SECP256R1|SECP384R1|prime256v1", "ECC (ECDSA/ECDH)", "shor_vulnerable", 10,
       "Elliptic-curve key generation — the curve is used for signatures or key agreement, both broken by Shor's algorithm.", "Replace with ML-DSA (signatures) / hybrid ML-KEM (key agreement)."),
    _r("ECDH", r"\bECDH\b|X25519|Curve25519", "ECDH/X25519", "shor_vulnerable", 9,
       "Elliptic-curve key agreement — broken by Shor's algorithm.", "Use hybrid key agreement (X25519 + ML-KEM-768)."),
    _r("DH", r"Diffie[- ]Hellman|\bdh\.generate_parameters|\bDH\b(?!S)", "Diffie-Hellman", "shor_vulnerable", 9,
       "Finite-field DH — broken by Shor's algorithm.", "Use hybrid key agreement (X25519 + ML-KEM-768)."),
    _r("DSA", r"\bdsa\.generate_private_key|\bDSA\b(?!A)", "DSA", "shor_vulnerable", 10,
       "Digital Signature Algorithm — broken by Shor's algorithm.", "Replace with ML-DSA."),

    # --- Broken / deprecated classical primitives --------------------------
    _r("MD5", r"hashlib\.md5|Crypto\.Hash\.MD5|\bMD5\b", "MD5", "broken_classical", 9,
       "MD5 is cryptographically broken (collisions practical since 2004).", "Replace with SHA-256/SHA-3; use HMAC for keyed integrity; Argon2/bcrypt for passwords."),
    _r("SHA1", r"hashlib\.sha1|Crypto\.Hash\.SHA1|['\"]sha1['\"]|\bSHA-?1\b", "SHA-1", "broken_classical", 8,
       "SHA-1 is collision-broken; deprecated for all security uses.", "Replace with SHA-256/SHA-3."),
    _r("RC4", r"\bRC4\b|ARC4", "RC4", "broken_classical", 9,
       "RC4 stream cipher is broken and prohibited.", "Use AES-256-GCM."),
    _r("DES", r"\bDES3\b|TripleDES|\bDES\b.*MODE|MODE_?DES\b", "DES/3DES", "broken_classical", 8,
       "DES/3DES have tiny effective key sizes; deprecated.", "Use AES-256-GCM."),

    # --- Grover-affected symmetric -----------------------------------------
    _r("AES128", r"\bAES[-_ ]?128\b|key_size\s*=\s*128", "AES-128", "grover_weak", 6,
       "AES-128 halves to ~64-bit quantum security under Grover's algorithm — below the long-term bar.", "Move to AES-256."),
    _r("AES192", r"\bAES[-_ ]?192\b", "AES-192", "grover_weak", 5,
       "AES-192 retains ~96-bit quantum security — marginal for 30-year horizons.", "Prefer AES-256."),
    _r("AES256", r"\bAES[-_ ]?256\b", "AES-256", "quantum_resistant", 2,
       "AES-256 remains quantum-resistant (Grover leaves ~128-bit security).", "Keep; ensure AEAD mode."),
    _r("SHA256", r"\bSHA[-_ ]?256\b|hashlib\.sha256", "SHA-256", "quantum_resistant", 2,
       "SHA-256 remains acceptable post-quantum (Grover resistance via 256-bit output).", "Keep; SHA-384/SHA-3 optional."),

    # --- Modes / implementation pitfalls ------------------------------------
    _r("ECB", r"AES\.MODE_ECB|MODE_?ECB\b", "ECB mode", "implementation_risk", 8,
       "ECB mode leaks patterns and provides no semantic security (independent of quantum risk).", "Use an AEAD mode: AES-256-GCM."),
    _r("TLS-VERIFY-OFF", r"verify\s*=\s*False|CERT_NONE|_create_unverified_context|check_hostname\s*=\s*False", "TLS verification disabled", "implementation_risk", 9,
       "Certificate verification disabled — trivially exploitable by MITM today (no quantum needed).", "Enable verification; pin or use a proper trust store."),
    _r("TLS-LEGACY", r"PROTOCOL_TLSv1_1|PROTOCOL_TLSv1\b|TLSv1\.0|TLSv1\.1|SSLv3", "Legacy TLS", "legacy_protocol", 8,
       "TLS below 1.2 is deprecated and commonly configured with RSA key exchange (harvest-now-decrypt-later exposure).", "Enforce TLS 1.3 with hybrid groups (e.g., X25519MLKEM768)."),
    _r("TLS-NORMAL", r"TLSv1\.2|TLSv1\.3|PROTOCOL_TLS_CLIENT", "TLS 1.2/1.3", "quantum_resistant", 2,
       "Modern TLS in use; classical key exchange inside it is still Shor-vulnerable.", "Adopt TLS 1.3 hybrid key exchange."),
    _r("X509-CERT", r"BEGIN CERTIFICATE|BEGIN (RSA |EC )?PRIVATE KEY", "X.509 certificate/key", "shor_vulnerable", 8,
       "Certificate/keys present — verify the algorithm; RSA/ECDSA certificates are Shor-vulnerable.", "Inventory certificate lifetimes; plan ML-DSA re-issuance."),
    _r("OPENSSL-CIPHERS", r"ssl_ciphers\b", "TLS cipher configuration", "legacy_protocol", 5,
       "Custom TLS cipher configuration detected — check for RSA key-exchange suites.", "Prefer TLS 1.3 defaults; add hybrid KEM groups."),
]

USAGE_KEYWORDS = {
    "authentication": ("auth", "login", "session", "token", "jwt"),
    "key_agreement": ("exchange", "handshake", "shared_secret", "ecdh", "kem"),
    "data_encryption": ("record", "encrypt", "cipher", "storage", "patient"),
    "integrity": ("checksum", "digest", "integrity", "hash"),
    "signing": ("sign", "referral", "certificate", "crt"),
}


@dataclass
class Finding:
    file: str
    line: int
    snippet: str
    algorithm: str
    category: str
    key_size: int | None
    usage: str
    description: str
    fix: str
    rule_id: str
    severity: int = 0       # filled by the risk engine
    risk_score: float = 0.0
    risk_band: str = ""


def _classify_usage(path: Path, text: str) -> str:
    haystack = (str(path) + " " + text[:4000]).lower()
    best, best_hits = "other", 0
    for usage, keywords in USAGE_KEYWORDS.items():
        hits = sum(1 for kw in keywords if kw in haystack)
        if hits > best_hits:
            best, best_hits = usage, hits
    return best


def _scan_text(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    usage = _classify_usage(path, text)
    lines = text.splitlines()
    emitted: set[tuple] = set()
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            key = (rule.rule_id, line_no)
            if key in emitted:      # one finding per rule per line
                continue
            emitted.add(key)
            snippet = lines[line_no - 1].strip()[:160] if line_no <= len(lines) else ""
            key_size = None
            m_size = re.search(r"(\d{3,4})", match.group(0))
            if m_size and rule.algorithm in ("RSA", "AES-128", "AES-192", "AES-256"):
                size = int(m_size.group(1))
                if rule.algorithm == "RSA" and size in (1024, 2048, 3072, 4096):
                    key_size = size
                elif rule.algorithm.startswith("AES") and size in (128, 192, 256):
                    key_size = size
            findings.append(Finding(
                file=str(path).replace("\\", "/"), line=line_no, snippet=snippet,
                algorithm=rule.algorithm, category=rule.category, key_size=key_size,
                usage=usage, description=rule.description, fix=rule.fix,
                rule_id=rule.rule_id, severity=rule.severity,
            ))
    return findings


def scan_project(root: str | Path) -> dict:
    """Scan a directory tree; returns the cryptographic inventory."""
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"scan target does not exist: {root}")

    findings: list[Finding] = []
    files_scanned = 0
    skipped = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            skipped += 1
            continue
        if path.suffix.lower() not in SCANNABLE_SUFFIXES:
            skipped += 1
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                skipped += 1
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped += 1
            continue
        files_scanned += 1
        findings.extend(_scan_text(path, text))

    return {
        "root": str(root).replace("\\", "/"),
        "files_scanned": files_scanned,
        "files_skipped": skipped,
        "findings": [asdict(f) for f in findings],
    }


if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "demo/vulnerable_app"
    result = scan_project(target)
    by_alg: dict[str, int] = {}
    for f in result["findings"]:
        by_alg[f["algorithm"]] = by_alg.get(f["algorithm"], 0) + 1
    print(f"Scanned {result['files_scanned']} files under {result['root']}")
    for alg, count in sorted(by_alg.items(), key=lambda kv: -kv[1]):
        print(f"  {alg:<28} x{count}")
    print(f"Total findings: {len(result['findings'])}")
