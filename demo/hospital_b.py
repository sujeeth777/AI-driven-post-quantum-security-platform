"""Q-SHIELD demo — Hospital B: receive, verify, and decrypt the package.

Receiver-side order of operations (the security argument):
    verify ML-DSA  ->  check replay  ->  decapsulate ML-KEM
    ->  derive hybrid key  ->  decrypt AES-256-GCM  ->  store record

Run from repo root:  python -m demo.hospital_b
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from backend.crypto import classical
from backend.crypto.hybrid import (
    PackageError,
    open_package,
)
from demo.identities import ensure_identity

TRANSFER_DIR = Path("transfer")
SEEN_IDS_PATH = TRANSFER_DIR / "seen_ids.json"
AUDIT_LOG_PATH = TRANSFER_DIR / "audit.log"


def load_seen_ids() -> set:
    if SEEN_IDS_PATH.exists():
        return set(json.loads(SEEN_IDS_PATH.read_text(encoding="utf-8")))
    return set()


def save_seen_ids(seen: set) -> None:
    SEEN_IDS_PATH.write_text(json.dumps(sorted(seen)), encoding="utf-8")


def audit(event: str, detail: str) -> None:
    line = (f"{datetime.now(timezone.utc).isoformat()} | {event:<10} | {detail}")
    print(f"    [audit] {line}")
    with AUDIT_LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def find_package() -> Path:
    packages = TRANSFER_DIR.glob("package-*.json")
    newest = max(packages, key=lambda p: p.stat().st_mtime, default=None)
    if newest is None:
        raise SystemExit("No packages in transfer/. Run: python -m demo.hospital_a")
    return newest


def main() -> int:
    print("=" * 62)
    print("Q-SHIELD DEMO — HOSPITAL B (receiver)")
    print("=" * 62)

    hospital_a = ensure_identity("hospital-a")
    hospital_b = ensure_identity("hospital-b")

    pkg_path = find_package()
    pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
    print(f"\n[1] Loaded package {pkg_path.name} "
          f"from {pkg['from']} -> {pkg['to']}")

    seen = load_seen_ids()
    a_x25519_pk = classical.x25519_public_bytes(hospital_a.x25519_sk)

    print("[2] Verifying ML-DSA-65 transcript signature...")
    print("[3] Checking replay ledger...")
    print("[4] Decapsulating ML-KEM-768 + X25519 -> HKDF session key...")
    print("[5] Decrypting AES-256-GCM record...\n")
    try:
        plaintext = open_package(pkg, hospital_b, hospital_a.sig_pk, a_x25519_pk,
                                 seen_msg_ids=seen)
    except PackageError as exc:
        audit("REJECT", f"{pkg_path.name}: {exc}")
        save_seen_ids(seen)
        print(f"PACKAGE REJECTED: {exc}")
        return 1

    audit("ACCEPT", f"{pkg_path.name}: verified + decrypted")
    save_seen_ids(seen)

    record = json.loads(plaintext)
    print("RECORD ACCEPTED AND DECRYPTED")
    print("-" * 62)
    print(f"  Patient      : {record['patient_id']}")
    print(f"  MRI report   : {record['mri_report']}")
    print(f"  Blood test   : {record['blood_test']}")
    print(f"  Diagnosis    : {record['diagnosis']}")
    print(f"  Prescription : {record['prescription']}")
    print(f"  Attending    : {record['attending']}")
    print("-" * 62)
    print("Cryptographic protection: ML-KEM-768 + X25519 (hybrid),"
          " ML-DSA-65, AES-256-GCM")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
