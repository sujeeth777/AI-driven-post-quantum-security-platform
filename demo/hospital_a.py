"""Q-SHIELD demo — Hospital A: send a patient record to Hospital B.

Pipeline (design doc §13):
    Medical data -> AES-256-GCM encryption
                 -> hybrid session key (ML-KEM-768 + X25519 -> HKDF-SHA-256)
                 -> ML-DSA-65 transcript signature
                 -> secure package -> transfer/

Run from repo root:  python -m demo.hospital_a
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from backend.crypto.hybrid import build_package
from demo.identities import ensure_identity

TRANSFER_DIR = Path("transfer")


def make_record() -> dict:
    return {
        "patient_id": "P001",
        "type": "medical_record_bundle",
        "created": datetime.now(timezone.utc).isoformat(),
        "mri_report": "No acute abnormality; follow-up in 6 months.",
        "blood_test": {"hemoglobin": "13.8 g/dL", "wbc": "7.2 K/uL", "glucose": "95 mg/dL"},
        "diagnosis": "Stable; continue current treatment plan",
        "prescription": "Medication X, 10 mg, once daily",
        "attending": "Dr. Ramirez, Hospital A",
    }


def main() -> int:
    print("=" * 62)
    print("Q-SHIELD DEMO — HOSPITAL A (sender)")
    print("=" * 62)

    hospital_a = ensure_identity("hospital-a")
    hospital_b = ensure_identity("hospital-b")

    record = make_record()
    message = json.dumps(record, indent=2).encode("utf-8")

    print(f"\n[1] Composed medical record for patient {record['patient_id']}"
          f" ({len(message)} bytes)")

    print("[2] Hybrid key establishment: ML-KEM-768 encapsulate + X25519 ECDH"
          " -> HKDF-SHA-256 session key")
    pkg = build_package(message, hospital_a, hospital_b)

    print("[3] AES-256-GCM encryption of record")
    print("[4] ML-DSA-65 signature over package transcript")

    TRANSFER_DIR.mkdir(exist_ok=True)
    out_path = TRANSFER_DIR / f"package-{pkg['msg_id']}.json"
    out_path.write_text(json.dumps(pkg, indent=2), encoding="utf-8")

    print(f"[5] Secure package written: {out_path}")
    print(f"    msg_id   : {pkg['msg_id']}")
    print(f"    package  : {len(json.dumps(pkg))} bytes"
          f" (payload {len(message)} bytes + PQC overhead)")
    print("\nNext:  python -m demo.hospital_b")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
