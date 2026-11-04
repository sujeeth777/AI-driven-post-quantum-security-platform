"""Q-SHIELD PQC Benchmarking Laboratory — Milestone 1.

Measures key generation, encapsulation/decapsulation, signing/verification,
and encryption/decryption for post-quantum and classical primitives, plus
the full hybrid exchange. Results land in research/results/ as JSON + CSV.

Run from repo root:
    python -m backend.benchmarks.bench [--quick] [--iterations N]
"""

from __future__ import annotations

import argparse
import csv
import json
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from backend.crypto import classical, kem, signatures, symmetric
from backend.crypto.hybrid import (
    EndpointKeys,
    build_package,
    derive_session_key,
    open_package,
)

RESULTS_DIR = Path("research/results")
MESSAGE = b"Q-SHIELD benchmark payload" * 40  # ~1 KiB


def measure(op, iterations: int) -> dict:
    """Time an operation, returning ms statistics."""
    samples = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        op()
        samples.append((time.perf_counter() - t0) * 1000)
    samples.sort()
    p95_idx = min(len(samples) - 1, int(round(0.95 * len(samples))) - 1)
    return {
        "iterations": iterations,
        "mean_ms": statistics.fmean(samples),
        "median_ms": statistics.median(samples),
        "p95_ms": samples[p95_idx],
        "min_ms": samples[0],
    }


def bench_crypto(its: int, keygen_its: int) -> list[dict]:
    """Collect per-primitive benchmark rows."""
    rows: list[dict] = []

    def add(primitive, family, op, stats, **sizes):
        rows.append({"primitive": primitive, "family": family, "op": op, **stats,
                     **{k: v for k, v in sizes.items() if v is not None}})

    def timed(primitive, family, make_op, ops=("keygen",), n=its, kn=None):
        kn = kn or keygen_its
        for op_name in ops:
            if op_name == "keygen":
                stats = measure(make_op(), kn)
            else:
                stats = measure(make_op(), n)
            sizes = size_probe(primitive)
            add(primitive, family, op_name, stats, **sizes)

    # --- Post-quantum primitives -----------------------------------------
    kem_sk = kem.keygen()
    kem_pk = kem_sk.public_key()
    ss, kem_ct = kem.encapsulate(kem_pk)
    add("ML-KEM-768", "PQC KEM", "keygen", measure(lambda: kem.keygen(), keygen_its),
        public_key=kem.public_key_bytes(kem_pk).__len__(), ciphertext=len(kem_ct),
        shared_secret=len(ss))
    add("ML-KEM-768", "PQC KEM", "encapsulate", measure(lambda: kem.encapsulate(kem_pk), its))
    add("ML-KEM-768", "PQC KEM", "decapsulate",
        measure(lambda: kem.decapsulate(kem_sk, kem_ct), its))

    sig_sk = signatures.keygen()
    sig_pk = sig_sk.public_key()
    sig = signatures.sign(sig_sk, MESSAGE)
    add("ML-DSA-65", "PQC signature", "keygen",
        measure(lambda: signatures.keygen(), keygen_its),
        public_key=len(signatures.public_key_bytes(sig_pk)), signature=len(sig))
    add("ML-DSA-65", "PQC signature", "sign",
        measure(lambda: signatures.sign(sig_sk, MESSAGE), its), message_size=len(MESSAGE))
    add("ML-DSA-65", "PQC signature", "verify",
        measure(lambda: signatures.verify(sig_pk, sig, MESSAGE), its))

    # --- Classical baseline (quantum-vulnerable / quantum-affected) -------
    rsa_sk = classical.rsa_keygen()
    rsa_pk = rsa_sk.public_key()
    rsa_sig = classical.rsa_sign(rsa_sk, MESSAGE)
    add("RSA-2048", "classical (Shor-vulnerable)", "keygen",
        measure(classical.rsa_keygen, max(5, keygen_its // 20)),
        public_key=rsa_pk.key_size // 8, signature=len(rsa_sig))
    add("RSA-2048", "classical (Shor-vulnerable)", "sign",
        measure(lambda: classical.rsa_sign(rsa_sk, MESSAGE), its))
    add("RSA-2048", "classical (Shor-vulnerable)", "verify",
        measure(lambda: classical.rsa_verify(rsa_pk, rsa_sig, MESSAGE), its))
    rsa_ct = classical.rsa_encrypt(rsa_pk, MESSAGE[:190])
    add("RSA-2048-OAEP", "classical (Shor-vulnerable)", "encrypt",
        measure(lambda: classical.rsa_encrypt(rsa_pk, MESSAGE[:190]), its),
        ciphertext=len(rsa_ct))
    add("RSA-2048-OAEP", "classical (Shor-vulnerable)", "decrypt",
        measure(lambda: classical.rsa_decrypt(rsa_sk, rsa_ct), its))

    x_sk = classical.x25519_keygen()
    x_peer = classical.x25519_keygen()
    add("X25519", "classical KEX", "keygen",
        measure(classical.x25519_keygen, keygen_its))
    add("X25519", "classical KEX", "ecdh",
        measure(lambda: classical.x25519_shared_secret(x_sk, x_peer.public_key()), its))

    ed_sk = classical.ed25519_keygen()
    ed_sig = classical.ed25519_sign(ed_sk, MESSAGE)
    add("Ed25519", "classical signature", "keygen",
        measure(classical.ed25519_keygen, keygen_its))
    add("Ed25519", "classical signature", "sign",
        measure(lambda: classical.ed25519_sign(ed_sk, MESSAGE), its))
    add("Ed25519", "classical signature", "verify",
        measure(lambda: classical.ed25519_verify(ed_sk.public_key(), ed_sig, MESSAGE), its))

    # --- Symmetric (quantum-affected only by Grover) -----------------------
    aes_key = bytes(32)
    for label, payload in (("1 KiB", MESSAGE), ("64 KiB", MESSAGE * 64)):
        nonce, aes_ct = symmetric.encrypt(aes_key, payload)
        add(f"AES-256-GCM ({label})", "symmetric", "encrypt",
            measure(lambda p=payload: symmetric.encrypt(aes_key, p), its),
            message_size=len(payload))
        add(f"AES-256-GCM ({label})", "symmetric", "decrypt",
            measure(lambda: symmetric.decrypt(aes_key, nonce, aes_ct), its))

    # --- Full hybrid exchange ----------------------------------------------
    alice = EndpointKeys("bench-a", kem.keygen(), signatures.keygen(),
                         classical.x25519_keygen())
    bob = EndpointKeys("bench-b", kem.keygen(), signatures.keygen(),
                       classical.x25519_keygen())
    pkg = build_package(MESSAGE, alice, bob)
    a_pk = classical.x25519_public_bytes(alice.x25519_sk)
    add("Hybrid exchange (full)", "Q-SHIELD channel", "build_package",
        measure(lambda: build_package(MESSAGE, alice, bob), its),
        package_size=len(json.dumps(pkg)))
    add("Hybrid exchange (full)", "Q-SHIELD channel", "open_package",
        measure(lambda: open_package(dict(pkg), bob, alice.sig_pk, a_pk), its))

    ss1, _ = kem.encapsulate(bob.kem_pk)
    ss2 = classical.x25519_shared_secret(alice.x25519_sk, bob.x25519_sk.public_key())
    add("Hybrid KDF (HKDF-SHA256)", "Q-SHIELD channel", "derive_session_key",
        measure(lambda: derive_session_key(ss1, ss2), its))

    # remove the size_probe leftovers if any (rows carry explicit sizes)
    return rows


def size_probe(_primitive):
    return {}


def write_outputs(rows: list[dict], meta: dict) -> tuple[Path, Path]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    json_path = RESULTS_DIR / f"benchmark-{stamp}.json"
    json_path.write_text(json.dumps({"meta": meta, "results": rows}, indent=2),
                         encoding="utf-8")

    csv_path = RESULTS_DIR / f"benchmark-{stamp}.csv"
    fields = ["primitive", "family", "op", "iterations",
              "mean_ms", "median_ms", "p95_ms", "min_ms",
              "public_key", "ciphertext", "shared_secret", "signature",
              "message_size", "package_size"]
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return json_path, csv_path


def print_table(rows: list[dict]) -> None:
    print(f"{'Primitive':<28} {'Operation':<20} {'Mean ms':>9} {'P95 ms':>9}  Sizes")
    print("-" * 88)
    for row in rows:
        sizes = []
        for key, label in (("public_key", "pk"), ("signature", "sig"),
                           ("ciphertext", "ct"), ("package_size", "pkg"),
                           ("message_size", "msg")):
            if row.get(key) is not None:
                sizes.append(f"{label}={row[key]}B")
        print(f"{row['primitive']:<28} {row['op']:<20} "
              f"{row['mean_ms']:>9.3f} {row['p95_ms']:>9.3f}  {' '.join(sizes)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Q-SHIELD PQC benchmarks")
    parser.add_argument("--iterations", type=int, default=200,
                        help="iterations per operation (default 200)")
    parser.add_argument("--keygen-iterations", type=int, default=50,
                        help="iterations for key generation (default 50)")
    parser.add_argument("--quick", action="store_true",
                        help="reduced iterations for a fast smoke run")
    args = parser.parse_args()
    if args.quick:
        args.iterations, args.keygen_its = 20, 10
    else:
        args.keygen_its = args.keygen_iterations

    print("Q-SHIELD PQC BENCHMARKING LABORATORY")
    print(f"iterations={args.iterations} keygen_iterations={args.keygen_its}\n")

    rows = bench_crypto(args.iterations, args.keygen_its)
    print_table(rows)

    meta = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "python": sys.version.split()[0],
        "message_size": len(MESSAGE),
        "iterations": args.iterations,
        "keygen_iterations": args.keygen_its,
    }
    json_path, csv_path = write_outputs(rows, meta)
    print(f"\nSaved: {json_path}")
    print(f"Saved: {csv_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
