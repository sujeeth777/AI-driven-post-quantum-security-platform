"""Q-SHIELD Web Control Center — FastAPI application.

Serves the SPA frontend and the platform API:
    /api/*       platform endpoints (scanner, risk, migration, exchange, AI)
    /static/*    frontend assets
    /            the web control center

Run from repo root:
    python -m backend.api.app            (serves on http://127.0.0.1:8000)
"""

from __future__ import annotations

import base64
import json
import threading
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.ai.assistant import answer as assistant_answer
from backend.ai.analyzer import extract_requirements
from backend.crypto import classical
from backend.crypto.agility import CryptoPolicy, available_algorithms
from backend.crypto.hybrid import (
    AuthenticationError,
    EndpointKeys,
    PackageError,
    ReplayError,
    build_package,
    open_package,
)
from backend.crypto import session as session_mod
from backend.migration.planner import build_plan
from backend.risk.engine import assess_scan
from backend.scanner.scanner import scan_project
from backend import storage

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"
DEFAULT_SCAN_TARGET = "demo/vulnerable_app"

app = FastAPI(title="Q-SHIELD", version="1.0.0",
              description="AI-Driven Post-Quantum Security & Healthcare Privacy Platform")

_identity_lock = threading.Lock()
_identities: dict[tuple[str, str, str], EndpointKeys] = {}


def identity(name: str, policy: CryptoPolicy) -> EndpointKeys:
    """Cached, thread-safe per-policy endpoint identity (demo keys)."""
    key = (name, policy.kem, policy.sig)
    with _identity_lock:
        if key not in _identities:
            from demo.identities import ensure_identity
            _identities[key] = ensure_identity(name, policy)
        return _identities[key]


# --- request models --------------------------------------------------------


class ScanRequest(BaseModel):
    path: str = DEFAULT_SCAN_TARGET
    exposure: str = Field("public", pattern="^(public|internal|isolated)$")
    data_lifetime_years: float = Field(30.0, ge=0.5, le=100)


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=8, max_length=4000)


class AskRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=1000)


class SendRequest(BaseModel):
    record: dict | None = None
    kem: str = "ML-KEM-768"
    sig: str = "ML-DSA-65"


class AttackRequest(BaseModel):
    msg_id: str
    kind: str = Field(..., pattern="^(tamper|mitm|forge|replay)$")


# --- overview --------------------------------------------------------------


@app.get("/api/overview")
def overview():
    scan = storage.latest_scan()
    bench = storage.latest_benchmark()
    return {
        "platform": "Q-SHIELD",
        "version": "1.0.0",
        "scan": scan,
        "benchmark": {"id": bench["id"], "timestamp": bench["timestamp"]} if bench else None,
        "supported": available_algorithms(),
        "vulnerable_demo_app": DEFAULT_SCAN_TARGET,
    }


# --- scanner + risk --------------------------------------------------------


@app.post("/api/scan")
def run_scan(req: ScanRequest):
    try:
        scan = scan_project(req.path)
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    if not scan["files_scanned"]:
        raise HTTPException(422, "no scannable files found at that path")
    assessment = assess_scan(scan, req.exposure, req.data_lifetime_years)
    scan_id = storage.save_scan(assessment)
    return {"scan_id": scan_id, **assessment}


@app.get("/api/scan/latest")
def latest_scan():
    scan = storage.latest_scan()
    if not scan:
        raise HTTPException(404, "no scan yet — POST /api/scan first")
    return scan


# --- migration -------------------------------------------------------------


@app.get("/api/migration/latest")
def latest_migration():
    scan = storage.latest_scan()
    if not scan:
        raise HTTPException(404, "no scan yet — run a scan first")
    return build_plan(scan)


# --- benchmarking ----------------------------------------------------------


@app.post("/api/benchmark/run")
def run_benchmark():
    """Runs a compact benchmark synchronously (~4-8 s) and stores it."""
    from backend.benchmarks.bench import bench_crypto, write_outputs
    rows = bench_crypto(its=30, keygen_its=10)
    try:
        json_path, _ = write_outputs(rows, {"mode": "api"})
    except Exception:  # noqa: BLE001 - results dir issues must not break the API
        json_path = None
    bench_id = storage.save_benchmark({"mode": "api"}, rows)
    storage.audit("BENCH", f"benchmark #{bench_id}: {len(rows)} measurements")
    return {"benchmark_id": bench_id, "rows": rows, "artifact": str(json_path) if json_path else None}


@app.get("/api/benchmark/latest")
def latest_benchmark():
    bench = storage.latest_benchmark()
    if not bench:
        raise HTTPException(404, "no benchmark yet — POST /api/benchmark/run first")
    return bench


# --- secure exchange -------------------------------------------------------


def _policy(kem: str, sig: str) -> CryptoPolicy:
    try:
        return CryptoPolicy(kem=kem, sig=sig)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(422, f"invalid policy: {exc}") from exc


@app.post("/api/exchange/send")
def exchange_send(req: SendRequest):
    policy = _policy(req.kem, req.sig)
    hospital_a = identity("hospital-a", policy)
    hospital_b = identity("hospital-b", policy)

    record = req.record or {
        "patient_id": "P001",
        "type": "medical_record_bundle",
        "mri_report": "No acute abnormality; follow-up in 6 months.",
        "blood_test": {"hemoglobin": "13.8 g/dL", "wbc": "7.2 K/uL"},
        "diagnosis": "Stable; continue current treatment plan",
        "prescription": "Medication X, 10 mg, once daily",
    }
    message = json.dumps(record, indent=2).encode("utf-8")

    t0 = time.perf_counter()
    pkg = build_package(message, hospital_a, hospital_b, policy=policy)
    build_ms = (time.perf_counter() - t0) * 1000

    msg_id = pkg["msg_id"]
    (Path("transfer")).mkdir(exist_ok=True)
    (Path("transfer") / f"package-{msg_id}.json").write_text(
        json.dumps(pkg, indent=2), encoding="utf-8")
    storage.record_package({"msg_id": msg_id, "from": "hospital-a",
                            "to": "hospital-b", "kem": policy.kem, "sig": policy.sig,
                            "build_ms": round(build_ms, 3)})
    storage.audit("SEND", f"package {msg_id} ({policy.kem}, {policy.sig})")
    return {"msg_id": msg_id, "package": pkg,
            "sizes": {"payload": len(message), "package": len(json.dumps(pkg)),
                      "kem_ct": len(base64.b64decode(pkg["kem_ct"])),
                      "signature": len(base64.b64decode(pkg["signature"]))},
            "build_ms": round(build_ms, 3), "policy": policy.algorithms}


@app.post("/api/exchange/receive/{msg_id}")
def exchange_receive(msg_id: str):
    pkg_path = Path("transfer") / f"package-{msg_id}.json"
    if not pkg_path.exists():
        raise HTTPException(404, f"package {msg_id} not found in transfer/")
    pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
    alg = pkg["algorithms"]
    policy = CryptoPolicy(kem=alg["kem"], sig=alg["sig"])
    hospital_a = identity("hospital-a", policy)
    hospital_b = identity("hospital-b", policy)

    t0 = time.perf_counter()
    try:
        plaintext = open_package(pkg, hospital_b, hospital_a.sig_pk,
                                 classical.x25519_public_bytes(hospital_a.x25519_sk),
                                 seen_msg_ids=set(storage.seen_msg_ids()) or None,
                                 policy=policy)
    except (PackageError, AuthenticationError, ReplayError) as exc:
        storage.audit("REJECT", f"package {msg_id}: {exc}")
        raise HTTPException(422, f"package rejected: {exc}") from exc
    open_ms = (time.perf_counter() - t0) * 1000

    storage.mark_seen(msg_id)
    storage.audit("RECV", f"package {msg_id} verified + decrypted ({open_ms:.2f} ms)")
    return {"record": json.loads(plaintext.decode("utf-8")),
            "open_ms": round(open_ms, 3),
            "steps": ["ML-DSA signature verified", "replay ledger checked",
                      "ML-KEM decapsulated + X25519 ECDH", "HKDF-SHA-256 session key",
                      "AES-256-GCM decrypted", "record stored + audit logged"]}


@app.post("/api/exchange/attack")
def exchange_attack(req: AttackRequest):
    pkg_path = Path("transfer") / f"package-{req.msg_id}.json"
    if not pkg_path.exists():
        raise HTTPException(404, f"package {req.msg_id} not found")
    pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
    alg = pkg["algorithms"]
    policy = CryptoPolicy(kem=alg["kem"], sig=alg["sig"])
    hospital_a = identity("hospital-a", policy)
    hospital_b = identity("hospital-b", policy)
    mallory = EndpointKeys.generate("mallory", policy)
    a_x_pk = classical.x25519_public_bytes(hospital_a.x25519_sk)

    def open_res(p, use_ledger: bool = False):
        """use_ledger=False isolates the attack's own rejection from replay checks."""
        try:
            open_package(p, hospital_b, hospital_a.sig_pk, a_x_pk,
                         seen_msg_ids=(set(storage.seen_msg_ids()) or None)
                         if use_ledger else None, policy=policy)
            return {"result": "ACCEPTED"}
        except PackageError as exc:
            return {"result": "REJECTED", "error": type(exc).__name__, "detail": str(exc)}

    if req.kind == "tamper":
        raw = bytearray(base64.b64decode(pkg["ciphertext"]))
        raw[len(raw) // 3] ^= 0x40
        pkg["ciphertext"] = base64.b64encode(bytes(raw)).decode()
        res = open_res(pkg)
    elif req.kind == "mitm":
        from backend.crypto import kem as kem_mod
        _, mitm_ct = kem_mod.encapsulate(mallory.kem_pk)
        pkg["kem_ct"] = base64.b64encode(mitm_ct).decode()
        res = open_res(pkg)
    elif req.kind == "forge":
        from backend.crypto import signatures as sig_mod
        from backend.crypto.hybrid import _canonical
        meta = {k: pkg[k] for k in ("version", "from", "to", "msg_id", "algorithms")}
        transcript = _canonical(meta) + base64.b64decode(pkg["kem_ct"])
        pkg["signature"] = base64.b64encode(
            sig_mod.sign(mallory.sig_sk, transcript)).decode()
        res = open_res(pkg)
    else:  # replay
        seen = set(storage.seen_msg_ids())
        if req.msg_id in seen:
            res = {"result": "REJECTED", "error": "ReplayError",
                   "detail": f"msg_id {req.msg_id} was already processed"}
        else:
            try:
                open_package(pkg, hospital_b, hospital_a.sig_pk, a_x_pk,
                             seen_msg_ids=seen, policy=policy)
                storage.mark_seen(req.msg_id)
                res = {"result": "ACCEPTED (first delivery recorded — send again to see rejection)"}
            except PackageError as exc:
                res = {"result": "REJECTED", "error": type(exc).__name__, "detail": str(exc)}

    storage.audit("ATTACK", f"{req.kind} against {req.msg_id}: {res['result']}")
    return {"kind": req.kind, **res}


@app.post("/api/exchange/session")
def exchange_fs_session():
    """Runs the full forward-secrecy session handshake (3 steps) and reports."""
    policy = CryptoPolicy()
    alice = identity("hospital-a", policy)
    bob = identity("hospital-b", policy)
    record = json.dumps({"patient_id": "P001", "type": "session_demo",
                         "note": "ephemeral keys, forward secrecy"}).encode()

    t0 = time.perf_counter()
    offer, responder_state = session_mod.create_offer(bob, policy)
    offer_ms = (time.perf_counter() - t0) * 1000

    t1 = time.perf_counter()
    smsg = session_mod.respond_to_offer(offer, alice, record, bob.sig_pk, policy)
    respond_ms = (time.perf_counter() - t1) * 1000

    t2 = time.perf_counter()
    plaintext = session_mod.complete_session(smsg, responder_state, bob, alice.sig_pk, policy)
    complete_ms = (time.perf_counter() - t2) * 1000

    storage.audit("SESSION", f"FS session {smsg['msg_id']} completed; ephemeral keys destroyed")
    return {
        "steps": [
            {"step": 1, "name": "Hospital B publishes signed offer (ephemeral ML-KEM + X25519 keys)",
             "ms": round(offer_ms, 3), "offer_id": offer["offer_id"]},
            {"step": 2, "name": "Hospital A encapsulates + ECDH against ephemeral keys, encrypts, signs; erases its ephemeral secret",
             "ms": round(respond_ms, 3)},
            {"step": 3, "name": "Hospital B verifies, decrypts, destroys ephemeral secrets (forward secrecy)",
             "ms": round(complete_ms, 3)},
        ],
        "record": json.loads(plaintext.decode("utf-8")),
        "sizes": {"kem_ct": len(base64.b64decode(smsg["kem_ct"])),
                  "signature": len(base64.b64decode(smsg["signature"]))},
        "forward_secrecy": ("stolen static keys CANNOT decrypt this session — ephemeral "
                            "secrets were destroyed (proven by validation test 26)"),
    }


# --- AI layer --------------------------------------------------------------


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    spec = extract_requirements(req.text)
    req_id = storage.save_requirements(spec)
    storage.audit("ANALYZE", f"requirements #{req_id}: {spec['organization']}, "
                             f"{spec['confidentiality_duration_years']}y confidentiality")
    return {"id": req_id, "spec": spec}


@app.post("/api/assistant")
def assistant(req: AskRequest):
    context = {
        "assessment": storage.latest_scan(),
        "plan": build_plan(storage.latest_scan()) if storage.latest_scan() else None,
        "benchmark": storage.latest_benchmark(),
    }
    result = assistant_answer(req.message, context)
    storage.audit("ASSISTANT", f"[{result['intent']}] {req.message[:60]}")
    return result


@app.get("/api/audit")
def audit_log(limit: int = 60):
    return storage.get_audit(limit)


@app.get("/api/policies")
def policies():
    return available_algorithms()


# --- frontend --------------------------------------------------------------


@app.get("/")
def index():
    return FileResponse(FRONTEND_DIR / "index.html")


if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


def main() -> None:
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8600, log_level="info")


if __name__ == "__main__":
    main()
