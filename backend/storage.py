"""Q-SHIELD platform storage — JSON-file backed, Postgres-swappable.

Milestone-appropriate persistence: a single JSON document with a thread
lock and atomic writes. The interface (save_scan, save_benchmark, audit...)
is what matters; a SQLAlchemy/Postgres backend can implement the same
surface when the platform outgrows single-node demos.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

STORE_PATH = Path("data/store.json")
_LOCK = threading.Lock()
_EMPTY = {
    "scans": [], "benchmarks": [], "requirements": [],
    "packages": [], "audit": [], "seen_msg_ids": [],
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load() -> dict:
    if STORE_PATH.exists():
        try:
            data = json.loads(STORE_PATH.read_text(encoding="utf-8"))
            for key, default in _EMPTY.items():
                data.setdefault(key, json.loads(json.dumps(default)))
            return data
        except (json.JSONDecodeError, OSError):
            pass
    return json.loads(json.dumps(_EMPTY))


def _save(data: dict) -> None:
    STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STORE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    tmp.replace(STORE_PATH)


def save_scan(assessment: dict) -> int:
    with _LOCK:
        data = _load()
        scan_id = (max((s["id"] for s in data["scans"]), default=0)) + 1
        record = {"id": scan_id, "timestamp": _now(), **assessment}
        data["scans"].append(record)
        data["scans"] = data["scans"][-20:]
        _save(data)
    audit("SCAN", f"scan #{scan_id}: {len(assessment['findings'])} findings, "
                  f"exposure {assessment['exposure']['score']}")
    return scan_id


def latest_scan() -> dict | None:
    with _LOCK:
        scans = _load()["scans"]
        return scans[-1] if scans else None


def get_scan(scan_id: int) -> dict | None:
    with _LOCK:
        for s in _load()["scans"]:
            if s["id"] == scan_id:
                return s
    return None


def save_benchmark(meta: dict, rows: list[dict]) -> int:
    with _LOCK:
        data = _load()
        bench_id = (max((b["id"] for b in data["benchmarks"]), default=0)) + 1
        data["benchmarks"].append({"id": bench_id, "timestamp": _now(),
                                   "meta": meta, "rows": rows})
        data["benchmarks"] = data["benchmarks"][-10:]
        _save(data)
    return bench_id


def latest_benchmark() -> dict | None:
    with _LOCK:
        benches = _load()["benchmarks"]
        return benches[-1] if benches else None


def save_requirements(spec: dict) -> int:
    with _LOCK:
        data = _load()
        req_id = (max((r["id"] for r in data["requirements"]), default=0)) + 1
        data["requirements"].append({"id": req_id, "timestamp": _now(), **spec})
        data["requirements"] = data["requirements"][-20:]
        _save(data)
    return req_id


def record_package(meta: dict) -> None:
    with _LOCK:
        data = _load()
        data["packages"].append({"timestamp": _now(), **meta})
        data["packages"] = data["packages"][-50:]
        _save(data)


def seen_msg_ids() -> list[str]:
    with _LOCK:
        return list(_load()["seen_msg_ids"])


def mark_seen(msg_id: str) -> None:
    with _LOCK:
        data = _load()
        if msg_id not in data["seen_msg_ids"]:
            data["seen_msg_ids"].append(msg_id)
            data["seen_msg_ids"] = data["seen_msg_ids"][-500:]
            _save(data)


def audit(event: str, detail: str) -> None:
    with _LOCK:
        data = _load()
        data["audit"].append({"timestamp": _now(), "event": event, "detail": detail})
        data["audit"] = data["audit"][-300:]
        _save(data)


def get_audit(limit: int = 60) -> list[dict]:
    with _LOCK:
        return list(reversed(_load()["audit"]))[:limit]


def reset_seen() -> None:
    with _LOCK:
        data = _load()
        data["seen_msg_ids"] = []
        _save(data)
