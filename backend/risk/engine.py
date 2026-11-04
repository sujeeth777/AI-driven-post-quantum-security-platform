"""Q-SHIELD Quantum Risk Engine (design doc Modules 4, 24, 25).

Deterministic, rules-based scoring — the "engine validates" half of the
AI-proposes/engine-validates principle. No ML, no LLM: every score is
explainable from its factors.

Quantum risk of a finding:
    Risk = algorithm severity + data lifetime + exposure + usage + migration difficulty
    (weighted, 0-100, banded CRITICAL/HIGH/MEDIUM/LOW)

Quantum Readiness Score (QRS): five weighted pillars, 0-100.

Harvest-now-decrypt-later: long-lifetime data protected by Shor-vulnerable
key establishment scores maximum risk even though no quantum computer
exists today — the data can be stored now and decrypted later.
"""

from __future__ import annotations

BANDS = [(80, "CRITICAL"), (60, "HIGH"), (40, "MEDIUM"), (0, "LOW")]

EXPOSURE_LEVELS = {"public": 10, "internal": 5, "isolated": 2}
USAGE_WEIGHTS = {"key_agreement": 10, "authentication": 9, "signing": 9,
                 "data_encryption": 7, "integrity": 5, "other": 4}

# Weight profile of the composite risk score (must sum to 1.0)
WEIGHTS = {"algorithm": 0.35, "lifetime": 0.20, "exposure": 0.20,
           "usage": 0.15, "migration": 0.10}


def _band(score: float) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "LOW"


def _migration_difficulty(category: str, file_hint: str) -> int:
    """How hard is replacement? (0-10, higher = harder)."""
    if file_hint.endswith((".conf", ".cnf", ".cfg", ".ini")):
        return 3                      # config change
    if category == "legacy_protocol":
        return 4
    if category == "shor_vulnerable":
        return 6                      # protocol-aware migration required
    if category in ("broken_classical", "implementation_risk"):
        return 2                      # drop-in primitive swap
    return 3


def assess_finding(finding: dict, exposure: str = "public",
                   data_lifetime_years: float = 30.0) -> dict:
    """Attach quantum risk factors to a scanner finding (mutates a copy)."""
    f = dict(finding)
    alg = float(f.get("severity", 5))
    lifetime = min(10.0, data_lifetime_years / 3.0)   # 30y+ saturates
    expo = float(EXPOSURE_LEVELS.get(exposure, 5))
    usage = float(USAGE_WEIGHTS.get(f.get("usage", "other"), 4))
    migration = float(_migration_difficulty(f.get("category", ""),
                                            f.get("file", "")))

    raw = (WEIGHTS["algorithm"] * alg + WEIGHTS["lifetime"] * lifetime +
           WEIGHTS["exposure"] * expo + WEIGHTS["usage"] * usage +
           WEIGHTS["migration"] * migration)
    score = round(100 * raw / 10, 1)

    f["risk_factors"] = {
        "algorithm_severity": round(alg, 1), "lifetime": round(lifetime, 1),
        "exposure": round(expo, 1), "usage": round(usage, 1),
        "migration_difficulty": round(migration, 1),
        "exposure_level": exposure,
        "data_lifetime_years": data_lifetime_years,
    }
    f["risk_score"] = score
    f["risk_band"] = _band(score)

    # Harvest-now-decrypt-later flag: confidential, long-lived data whose
    # confidentiality rests on Shor-vulnerable public-key crypto.
    f["hnd_l"] = (f.get("category") == "shor_vulnerable" and
                  f.get("usage") in ("key_agreement", "data_encryption",
                                     "authentication") and
                  data_lifetime_years >= 10)
    return f


BAND_WEIGHTS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 6, "LOW": 1}


def quantum_exposure(findings: list[dict]) -> dict:
    """Overall quantum exposure of a system, 0-100 (higher = worse)."""
    if not findings:
        return {"score": 0, "band": "LOW", "counts": {}}
    counts = {b: 0 for b in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for f in findings:
        counts[f["risk_band"]] = counts.get(f["risk_band"], 0) + 1
    score = min(100, sum(BAND_WEIGHTS[b] * n for b, n in counts.items()))
    return {"score": score, "band": _band(score), "counts": counts}


def quantum_readiness(findings: list[dict], files_scanned: int) -> dict:
    """QRS — Quantum Readiness Score (0-100, higher = more ready)."""
    total = len(findings)
    pqc = sum(1 for f in findings if f["category"] == "quantum_resistant")
    critical = sum(1 for f in findings if f["risk_band"] == "CRITICAL")
    broken = sum(1 for f in findings if f["category"] in
                 ("broken_classical", "implementation_risk"))

    pillars = {
        # We scanned the tree we could see: inventory is complete for this scope.
        "crypto_inventory": 100 if files_scanned > 0 else 0,
        # Share of findings already post-quantum or quantum-safe.
        "pqc_adoption": round(100 * pqc / total) if total else 0,
        # No agility layer is detectable in scanned code (deterministic rule).
        "crypto_agility": 0,
        # Legacy exposure pillar: penalties from critical/broken findings.
        "legacy_exposure": max(0, 100 - 12 * critical - 6 * broken),
        # Migration readiness proxy: inverse of mean risk.
        "migration_readiness": (round(max(0.0, 100 - sum(
            f["risk_score"] for f in findings) / max(1, total))) if total else 100),
    }
    weights = {"crypto_inventory": 0.25, "pqc_adoption": 0.25,
               "crypto_agility": 0.15, "legacy_exposure": 0.20,
               "migration_readiness": 0.15}
    qrs = round(sum(weights[k] * v for k, v in pillars.items()))
    verdict = ("STRONG" if qrs >= 80 else "MODERATE" if qrs >= 50 else
               "WEAK" if qrs >= 30 else "UNREADY")
    return {"qrs": qrs, "verdict": verdict, "pillars": pillars}


def assess_scan(scan: dict, exposure: str = "public",
                data_lifetime_years: float = 30.0) -> dict:
    """Full risk assessment over a scanner result (scan + risk + QRS)."""
    assessed = [assess_finding(f, exposure, data_lifetime_years)
                for f in scan["findings"]]
    assessed.sort(key=lambda f: -f["risk_score"])
    exposure_summary = quantum_exposure(assessed)
    readiness = quantum_readiness(assessed, scan["files_scanned"])
    return {
        "root": scan["root"],
        "files_scanned": scan["files_scanned"],
        "files_skipped": scan["files_skipped"],
        "context": {"exposure": exposure,
                    "data_lifetime_years": data_lifetime_years},
        "findings": assessed,
        "exposure": exposure_summary,
        "readiness": readiness,
    }
