"""Q-SHIELD Quantum Migration Planner (design doc Module 13 / §17).

Turns an assessed scan into a staged migration plan:
    inventory -> hybrid deployment -> PQC testing -> PQC production -> legacy removal

The replacement table encodes current NIST/CNSA 2.0 guidance:
    RSA/ECDH/DH     -> hybrid ML-KEM (key establishment)
    ECDSA/RSA sigs  -> ML-DSA
    AES-128         -> AES-256
    MD5/SHA-1       -> SHA-256/SHA-3
    legacy TLS      -> TLS 1.3 with hybrid groups
"""

from __future__ import annotations

REPLACEMENTS: dict[str, dict] = {
    "RSA": {"target": "Hybrid X25519 + ML-KEM-768 (establishment); ML-DSA-65 (signatures)",
            "effort": "M", "stage": 2, "priority": "P0",
            "note": "Run classical+PQC hybrid first; keep RSA verification only for legacy trust anchors."},
    "RSA (JWT RS*)": {"target": "ML-DSA-65-signed tokens (or hybrid RS256/ML-DSA)",
                      "effort": "M", "stage": 2, "priority": "P0",
                      "note": "Issue dual-signature tokens during transition; verify both."},
    "RSA (PKCS#1 v1.5)": {"target": "ML-DSA-65",
                          "effort": "M", "stage": 2, "priority": "P0",
                          "note": "Also removes the Bleichenbacher padding-oracle class."},
    "ECDSA": {"target": "ML-DSA-65", "effort": "M", "stage": 2, "priority": "P0",
              "note": "Dual-sign with ECDSA+ML-DSA during transition."},
    "ECC (ECDSA/ECDH)": {"target": "ML-DSA-65 (if signing) / hybrid X25519+ML-KEM-768 (if key agreement)",
                         "effort": "M", "stage": 2, "priority": "P0",
                         "note": "Determine each usage site's role first."},
    "ECDH/X25519": {"target": "Hybrid X25519 + ML-KEM-768", "effort": "M", "stage": 2,
                    "priority": "P0", "note": "Hybrid keeps classical security while adding PQC."},
    "Diffie-Hellman": {"target": "Hybrid X25519 + ML-KEM-768", "effort": "M", "stage": 2,
                       "priority": "P0", "note": "Retire finite-field DH."},
    "DSA": {"target": "ML-DSA-65", "effort": "M", "stage": 2, "priority": "P0",
            "note": "DSA is deprecated regardless of quantum risk."},
    "MD5": {"target": "SHA-256 / SHA-3; passwords -> Argon2id", "effort": "S", "stage": 2,
            "priority": "P1", "note": "Classical break, urgent independently of quantum."},
    "SHA-1": {"target": "SHA-256 / SHA-3", "effort": "S", "stage": 2, "priority": "P1",
              "note": "Collision-broken; replace everywhere."},
    "RC4": {"target": "AES-256-GCM", "effort": "S", "stage": 2, "priority": "P1", "note": ""},
    "DES/3DES": {"target": "AES-256-GCM", "effort": "S", "stage": 2, "priority": "P1", "note": ""},
    "AES-128": {"target": "AES-256-GCM", "effort": "S", "stage": 2, "priority": "P2",
                "note": "Grover halves key search; 256-bit keys restore the margin."},
    "AES-192": {"target": "AES-256-GCM", "effort": "S", "stage": 2, "priority": "P2", "note": ""},
    "ECB mode": {"target": "AES-256-GCM (AEAD)", "effort": "S", "stage": 2, "priority": "P1",
                 "note": "Independent of quantum risk — patterns leak today."},
    "TLS verification disabled": {"target": "Enable certificate verification + proper trust store",
                                  "effort": "S", "stage": 2, "priority": "P0",
                                  "note": "Exploitable by a classical MITM today."},
    "Legacy TLS": {"target": "TLS 1.3 with hybrid group X25519MLKEM768", "effort": "M",
                   "stage": 2, "priority": "P0",
                   "note": "RSA/ephemeral suites in old TLS are harvest-now-decrypt-later targets."},
    "TLS cipher configuration": {"target": "TLS 1.3 defaults + hybrid KEM groups", "effort": "S",
                                 "stage": 2, "priority": "P1", "note": ""},
    "X.509 certificate/key": {"target": "Re-issue certificates under ML-DSA (or dual-alg chains)",
                              "effort": "L", "stage": 3, "priority": "P1",
                              "note": "Track expiry dates; stagger re-issuance."},
    "TLS 1.2/1.3": {"target": "TLS 1.3 + hybrid key exchange (X25519MLKEM768)", "effort": "S",
                    "stage": 3, "priority": "P2", "note": "Layer PQC into an already-modern stack."},
    "AES-256": {"target": "KEEP — quantum-resistant", "effort": "S", "stage": 0, "priority": "-",
                "note": "Grover only halves the margin; 256-bit keys are sufficient."},
    "SHA-256": {"target": "KEEP — quantum-resistant", "effort": "S", "stage": 0, "priority": "-",
                "note": "SHA-256 remains acceptable post-quantum."},
}

PHASES = [
    {"stage": 1, "name": "Inventory & risk baseline",
     "actions": ["Maintain the cryptographic inventory (re-run Q-SHIELD scans in CI)",
                 "Assign owners to every CRITICAL finding",
                 "Freeze new deployments of Shor-vulnerable primitives"]},
    {"stage": 2, "name": "Hybrid deployment (classical + PQC)",
     "actions": ["Deploy hybrid X25519 + ML-KEM-768 for key establishment",
                 "Dual-sign (classical + ML-DSA) where verification allows",
                 "Replace broken primitives (MD5/SHA-1/ECB, TLS verification) immediately"]},
    {"stage": 3, "name": "PQC testing & interoperability",
     "actions": ["Run the Q-SHIELD validation suite against migrated components",
                 "Benchmark ML-KEM/ML-DSA under production-like load",
                 "Test interop with partner hospitals/gateways"]},
    {"stage": 4, "name": "PQC-first production",
     "actions": ["Make ML-KEM/ML-DSA the primary algorithms",
                 "Re-issue certificates under ML-DSA",
                 "Adopt crypto-agility layer so future changes are config-only"]},
    {"stage": 5, "name": "Legacy removal",
     "actions": ["Disable classical-only cipher suites and RSA key exchange",
                 "Revoke/retire RSA and ECC certificates",
                 "Re-scan: target Quantum Risk < 40 (MEDIUM) or lower"]},
]


def _dedupe(findings: list[dict]) -> list[dict]:
    """One migration item per (algorithm, usage) pair, worst-first."""
    seen: dict[tuple, dict] = {}
    for f in findings:
        key = (f["algorithm"], f["usage"])
        if key not in seen or f["risk_score"] > seen[key]["risk_score"]:
            seen[key] = f
    return sorted(seen.values(), key=lambda f: -f["risk_score"])


def build_plan(assessment: dict) -> dict:
    """Produce the migration plan for an assessed scan."""
    items = []
    for f in _dedupe(assessment["findings"]):
        rep = REPLACEMENTS.get(f["algorithm"], {
            "target": "Review manually — no fixed replacement rule",
            "effort": "M", "stage": 2, "priority": "P1", "note": ""})
        items.append({
            "algorithm": f["algorithm"],
            "usage": f["usage"],
            "locations": f"{f['file']}:{f['line']}",
            "risk_band": f["risk_band"],
            "risk_score": f["risk_score"],
            "target": rep["target"],
            "effort": rep["effort"],      # S/M/L
            "stage": rep["stage"],
            "priority": rep["priority"],
            "note": rep["note"],
        })

    keep = [i for i in items if i["stage"] == 0]
    change = [i for i in items if i["stage"] > 0]
    by_stage: dict[int, list] = {}
    for item in change:
        by_stage.setdefault(item["stage"], []).append(item)

    phases = []
    for phase in PHASES:
        stage_items = by_stage.get(phase["stage"], [])
        phases.append({**phase,
                       "items": [{"algorithm": i["algorithm"], "target": i["target"],
                                  "locations": i["locations"], "effort": i["effort"],
                                  "priority": i["priority"]}
                                 for i in stage_items]})

    priority_order = {"P0": 0, "P1": 1, "P2": 2, "-": 3}
    change.sort(key=lambda i: (priority_order[i["priority"]], -i["risk_score"]))
    return {
        "system": assessment["root"],
        "summary": {
            "total_items": len(change) + len(keep),
            "to_replace": len(change),
            "to_keep": len(keep),
            "p0_actions": sum(1 for i in change if i["priority"] == "P0"),
            "estimated_effort": {"S": sum(1 for i in change if i["effort"] == "S"),
                                 "M": sum(1 for i in change if i["effort"] == "M"),
                                 "L": sum(1 for i in change if i["effort"] == "L")},
        },
        "immediate_actions": [i for i in change if i["priority"] == "P0"],
        "phases": phases,
        "keep": keep,
    }
