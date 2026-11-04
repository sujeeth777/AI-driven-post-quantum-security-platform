"""Q-SHIELD AI Security Assistant (design doc §19).

Answers questions grounded in live platform data (latest scan, risk scores,
migration plan, benchmark results). Milestone implementation: deterministic
intent routing over a curated knowledge base — honest about what it is, and
structurally ready for an LLM gateway (swap `answer()`'s internals; the
grounding data and interface stay).
"""

from __future__ import annotations

import re

INTENTS = [
    ("why_vulnerable", r"why.*(vulnerable|risk|bad|weak)|shor|how.*(break|attack)"),
    ("replacement", r"replace|instead|recommend|what (should|algorithm)|alternative"),
    ("risk_status", r"risk|exposure|score|how bad|status|vulnerab"),
    ("readiness", r"readiness|ready|qrs"),
    ("harvest", r"harvest|decrypt later|hnd"),
    ("migration", r"migrat|plan|phase|roadmap|step"),
    ("benchmark", r"benchmark|performance|fast|slow|latency|overhead"),
    ("symmetric", r"grover|aes|symmetric|hash"),
    ("tls", r"\btls\b|https|certificate"),
    ("session", r"forward secrec|session|ephemeral"),
    ("capabilities", r"^(hi|hello|hey|help|what can you)|capabilit|feature"),
]

KNOWLEDGE = {
    "shor": ("Shor's algorithm, running on a cryptographically relevant quantum "
             "computer, solves integer factorization and discrete logarithms in "
             "polynomial time. That breaks RSA, Diffie-Hellman, and all elliptic-curve "
             "cryptography — the public-key primitives protecting today's key "
             "establishment and signatures. Symmetric primitives are far less affected: "
             "Grover's algorithm only halves the effective key length, so AES-256 and "
             "SHA-256 remain acceptable."),
    "mlkem": ("ML-KEM (FIPS 203, formerly Kyber) is NIST's standardized post-quantum "
              "key encapsulation mechanism. ML-KEM-768 targets NIST security category 3. "
              "Q-SHIELD combines it with X25519 in a hybrid construction so security "
              "holds as long as either primitive survives."),
    "mldsa": ("ML-DSA (FIPS 204, formerly Dilithium) is NIST's standardized post-quantum "
              "signature scheme. ML-DSA-65 targets category 3; signatures are larger than "
              "RSA (~3.3 KB vs 256 B) but signing throughput is competitive."),
    "hnd": ("Harvest-now-decrypt-later: an adversary records encrypted traffic today and "
            "decrypts it once a quantum computer exists. Data whose confidentiality must "
            "outlive the arrival of quantum computers (patient records: decades) is at "
            "risk NOW even though the decryption capability does not exist yet."),
    "fs": ("Forward secrecy means past sessions stay confidential even if long-term keys "
           "are later stolen. Q-SHIELD's package flow (long-term keys) does not provide "
           "it; the session flow does — each session uses fresh ephemeral ML-KEM and "
           "X25519 keys that are destroyed after use, validated by the security test "
           "'stolen static keys cannot decrypt past session'."),
}


def _fmt_score(v: float) -> str:
    return f"{v:g}"


def answer(question: str, context: dict) -> dict:
    """Answer a question using intent routing + live platform data.

    context keys (all optional): assessment (dict), plan (dict),
    benchmark (dict with 'rows').
    """
    q = question.lower()
    assessment = context.get("assessment")
    plan = context.get("plan")
    benchmark = context.get("benchmark")
    data: dict = {}

    intent = next((name for name, pat in INTENTS if re.search(pat, q)), "fallback")

    if intent == "why_vulnerable":
        body = KNOWLEDGE["shor"]
        if assessment:
            top = assessment["findings"][:3]
            if top:
                listing = "; ".join(
                    f"{f['algorithm']} at {f['file']}:{f['line']} "
                    f"(risk {_fmt_score(f['risk_score'])}/100)" for f in top)
                body += (f" In your scanned system, the highest-risk instances are: "
                         f"{listing}.")
        return {"intent": intent, "answer": body, "data": data}

    if intent == "replacement":
        body = ("For key establishment, Q-SHIELD recommends ML-KEM-768; for signatures, "
                "ML-DSA-65 (FIPS 203/204). Keep AES-256-GCM for bulk encryption. Because "
                "most organizations cannot remove classical cryptography immediately, "
                "deploy hybrid constructions (X25519 + ML-KEM-768) first, then move to "
                "PQC-first, then retire legacy algorithms.")
        if plan:
            p0 = plan["summary"]["p0_actions"]
            body += f" Your current migration plan has {p0} P0 (immediate) actions — see the Migration page."
        data.update({"kem": "ML-KEM-768", "sig": "ML-DSA-65", "aead": "AES-256-GCM"})
        return {"intent": intent, "answer": body, "data": data}

    if intent == "risk_status":
        if not assessment:
            return {"intent": intent,
                    "answer": "No scan has been run yet. Open the Scanner page and scan "
                              "the bundled vulnerable demo app (or your own project) to "
                              "compute quantum exposure.", "data": {}}
        exp, rdy = assessment["exposure"], assessment["readiness"]
        body = (f"Quantum Exposure: {_fmt_score(exp['score'])}/100 ({exp['band']}) with "
                f"{exp['counts'].get('CRITICAL', 0)} critical and "
                f"{exp['counts'].get('HIGH', 0)} high-risk findings across "
                f"{assessment['files_scanned']} files. Quantum Readiness Score: "
                f"{rdy['qrs']}/100 ({rdy['verdict']}).")
        if assessment["findings"]:
            f0 = assessment["findings"][0]
            body += (f" Worst finding: {f0['algorithm']} at {f0['file']}:{f0['line']} "
                     f"(risk {_fmt_score(f0['risk_score'])}).")
        data.update({"exposure": exp, "readiness": rdy})
        return {"intent": intent, "answer": body, "data": data}

    if intent == "readiness":
        if not assessment:
            return {"intent": intent, "answer": "Run a scan first — readiness is computed "
                    "from the cryptographic inventory.", "data": {}}
        rdy = assessment["readiness"]
        pillars = ", ".join(f"{k.replace('_', ' ')} {v}%" for k, v in rdy["pillars"].items())
        body = (f"Quantum Readiness Score: {rdy['qrs']}/100 — {rdy['verdict']}. "
                f"Pillars: {pillars}. The binding constraints here are PQC adoption and "
                f"crypto agility: adopt hybrid PQC and route crypto through an agility "
                f"layer to raise the score.")
        data.update({"readiness": rdy})
        return {"intent": intent, "answer": body, "data": data}

    if intent == "harvest":
        body = KNOWLEDGE["hnd"]
        if assessment:
            flagged = [f for f in assessment["findings"] if f.get("hnd_l")]
            body += (f" {len(flagged)} of your findings are flagged "
                     f"harvest-now-decrypt-later: long-lived data protected by "
                     f"Shor-vulnerable public-key cryptography.")
            data["hnd_count"] = len(flagged)
        return {"intent": intent, "answer": body, "data": data}

    if intent == "migration":
        if not plan:
            return {"intent": intent, "answer": "Run a scan, then generate the migration "
                    "plan from the Migration page.", "data": {}}
        s = plan["summary"]
        phase_names = " → ".join(p["name"] for p in plan["phases"])
        body = (f"Your plan: {s['to_replace']} replacements, {s['p0_actions']} immediate "
                f"(P0) actions, effort mix S:{s['estimated_effort']['S']} "
                f"M:{s['estimated_effort']['M']} L:{s['estimated_effort']['L']}. "
                f"Stages: {phase_names}.")
        data.update({"plan_summary": s})
        return {"intent": intent, "answer": body, "data": data}

    if intent == "benchmark":
        if benchmark and benchmark.get("rows"):
            rows = benchmark["rows"]
            def find(primitive, op):
                for r in rows:
                    if r["primitive"] == primitive and r["op"] == op:
                        return r["mean_ms"]
                return None
            ml_keygen, rsa_keygen = find("ML-KEM-768", "keygen"), find("RSA-2048", "keygen")
            if ml_keygen and rsa_keygen:
                body = (f"Measured on this machine: ML-KEM-768 keygen "
                        f"{ml_keygen:.3f} ms vs RSA-2048 keygen {rsa_keygen:.1f} ms "
                        f"(~{rsa_keygen / max(ml_keygen, 1e-9):.0f}x faster). The quantum "
                        f"tradeoff is size: ML-DSA-65 signatures are ~3.3 KB vs RSA's 256 B.")
            else:
                body = "Benchmark data available on the Laboratory page."
        else:
            body = ("No benchmark has been run yet in this session. Open the Laboratory "
                    "page and run the suite: it measures keygen, encapsulation, signing, "
                    "and the full hybrid exchange.")
        return {"intent": intent, "answer": body, "data": data}

    if intent == "symmetric":
        body = ("Grover's algorithm gives a quadratic speedup for brute force: AES-128 "
                "effectively drops to ~64-bit security, while AES-256 retains ~128-bit — "
                "still infeasible to break. Guidance: standardize on AES-256-GCM and "
                "SHA-256/SHA-3. MD5 and SHA-1 are already broken classically and must go "
                "regardless of quantum risk.")
        return {"intent": intent, "answer": body, "data": data}

    if intent == "tls":
        body = ("TLS 1.3 should be enforced everywhere; TLS 1.0/1.1 and RSA key exchange "
                "are deprecated and prime harvest-now-decrypt-later targets. The "
                "post-quantum path for TLS is hybrid key exchange — the X25519MLKEM768 "
                "group already deployed by major browsers and CDNs. Certificates will "
                "migrate to ML-DSA; plan re-issuance around expiry dates.")
        return {"intent": intent, "answer": body, "data": data}

    if intent == "session":
        body = KNOWLEDGE["fs"]
        return {"intent": intent, "answer": body, "data": data}

    if intent == "capabilities":
        body = ("I'm Q-SHIELD's security assistant, grounded in this platform's live data. "
                "Ask: 'why is RSA vulnerable?', 'what should replace our RSA?', 'what's "
                "our current risk?', 'explain harvest now decrypt later', 'how do I "
                "migrate?', 'how fast is ML-KEM?'. I reason deterministically over scan "
                "results and benchmarks — an LLM gateway can be swapped in behind the "
                "same interface.")
        return {"intent": intent, "answer": body, "data": data}

    body = ("I answer questions about quantum risk, PQC algorithms, your scan results, "
            "and the migration plan. Try 'why is our hospital's RSA vulnerable?' or "
            "'what should replace it?'.")
    if assessment:
        body += (f" Current snapshot: exposure {_fmt_score(assessment['exposure']['score'])}"
                 f"/100 ({assessment['exposure']['band']}), readiness "
                 f"{assessment['readiness']['qrs']}/100.")
    return {"intent": "fallback", "answer": body, "data": data}
