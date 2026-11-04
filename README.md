# Q-SHIELD 🛡️

**AI-Driven Post-Quantum Security & Healthcare Privacy Platform**

Q-SHIELD scans applications and healthcare data flows for quantum-vulnerable
cryptography, computes quantum risk, designs a staged hybrid PQC migration,
generates secure crypto configurations, and continuously validates the result —
all from a web control center.

Design principle: **AI proposes → cryptographic engine validates → human
approves → deployment layer implements.** Q-SHIELD never implements
cryptographic mathematics itself — it orchestrates vetted libraries
(`pyca/cryptography`, OpenSSL-backed).

---

## Quickstart

```bash
pip install --upgrade cryptography fastapi uvicorn    # tested: cryptography 50.0.2

python -m backend.validation.test_crypto              # 27/27 security validations
python -m backend.api.app                             # web control center
# open http://127.0.0.1:8600
```

CLI demos also work without the web server:

```bash
python -m backend.benchmarks.bench                    # benchmark lab -> research/results/
python -m demo.hospital_a && python -m demo.hospital_b
python -m demo.tamper_demo                            # attack laboratory
python -m backend.scanner.scanner                     # scan the vulnerable demo app
```

## The web control center (http://127.0.0.1:8600)

| Page | What it does |
|---|---|
| **Overview** | Quantum Exposure gauge, Quantum Readiness Score (QRS), risk distribution, live audit log |
| **Scanner** | Cryptographic Discovery Engine: scans any source tree, scores every finding (CRITICAL→LOW), flags harvest-now-decrypt-later exposure |
| **Migration** | 5-phase migration plan (inventory → hybrid → testing → PQC-first → legacy removal) with prioritized P0 actions |
| **Laboratory** | PQC benchmarking: ML-KEM/ML-DSA vs RSA/Ed25519 timings + sizes, full hybrid exchange cost |
| **Exchange** | Hospital A→B secure medical record exchange over the hybrid channel; live algorithm switching (crypto agility); attack laboratory (tamper / MITM / forge / replay — all rejected); forward-secrecy session demo |
| **Assistant** | AI Security Assistant (grounded in live platform data, LLM-ready gateway) + NL→spec Analyzer |

## Cryptographic architecture

| Role | Algorithm | Standard |
|---|---|---|
| Key establishment | **ML-KEM-768/1024** + X25519 (hybrid) | FIPS 203 |
| Key derivation | HKDF-SHA-256 over both shared secrets | RFC 5869 |
| Authentication | **ML-DSA-65/87** transcript signatures | FIPS 204 |
| Bulk encryption | AES-256-GCM | — |
| Baselines (Shor-vulnerable) | RSA-2048, Ed25519 | for benchmarks |

Two secure flows:

1. **Package flow** (store-and-forward): long-term hybrid identities, signed
   packages (`qshield-package-v1`), replay ledger, downgrade protection via
   signed algorithm tables.
2. **Session flow** (forward secrecy): TLS-style ephemeral handshake — fresh
   ephemeral ML-KEM + X25519 keys per session, destroyed after use. *Proven*
   by validation: stolen static keys cannot decrypt past sessions.

## Security validation engine — 27/27

`backend/validation/test_crypto.py` — positive (correctness) + negative (attack)
tests: wrong keys, tampered ciphertexts/AAD/signatures, forged signatures,
MITM KEM substitution, replay, wrong recipient, **downgrade attempts**,
**FS session attacks**, and the **forward-secrecy proof**.

## Benchmark results (sample run)

| Primitive | Operation | Mean | Notes |
|---|---|---:|---|
| ML-KEM-768 | keygen | 0.096 ms | vs RSA-2048 keygen **45.3 ms** (~470×) |
| ML-DSA-65 | sign / verify | 0.528 / 0.105 ms | signature 3309 B vs RSA 256 B |
| **Hybrid exchange** | build / open package | **0.67 / 0.20 ms** | encrypt+sign / verify+decrypt |

Full data: `research/results/benchmark-*.json|csv`. The research tradeoff:
PQC is *faster* to establish than RSA but carries a ~7× signature-size overhead.

## Cryptographic Discovery Engine (scanner)

Deterministic rules (21 rules: Shor-vulnerable, Grover-weak, broken-classical,
legacy protocol, implementation pitfalls) with key-size extraction and usage
heuristics. Try it on the bundled **deliberately vulnerable demo app**
(`demo/vulnerable_app/`): 24 findings, exposure 100/100 CRITICAL, QRS 28 UNREADY.
Known limitation (documented, not hidden): no data-flow analysis — variable
indirection can be missed and false positives are possible.

## Repository layout

```
backend/
  crypto/       kem.py signatures.py symmetric.py classical.py
                agility.py (registry + policy) hybrid.py session.py (FS)
  scanner/      scanner.py            # 21-rule discovery engine
  risk/         engine.py             # risk scoring + QRS + HNDL flags
  migration/    planner.py            # 5-phase migration plans
  ai/           analyzer.py assistant.py  # NL→spec + grounded assistant
  validation/   test_crypto.py        # 27 security validations
  benchmarks/   bench.py              # PQC benchmarking laboratory
  api/          app.py                # FastAPI web control center
  storage.py                          # JSON store (Postgres-swappable)
frontend/       index.html styles.css app.js   # dark SOC-themed SPA
demo/           hospital_a.py hospital_b.py tamper_demo.py identities.py
                vulnerable_app/       # deliberately vulnerable scan target
research/       results/              # benchmark JSON/CSV
```

## Security model — honest limitations

| Protected against | Not yet covered |
|---|---|
| Eavesdropping (hybrid KEM + AES-GCM) | Forward secrecy in the *package* flow (the session flow has it) |
| Tampering (GCM + signed transcripts) | PKI — identities are pre-distributed files (trust on first use) |
| MITM key substitution (signature covers KEM ct) | Key-at-rest protection (demo keys unencrypted; would be HSM/KMS) |
| Replay (msg_id ledger, single-use session offers) | Network transport (files/in-process, not sockets) |
| Downgrade (algorithm table is signed) | Memory zeroization guarantees (Python-level secret drop) |
| Algorithm rollover (agility layer, config-only change) | Multi-tenant RBAC & healthcare workflow UI |

## Roadmap

- **M7** — WebSocket live exchange + RBAC (Patient/Doctor/Lab/Security Admin)
- **M8** — PKI-lite (certificates, ML-DSA chains), dependency/TLS scanner
- **M9** — LLM gateway integration (real model behind the existing assistant interface)
- **M10** — research paper: PQC-vs-classical healthcare benchmarks + AI detection dataset
