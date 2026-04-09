# Post-Quantum Cryptography — Benchmark & Analysis

> **Research project** developed at the **Instituto Militar de Engenharia (IME)**,
> Brazilian Military Institute of Engineering — Quantum Technologies Applications course.
>
> **Author:** Bernardo Pereira Pinto de Castro  
> **Advisor:** Colonel Anderson Fernandes Pereira dos Santos

---

## Overview

This repository contains the implementation and performance benchmarks for **four
NIST-standardized Post-Quantum Cryptography (PQC) algorithms**, evaluated in the
context of secure message exchange. The study covers algorithms from three distinct
PQC families, each based on a different mathematical hardness assumption.

The core motivation is the imminent threat posed by large-scale quantum computers
to classical public-key cryptosystems (RSA, Diffie-Hellman). Shor's algorithm can
solve integer factorization and discrete logarithm in polynomial time, rendering
these schemes obsolete. The algorithms analyzed here are designed to resist both
classical and quantum adversaries.

---

## Algorithms Analyzed

| # | Algorithm | Type | Family | NIST Standard |
|---|-----------|------|--------|---------------|
| 1 | **CRYSTALS-Kyber** | KEM | Lattice-based (Module-LWE) | FIPS 203 |
| 2 | **CRYSTALS-Dilithium** | Digital Signature | Lattice-based (Module-LWE/SIS) | FIPS 204 |
| 3 | **Classic McEliece** | KEM | Code-based (Goppa codes) | (Standardized) |
| 4 | **SPHINCS+** | Digital Signature | Hash-based | FIPS 205 |

---

## Repository Structure

```
pqc-benchmark/
├── 01_crystals_kyber.py       # KEM benchmark — CRYSTALS-Kyber512
├── 02_crystals_dilithium.py   # Signature benchmark — CRYSTALS-Dilithium2
├── 03_classic_mceliece.py     # KEM benchmark — McEliece-6960119
├── 04_sphincs_plus.py         # Signature benchmark — SPHINCS+-SHAKE-256s
├── requirements.txt           # Python dependencies
└── README.md
```

---

## Quick Start

### 1. Install dependencies

```bash
pip install kyber-py dilithium-py pypqc
```

Or using the requirements file:

```bash
pip install -r requirements.txt
```

### 2. Run a benchmark

```bash
python 01_crystals_kyber.py
python 02_crystals_dilithium.py
python 03_classic_mceliece.py
python 04_sphincs_plus.py
```

Each script runs 100 iterations and prints key sizes and average operation times.

---

## Benchmark Results

Tests were performed in a Google Colab virtualized environment (CPU only).
Each cryptographic operation was executed **100 times**; reported times are averages.

### Performance Metrics

| Metric | Kyber512 | Dilithium2 | McEliece-6960119 | SPHINCS+-256s |
|--------|----------|------------|-----------------|---------------|
| Public Key (bytes) | 800 | 1,312 | **1,047,319** | 64 |
| Secret Key (bytes) | 1,632 | 2,528 | 13,948 | 128 |
| Payload (bytes) | 768 | 2,420 | 194 | **29,792** |
| Avg KeyGen (ms) | 2.68 | 8.92 | 426.73 | 248.78 |
| Avg Encap/Sign (ms) | 3.76 | 49.21 | **1.51** | **2,985.68** |
| Avg Decap/Verify (ms) | 5.46 | 42.30 | 119.88 | 4.09 |

### Key Takeaways

- **CRYSTALS-Kyber** — Best overall balance. Compact keys (~800 bytes public) and
  sub-10 ms operations across the board. The natural default for KEMs in general-purpose
  applications such as TLS/HTTPS.

- **CRYSTALS-Dilithium** — Fast and compact signatures (2,420 bytes). The signing
  operation is slower (~49 ms) due to rejection sampling, but still highly practical.
  Ideal companion to Kyber for authenticated key exchange.

- **Classic McEliece** — Historically battle-tested (since 1978) and formally secure
  (tight IND-CCA2 proof in the QROM). The massive public key (~1 MB) is prohibitive
  for most network protocols but acceptable for long-term archival or offline scenarios.

- **SPHINCS+** — The most conservative choice: security reduces entirely to hash
  function properties. Large signatures (~29 KB) and very slow signing (~3 s) make
  it unsuitable for high-throughput servers, but ideal for infrequent, high-assurance
  signings (firmware, root CA certificates, digital cold storage).

---

## Security Metrics Summary

| Algorithm | Hard Problem | Security Level | QROM Proof |
|-----------|-------------|----------------|------------|
| Kyber512 | Module-LWE | NIST Level 1 | Non-tight |
| Dilithium2 | Module-LWE + Module-SIS | NIST Level 2 | Non-tight |
| McEliece-6960119 | Code Decoding (NP-hard) | NIST Level 5 | **Tight** |
| SPHINCS+-256s | Hash function properties | NIST Level 5 | ROM/QROM |

---

## TLS Integration Viability

| Algorithm | Viability | Reason |
|-----------|-----------|--------|
| CRYSTALS-Kyber | ✅ Excellent | ~1.6 KB total handshake overhead, <6 ms decap |
| CRYSTALS-Dilithium | ✅ Excellent | 2,420-byte signature, ~49 ms signing |
| Classic McEliece | ❌ Not viable | ~1 MB public key per connection |
| SPHINCS+ | ❌ Not viable | ~3 s signing time exhausts server resources |

---

## References

1. Avanzi et al. *CRYSTALS-KYBER Algorithm Specifications And Supporting Documentation v3.0*. NIST PQC Submission, 2020.
2. Bai et al. *CRYSTALS-Dilithium Algorithm Specifications and Supporting Documentation*. NIST PQC Submission, 2020.
3. Albrecht et al. *Classic McEliece: conservative code-based cryptography*. NIST PQC Submission, 2020.
4. Aumasson et al. *SPHINCS+ Submission to the NIST post-quantum project, v3*. NIST PQC Submission, 2020.
5. Faleiros, A.C. *Criptografia*. SBMAC, São Carlos, 2011. (Notas em Matemática Aplicada, v.52).

---

## License

This project is intended for academic and research purposes.
