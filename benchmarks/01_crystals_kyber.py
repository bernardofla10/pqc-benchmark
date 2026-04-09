# ==============================================================================
# Post-Quantum Cryptography Benchmark — CRYSTALS-Kyber (KEM)
# Research: IME — Instituto Militar de Engenharia
# Author:   Bernardo Pereira Pinto de Castro
# ==============================================================================
#
# CRYSTALS-Kyber is a Key Encapsulation Mechanism (KEM) standardized by NIST.
# Its security is based on the hardness of the Module Learning With Errors
# (Module-LWE) problem: given t = A·s + e, it is computationally infeasible
# to recover the secret vector s from the public pair (A, t) because of the
# small error vector e.
#
# Key exchange protocol (Alice ↔ Bob):
#   1. KeyGen  — Alice generates her public key (A, t) and secret key s.
#   2. Encaps  — Bob encapsulates a shared secret using Alice's public key,
#                producing ciphertext c = (u, v) and shared secret ss = H(m).
#   3. Decaps  — Alice decapsulates c with s to recover ss = H(m).
#
# Install dependency:
#   pip install kyber-py
# ==============================================================================

import time
from kyber_py.kyber import Kyber512

NUM_ITERATIONS = 100

# Accumulators for timing and size metrics
times  = {"keygen": 0.0, "encaps": 0.0, "decaps": 0.0}
sizes  = {"public_key": 0, "secret_key": 0, "ciphertext": 0}

print(f"Performance benchmark for CRYSTALS-Kyber512 — {NUM_ITERATIONS} iterations.")

# ── Main benchmark loop ────────────────────────────────────────────────────────
for _ in range(NUM_ITERATIONS):

    # ── Key Generation ──────────────────────────────────────────────────────
    # Alice generates:
    #   • Secret key  s  — small-coefficient vector sampled from a centered
    #                       binomial distribution (low-norm, hard to guess).
    #   • Public key (A, t) where t = A·s + e  (Module-LWE instance).
    start = time.perf_counter()
    public_key, secret_key = Kyber512.keygen()
    times["keygen"] += time.perf_counter() - start

    # ── Encapsulation (Bob) ─────────────────────────────────────────────────
    # Bob encapsulates a fresh shared secret using Alice's public key:
    #   • Samples random seed m and temporary error vectors r, e1, e2.
    #   • Computes ciphertext  c = (u, v):
    #       u = Aᵀ·r + e1
    #       v = tᵀ·r + e2 + m
    #   • Derives shared secret via hash:  ss = H(m).
    # Bob sends only the ciphertext c to Alice.
    start = time.perf_counter()
    shared_secret_sender, ciphertext = Kyber512.encaps(public_key)
    times["encaps"] += time.perf_counter() - start

    # ── Decapsulation (Alice) ───────────────────────────────────────────────
    # Alice recovers the shared secret from c = (u, v) using her secret key s:
    #   • Computes  v - uᵀ·s  ≈  m + small_errors.
    #   • Rounds off the small residual errors to recover the seed m exactly.
    #   • Applies the same hash:  ss = H(m).
    start = time.perf_counter()
    shared_secret_receiver = Kyber512.decaps(secret_key, ciphertext)
    times["decaps"] += time.perf_counter() - start

    # Correctness check — both parties must hold identical shared secrets.
    assert shared_secret_sender == shared_secret_receiver, \
        "Key exchange failed: shared secrets do not match!"

# ── Measure artifact sizes (single run, outside the timed loop) ───────────────
public_key, secret_key             = Kyber512.keygen()
shared_secret_sender, ciphertext   = Kyber512.encaps(public_key)
sizes["public_key"]  = len(public_key)
sizes["secret_key"]  = len(secret_key)
sizes["ciphertext"]  = len(ciphertext)

# ── Results ───────────────────────────────────────────────────────────────────
print("Benchmark complete.")
print("-" * 50)
print(f"Public key size  : {sizes['public_key']}  bytes")
print(f"Secret key size  : {sizes['secret_key']} bytes")
print(f"Ciphertext size  : {sizes['ciphertext']}  bytes")
print(f"Avg KeyGen time  : {(times['keygen'] / NUM_ITERATIONS) * 1000:.4f} ms")
print(f"Avg Encaps time  : {(times['encaps'] / NUM_ITERATIONS) * 1000:.4f} ms")
print(f"Avg Decaps time  : {(times['decaps'] / NUM_ITERATIONS) * 1000:.4f} ms")
