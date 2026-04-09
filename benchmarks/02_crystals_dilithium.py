# ==============================================================================
# Post-Quantum Cryptography Benchmark — CRYSTALS-Dilithium (Digital Signature)
# Research: IME — Instituto Militar de Engenharia
# Author:   Bernardo Pereira Pinto de Castro
# ==============================================================================
#
# CRYSTALS-Dilithium is the NIST-standardized digital signature algorithm,
# companion to Kyber. It provides authenticity and integrity guarantees.
# Security is based on the hardness of Module-LWE and Module-SIS problems.
#
# Signature protocol (Alice signs, Bob verifies):
#   1. KeyGen  — Alice generates secret key (s1, s2) and public key (A, t)
#                where t = A·s1 + s2.
#   2. Sign    — Alice produces a signature (z, c) using the Fiat-Shamir
#                with Aborts heuristic. Rejection sampling ensures z leaks
#                no information about the secret key s1.
#   3. Verify  — Bob re-derives the challenge c' = H(M, HighBits(A·z − c·t))
#                and accepts if c' == c.
#
# Install dependency:
#   pip install dilithium-py
# ==============================================================================

import time
from dilithium_py.dilithium import Dilithium2

NUM_ITERATIONS = 100

# Message to be signed (must be bytes)
MESSAGE = b"Your message signed by Dilithium"

# Accumulators for timing and size metrics
times = {"keygen": 0.0, "sign": 0.0, "verify": 0.0}
sizes = {"public_key": 0, "secret_key": 0, "signature": 0}

print(f"Performance benchmark for CRYSTALS-Dilithium2 — {NUM_ITERATIONS} iterations.")

# ── Main benchmark loop ────────────────────────────────────────────────────────
for _ in range(NUM_ITERATIONS):

    # ── Key Generation ──────────────────────────────────────────────────────
    # Alice generates her key pair:
    #   • Secret key: small vectors (s1, s2) sampled uniformly.
    #   • Public key: (A, t) where t = A·s1 + s2.
    start = time.perf_counter()
    public_key, secret_key = Dilithium2.keygen()
    times["keygen"] += time.perf_counter() - start

    # ── Signing (Alice) ─────────────────────────────────────────────────────
    # Alice signs MESSAGE with her secret key:
    #   • Samples a random nonce vector y.
    #   • Computes commitment  w = A·y.
    #   • Derives challenge    c = H(MESSAGE, HighBits(w)).
    #   • Computes response    z = y + c·s1.
    #   • Applies rejection sampling: if ||z|| is too large, restart.
    #     This prevents z from leaking any information about s1.
    # The final signature is the pair (z, c).
    start = time.perf_counter()
    signature = Dilithium2.sign(secret_key, MESSAGE)
    times["sign"] += time.perf_counter() - start

    # ── Verification (Bob) ──────────────────────────────────────────────────
    # Bob verifies the signature using Alice's public key (A, t):
    #   • Re-computes  w'  = HighBits(A·z − c·t).
    #   • Re-derives   c'  = H(MESSAGE, w').
    #   • Accepts if c' == c and ||z|| is within bounds.

    start = time.perf_counter()

    # Test 1 — valid signature must verify correctly.
    assert Dilithium2.verify(public_key, MESSAGE, signature), \
        "Verification failed for a valid signature!"

    # Test 2 — the same signature must NOT verify against a different message.
    # This proves that the signature is bound to the exact message content.
    assert not Dilithium2.verify(public_key, b"", signature), \
        "Verification should have failed for a tampered message!"

    # Test 3 — the signature must NOT verify against a different public key.
    # This proves that the signature is bound to Alice's identity.
    public_key_bob, _ = Dilithium2.keygen()
    assert not Dilithium2.verify(public_key_bob, MESSAGE, signature), \
        "Verification should have failed with a different public key!"

    times["verify"] += time.perf_counter() - start

# ── Measure artifact sizes (single run, outside the timed loop) ───────────────
public_key, secret_key = Dilithium2.keygen()
signature              = Dilithium2.sign(secret_key, MESSAGE)
sizes["public_key"]    = len(public_key)
sizes["secret_key"]    = len(secret_key)
sizes["signature"]     = len(signature)

# ── Results ───────────────────────────────────────────────────────────────────
print("Benchmark complete.")
print("-" * 50)
print(f"Public key size   : {sizes['public_key']} bytes")
print(f"Secret key size   : {sizes['secret_key']} bytes")
print(f"Signature size    : {sizes['signature']} bytes")
print(f"Avg KeyGen time   : {(times['keygen'] / NUM_ITERATIONS) * 1000:.4f} ms")
print(f"Avg Sign time     : {(times['sign']   / NUM_ITERATIONS) * 1000:.4f} ms")
print(f"Avg Verify time   : {(times['verify'] / NUM_ITERATIONS) * 1000:.4f} ms")
