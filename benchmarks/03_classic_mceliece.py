# ==============================================================================
# Post-Quantum Cryptography Benchmark — Classic McEliece (KEM)
# Research: IME — Instituto Militar de Engenharia
# Author:   Bernardo Pereira Pinto de Castro
# ==============================================================================
#
# Classic McEliece is a NIST-standardized KEM and one of the oldest, most
# battle-tested PQC schemes (proposed in 1978). Its security is based on the
# NP-hard problem of decoding a random linear code.
#
# The core idea is to disguise an easily decodable Goppa code (the trapdoor)
# as a random-looking linear code (the public key).
#
# Key exchange protocol (Alice ↔ Bob):
#   1. KeyPair — Alice picks a binary Goppa code G and secret scrambling
#                matrices S and P. Public key: G' = S·G·P (looks random).
#                Secret key: the trio (S, G, P).
#   2. Encap   — Bob generates a random seed m and an error vector e with
#                a fixed Hamming weight t. Ciphertext: c = (m·G') + e.
#   3. Decap   — Alice applies P⁻¹, decodes the Goppa code to remove e,
#                then applies S⁻¹ to recover m exactly.
#
# Variant used: mceliece6960119  (NIST security level 5)
#
# Install dependency:
#   pip install pypqc
# ==============================================================================

import time
from pqc.kem import mceliece6960119 as kemalg

NUM_ITERATIONS = 100

# Accumulators for timing and size metrics
times = {"keypair": 0.0, "encap": 0.0, "decap": 0.0}
sizes = {"public_key": 0, "secret_key": 0, "ciphertext": 0}

print(f"Performance benchmark for Classic McEliece-6960119 — {NUM_ITERATIONS} iterations.")

# ── Main benchmark loop ────────────────────────────────────────────────────────
for _ in range(NUM_ITERATIONS):

    # ── Key Pair Generation ─────────────────────────────────────────────────
    # Alice constructs the disguised public key:
    #   • Chooses a binary Goppa code G (efficiently decodable trapdoor).
    #   • Generates secret invertible matrix S and permutation matrix P.
    #   • Computes public key  G' = S·G·P  (indistinguishable from a random
    #     linear code to an adversary who does not know S, G, P).
    start = time.perf_counter()
    public_key, secret_key = kemalg.keypair()
    times["keypair"] += time.perf_counter() - start

    # ── Encapsulation (Bob) ─────────────────────────────────────────────────
    # Bob encapsulates a shared secret using Alice's public key:
    #   • Generates random seed m and error vector e with Hamming weight t.
    #   • Encodes m with the public code:  y = m·G'.
    #   • Adds the deliberate errors:      c = y + e  (the ciphertext).
    # Without knowing the Goppa trapdoor, decoding c is NP-hard.
    start = time.perf_counter()
    msg_sender, ciphertext = kemalg.encap(public_key)
    times["encap"] += time.perf_counter() - start

    # ── Decapsulation (Alice) ───────────────────────────────────────────────
    # Alice recovers the shared secret using her secret key (S, G, P):
    #   1. Applies P⁻¹ to undo the permutation.
    #   2. Uses the efficient Goppa decoder to remove the t errors.
    #   3. Applies S⁻¹ to unscramble and recover m exactly.
    start = time.perf_counter()
    msg_receiver = kemalg.decap(ciphertext, secret_key)
    times["decap"] += time.perf_counter() - start

    # Correctness check — both parties must hold identical shared secrets.
    assert msg_sender == msg_receiver, \
        "Key exchange failed: shared secrets do not match!"

# ── Measure artifact sizes (single run, outside the timed loop) ───────────────
public_key, secret_key     = kemalg.keypair()
msg_sender, ciphertext     = kemalg.encap(public_key)
sizes["public_key"]        = len(public_key)
sizes["secret_key"]        = len(secret_key)
sizes["ciphertext"]        = len(ciphertext)

# ── Results ───────────────────────────────────────────────────────────────────
print("Benchmark complete.")
print("-" * 50)
print(f"Public key size   : {sizes['public_key']:,} bytes  (~{sizes['public_key']/1024:.1f} KB)")
print(f"Secret key size   : {sizes['secret_key']:,} bytes")
print(f"Ciphertext size   : {sizes['ciphertext']}   bytes")
print(f"Avg KeyPair time  : {(times['keypair'] / NUM_ITERATIONS) * 1000:.4f} ms")
print(f"Avg Encap time    : {(times['encap']   / NUM_ITERATIONS) * 1000:.4f} ms")
print(f"Avg Decap time    : {(times['decap']   / NUM_ITERATIONS) * 1000:.4f} ms")
