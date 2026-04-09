# ==============================================================================
# Post-Quantum Cryptography Benchmark — SPHINCS+ (Digital Signature)
# Research: IME — Instituto Militar de Engenharia
# Author:   Bernardo Pereira Pinto de Castro
# ==============================================================================
#
# SPHINCS+ is a stateless hash-based digital signature scheme and the most
# conservative of the NIST standards: its security relies solely on the
# properties of a cryptographic hash function (second pre-image resistance,
# pseudorandomness), requiring no new mathematical assumptions.
#
# Architecture — a three-layer hierarchy:
#   • Base layer  : WOTS+ (Winternitz One-Time Signatures)
#   • Middle layer: Individual Merkle trees grouping WOTS+ public keys.
#   • Top layer   : Hyper-tree — a tree of Merkle trees where the root of
#                   a lower-level tree becomes a leaf in the level above.
#   The final public key is just the root of the topmost Merkle tree (small).
#
# Signature protocol:
#   1. KeyPair — Builds the hyper-tree structure.
#                Secret key: all WOTS+ key seeds + Merkle trees (large).
#                Public key: only the hyper-tree root (tiny, 64 bytes).
#   2. Sign    — Deterministically selects a WOTS+ key using H(message, sk_prf)
#                to avoid state management. Produces a large signature containing:
#                the WOTS+ signature, the used WOTS+ public key, and all Merkle
#                authentication paths up to the root.
#   3. Verify  — Re-verifies every layer bottom-up, checking that the computed
#                root matches the known public key.
#
# Variant used: sphincs_shake_256s_simple  (NIST security level 5, small sigs)
#
# Install dependency:
#   pip install pypqc
# ==============================================================================

import time
from pqc.sign import sphincs_shake_256s_simple as sigalg

NUM_ITERATIONS = 100

# Message to be signed (must be bytes)
MESSAGE = b"Your message signed by SPHINCS+"

# Accumulators for timing and size metrics
times = {"keypair": 0.0, "sign": 0.0, "verify": 0.0}
sizes = {"public_key": 0, "secret_key": 0, "signature": 0}

print(f"Performance benchmark for SPHINCS+-SHAKE-256s — {NUM_ITERATIONS} iterations.")

# ── Main benchmark loop ────────────────────────────────────────────────────────
for _ in range(NUM_ITERATIONS):

    # ── Key Pair Generation ─────────────────────────────────────────────────
    # Builds the full hyper-tree structure:
    #   • Secret key encodes all WOTS+ key seeds and Merkle sub-trees (large).
    #   • Public key is only the root of the top Merkle tree (64 bytes).
    start = time.perf_counter()
    public_key, secret_key = sigalg.keypair()
    times["keypair"] += time.perf_counter() - start

    # ── Signing ─────────────────────────────────────────────────────────────
    # Stateless signing process:
    #   1. Deterministically selects a WOTS+ leaf index using
    #      H(MESSAGE, sk_prf) — different messages always pick different
    #      one-time keys, eliminating any counter/state requirement.
    #   2. Signs the message hash with that WOTS+ key.
    #   3. Assembles the full signature bundle (large) containing:
    #      • The WOTS+ signature.
    #      • The WOTS+ public key used.
    #      • All Merkle authentication paths from leaf to hyper-tree root.
    start = time.perf_counter()
    signature = sigalg.sign(MESSAGE, secret_key)
    times["sign"] += time.perf_counter() - start

    # ── Verification ────────────────────────────────────────────────────────
    # Re-traverses the hyper-tree bottom-up:
    #   1. Verifies the WOTS+ signature at the base.
    #   2. Checks each Merkle authentication path layer by layer.
    #   3. Compares the computed root against the known public key.
    #      Accepts if and only if the roots match.
    start = time.perf_counter()
    sigalg.verify(signature, MESSAGE, public_key)
    times["verify"] += time.perf_counter() - start

# ── Measure artifact sizes (single run, outside the timed loop) ───────────────
public_key, secret_key = sigalg.keypair()
signature              = sigalg.sign(MESSAGE, secret_key)
sizes["public_key"]    = len(public_key)
sizes["secret_key"]    = len(secret_key)
sizes["signature"]     = len(signature)

# ── Results ───────────────────────────────────────────────────────────────────
print("Benchmark complete.")
print("-" * 50)
print(f"Public key size   : {sizes['public_key']}    bytes")
print(f"Secret key size   : {sizes['secret_key']}    bytes")
print(f"Signature size    : {sizes['signature']:,} bytes  (~{sizes['signature']/1024:.1f} KB)")
print(f"Avg KeyPair time  : {(times['keypair'] / NUM_ITERATIONS) * 1000:.4f} ms")
print(f"Avg Sign time     : {(times['sign']    / NUM_ITERATIONS) * 1000:.4f} ms")
print(f"Avg Verify time   : {(times['verify']  / NUM_ITERATIONS) * 1000:.4f} ms")
