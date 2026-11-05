"""
config/settings.py — single source of configuration for the PQC-NTN TLS testbed.
Every value here is copied into each run's config snapshot.
"""

import os
from pathlib import Path

# ── Paths (repository-relative) ────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
RUNS_DIR = BASE_DIR / "runs"            # one sub-directory per run; never merged
# Certificates are generated per run (01_setup.py) and kept with the run's evidence.
CERT_DIR = Path(os.environ["PQC_RUN_DIR"]) / "certs" if os.environ.get("PQC_RUN_DIR") \
    else BASE_DIR / "certs"


def run_dir() -> Path:
    """Directory of the current run (set by run_all.py). Stages refuse to run without it."""
    d = os.environ.get("PQC_RUN_DIR")
    if not d:
        raise SystemExit("PQC_RUN_DIR not set — start stages through run_all.py")
    return Path(d)


# ── Container image ────────────────────────────────────────
# Immutable digest: OpenSSL 3.6.0 + oqsprovider 0.11.0 (liboqs 0.15.0).
OQS_IMAGE     = ("openquantumsafe/oqs-ossl3@sha256:"
                 "79f6c56e9f3ae50649ead5894f8400a6bd3f0cfe328037f8a4d92f859339f6e4")
TESTBED_IMAGE = "pqc-ntn-testbed:local"   # docker/Dockerfile on top of OQS_IMAGE
SERVER_PORT   = 4433
SERVER_NAME   = "ntn-server"              # SAN of every valid server certificate

# ── Key exchange: FIXED for every trial ────────────────────
# Passed to s_server (-groups) and to the client; never taken from openssl.cnf
# (whose DEFAULT_GROUPS is frodo640aes in this image).
KEM_GROUP = "MLKEM768"

# ── Authentication configurations (the only thing that varies) ──
# expected_sig = TLS signature scheme name OpenSSL reports for the peer.
SIG_ALGS = {
    "ecdsa":          {"nist_level": 1, "type": "classical", "ca": "classical_ca", "expected_sig": "ecdsa_secp256r1_sha256"},
    "falcon512":      {"nist_level": 1, "type": "pqc",       "ca": "ca",           "expected_sig": "falcon512"},
    "mldsa44":        {"nist_level": 2, "type": "pqc",       "ca": "ca",           "expected_sig": "mldsa44"},
    "mldsa65":        {"nist_level": 3, "type": "pqc",       "ca": "ca",           "expected_sig": "mldsa65"},
    "mldsa87":        {"nist_level": 5, "type": "pqc",       "ca": "ca",           "expected_sig": "mldsa87"},
    "p256_falcon512": {"nist_level": 1, "type": "hybrid",    "ca": "ca",           "expected_sig": "p256_falcon512"},
    "p256_mldsa44":   {"nist_level": 2, "type": "hybrid",    "ca": "ca",           "expected_sig": "p256_mldsa44"},
    "p384_mldsa65":   {"nist_level": 3, "type": "hybrid",    "ca": "ca",           "expected_sig": "p384_mldsa65"},
}

ALGO_LABELS = {
    "ecdsa": "ECDSA P-256", "falcon512": "FALCON-512", "mldsa44": "ML-DSA-44",
    "mldsa65": "ML-DSA-65", "mldsa87": "ML-DSA-87", "p256_falcon512": "P-256+FALCON-512",
    "p256_mldsa44": "P-256+ML-DSA-44", "p384_mldsa65": "P-384+ML-DSA-65",
}

# ── NTN profiles (3GPP TR 38.821-inspired) ─────────────────
# Applied with ONE netem qdisc on eth0 of BOTH containers (egress), therefore:
#   delay_ms  : one-way, per direction      → RTT ≈ 2 × delay_ms
#   jitter_ms : uniform ± per direction     → RTT std ≈ jitter × √(2/3)
#   loss_pct  : independent per direction   → round-trip loss = 1 − (1 − p)²
#   bw_mbit   : per direction (full duplex) → netem built-in rate limiter
NTN_PROFILES = {
    "baseline": {"delay_ms": 0,   "jitter_ms": 0,  "loss_pct": 0.0, "bw_mbit": 100},
    "leo":      {"delay_ms": 20,  "jitter_ms": 5,  "loss_pct": 0.5, "bw_mbit": 20},
    "meo":      {"delay_ms": 80,  "jitter_ms": 10, "loss_pct": 1.0, "bw_mbit": 10},
    "geo":      {"delay_ms": 280, "jitter_ms": 20, "loss_pct": 2.0, "bw_mbit": 5},
}
NTN_ORDER = list(NTN_PROFILES)

# Network-validation tolerances: a profile outside these aborts the run.
TOL = {
    "rtt_rel": 0.10,       # |mean RTT − 2·delay| ≤ 10 % of 2·delay
    "rtt_abs_ms": 3.0,     # … or ≤ 3 ms (small RTTs; virtualisation overhead)
    "baseline_rtt_ms": 1.0,
    "bw_rel": 0.10,        # UDP receive rate within 10 % of bw·(1 − p)
    "loss_sigma": 3.0,     # round-trip ping loss within 3 binomial σ …
    "loss_abs_pct": 0.3,   # … plus 0.3 percentage points
    "jitter_rel": 0.35,    # RTT std within 35 % of jitter·√(2/3)
}
PING_COUNT, PING_INTERVAL_S = 1000, 0.01
IPERF_SECONDS = 5

# ── Benchmark design ───────────────────────────────────────
TRIALS             = int(os.environ.get("PQC_TRIALS", 50))   # per algorithm × profile (50 = publication)
CPU_BATCHES        = 5      # TRIALS split into independent cgroup batches
IDLE_WINDOW_S      = 3      # server idle CPU baseline per server start
HANDSHAKE_TIMEOUT_S = 120
PCAP_TRIALS        = 3      # representative trials per algorithm captured for byte validation

CONC_LEVELS   = [1, 5, 10, 20, 50]
CONC_ALGS     = ["ecdsa", "mldsa65"]
CONC_PROFILES = ["baseline", "geo"]

MICROBENCH_SECONDS = 2.0
MICROBENCH_WARMUP  = 50

SECURITY_PROFILE     = "geo"
RANDOMNESS_SAMPLES   = 1000  # ServerHello.random uniqueness (baseline profile)
