#!/usr/bin/env python3
"""
03_benchmark.py — measurements (raw evidence only; statistics live in 06_analyze.py).

  micro   in-process keygen/sign/verify per configuration (hsclient bench, warm-up,
          time-based loops, provider recorded)             → raw/microbench.csv
  matrix  8 configs × 4 profiles × TRIALS full handshakes, split into CPU_BATCHES
          cgroup batches                                   → raw/benchmark_trials.csv
                                                             raw/cpu_batches.csv
  pcap    PCAP_TRIALS captured handshakes per config (baseline, geo): logical byte
          counters vs captured TLS records, on-wire bytes  → raw/pcap_validation.csv
  conc    barrier-synchronised clients at CONC_LEVELS      → raw/concurrency_trials.csv
                                                             raw/concurrency_levels.csv
Usage (normally via run_all.py):  python 03_benchmark.py micro|matrix|pcap|conc
"""

import csv
import json
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import (run_dir, SIG_ALGS, NTN_PROFILES, NTN_ORDER, KEM_GROUP, TRIALS,
                             CPU_BATCHES, IDLE_WINDOW_S, PCAP_TRIALS, CONC_LEVELS, CONC_ALGS,
                             CONC_PROFILES, MICROBENCH_SECONDS, MICROBENCH_WARMUP,
                             HANDSHAKE_TIMEOUT_S, SERVER_PORT)
from modules.utils import log, write_csv, parse_jsonl, read_pcap, validate_connection_bytes
from modules.testbed import Testbed

OUT = run_dir()
RAW, LOGS = OUT / "raw", OUT / "logs"
RUN_ID = OUT.name


def checks(row: dict, alg: str) -> dict:
    """Individual success conditions — never collapsed without keeping each one."""
    c = {
        "chk_handshake_rc": row.get("ok_tls") == 1,
        "chk_tls13": row.get("protocol") == "TLSv1.3",
        "chk_cipher": row.get("cipher") not in ("", "NONE", "(NONE)"),
        "chk_group": row.get("group", "").lower() == KEM_GROUP.lower(),
        "chk_sigalg": row.get("peer_sig") == SIG_ALGS[alg]["expected_sig"],
        "chk_verify": row.get("verify_code") == 0,
        "chk_hostname": row.get("hostname_ok") == 1,
        "chk_app_data": row.get("ok_app") == 1,
    }
    failed = [k[4:] for k, v in c.items() if not v]
    c["success"] = not failed
    c["failure_stage"] = "" if not failed else f"{row.get('stage')}:{failed[0]}"
    return c


def physical(row: dict, profile: str) -> dict:
    """TCP and TLS 1.3 each need ≥ 1 RTT; the fastest possible RTT is 2·(delay − jitter)."""
    p = NTN_PROFILES[profile]
    floor = 2 * (p["delay_ms"] - p["jitter_ms"]) * 0.98
    ok = (not row.get("ok_tls")) or (row["t_tcp_ms"] >= floor and row["t_tls_ms"] >= floor)
    return {"phys_floor_ms": round(floor, 2), "phys_ok": ok}


def providers() -> dict:
    path = RAW / "microbench.csv"
    if not path.exists():
        raise SystemExit("run `03_benchmark.py micro` first (provider mapping)")
    with open(path) as f:
        return {r["alg"]: r["provider"] for r in csv.DictReader(f) if r["op"] == "sign"}


# ══════════════════════════════════════════════════════════
def micro():
    tb = Testbed("micro", OUT)
    rows = []
    try:
        tb.up()
        for alg, info in SIG_ALGS.items():
            out = tb.exec(tb.cli, f"hsclient bench /certs/{alg}_srv.key "
                                  f"{MICROBENCH_SECONDS} {MICROBENCH_WARMUP}")
            (LOGS / f"microbench_{alg}.jsonl").write_text(out)
            for r in parse_jsonl(out):
                rows.append({"run_id": RUN_ID, "alg": alg, "alg_type": info["type"], **r})
                log.info(f"  {alg:<15} {r['op']:<6} {r.get('ms_per_op', 'ERR'):>10} ms "
                         f"({r.get('ops')} ops, provider={r.get('provider')})")
    finally:
        tb.down()
    write_csv(RAW / "microbench.csv", rows)


def matrix():
    prov = providers()
    tb = Testbed("bench", OUT)
    trials, batches = [], []
    per_batch = TRIALS // CPU_BATCHES
    try:
        tb.up()
        for alg, info in SIG_ALGS.items():
            for prof in NTN_ORDER:
                tag = f"{alg}_{prof}"
                tb.profile = prof
                if not tb.start_server(f"{alg}_srv.crt", f"{alg}_srv.key"):
                    raise SystemExit(f"server failed for {tag}")
                (OUT / "network" / f"qdisc_bench_{tag}.txt").write_text(
                    "\n".join(f"## {c}\n{s}" for c, s in tb.qdisc_state().items()))
                idle = tb.idle_cpu_rate(IDLE_WINDOW_S)
                client_log = LOGS / f"client_{tag}.jsonl"
                log_lines = []
                for b in range(1, CPU_BATCHES + 1):
                    a = tb.cgroup()
                    rows = tb.hs(per_batch, info["ca"])
                    z = tb.cgroup()
                    wall = z["t"] - a["t"]
                    cpu_us = z["cpu_usec"] - a["cpu_usec"]
                    batches.append({
                        "run_id": RUN_ID, "alg": alg, "profile": prof, "batch": b,
                        "n_trials": len(rows), "n_success": sum(checks(r, alg)["success"] for r in rows),
                        "cpu_usec_delta": cpu_us, "wall_s": round(wall, 3),
                        "idle_usec_per_s": round(idle, 2), "idle_correction_usec": round(idle * wall, 1),
                        "cpu_ms_per_handshake": round((cpu_us - idle * wall) / 1000 / max(len(rows), 1), 4),
                        "user_ms_per_handshake": round((z["user_usec"] - a["user_usec"]) / 1000 / max(len(rows), 1), 4),
                        "system_ms_per_handshake": round((z["system_usec"] - a["system_usec"]) / 1000 / max(len(rows), 1), 4),
                        "server_mem_peak_bytes": z["mem_peak"]})
                    for r in rows:
                        log_lines.append(r)
                        trials.append({
                            "run_id": RUN_ID, "alg": alg, "alg_type": info["type"],
                            "nist_level": info["nist_level"], "sig_provider": prov.get(alg, ""),
                            "profile": prof, "batch": b,
                            "trial": (b - 1) * per_batch + r["trial"],
                            "expected_group": KEM_GROUP, "expected_sig": info["expected_sig"],
                            **{k: v for k, v in r.items() if k not in ("mode", "trial")},
                            **checks(r, alg), **physical(r, prof),
                            "client_log": str(client_log.relative_to(OUT)),
                            "server_log": f"logs/server_{tag}.log"})
                client_log.write_text("".join(json.dumps(x) + "\n" for x in log_lines))
                (LOGS / f"server_{tag}.log").write_text(tb.server_log())
                done = [t for t in trials if t["alg"] == alg and t["profile"] == prof]
                ok = [t for t in done if t["success"]]
                med = sorted(t["t_tls_ms"] for t in ok)[len(ok) // 2] if ok else float("nan")
                log.info(f"  {tag:<24} {len(ok)}/{len(done)} ok  TLS median {med:8.1f} ms  "
                         f"CPU {sum(x['cpu_ms_per_handshake'] for x in batches[-CPU_BATCHES:]) / CPU_BATCHES:.3f} ms/hs"
                         f"  phys-inconsistent {sum(not t['phys_ok'] for t in done)}")
    finally:
        tb.down()
    write_csv(RAW / "benchmark_trials.csv", trials)
    write_csv(RAW / "cpu_batches.csv", batches)


def pcap():
    tb = Testbed("pcap", OUT)
    rows = []
    try:
        tb.up()
        for alg, info in SIG_ALGS.items():
            for prof in ("baseline", "geo"):
                tb.profile = prof
                tb.start_server(f"{alg}_srv.crt", f"{alg}_srv.key")
                for k in range(1, PCAP_TRIALS + 1):
                    name = f"pcap_{alg}_{prof}_{k}"
                    tb.tcpdump_start(name)
                    r = (tb.hs(1, info["ca"]) or [{}])[0]
                    f = tb.tcpdump_stop(name)
                    v = validate_connection_bytes(read_pcap(f), SERVER_PORT,
                                                  r.get("bytes_c2s", -1), r.get("bytes_s2c", -1))
                    rows.append({"run_id": RUN_ID, "alg": alg, "profile": prof, "trial": k,
                                 "handshake_ok": r.get("stage") == "ok",
                                 "logical_c2s": r.get("bytes_c2s"), "logical_s2c": r.get("bytes_s2c"),
                                 **v, "pcap": str(f.relative_to(OUT))})
                log.info(f"  {alg:<15} {prof:<8} record-boundary match "
                         f"{sum(x['pcap_ok'] for x in rows[-PCAP_TRIALS:])}/{PCAP_TRIALS}")
    finally:
        tb.down()
    write_csv(RAW / "pcap_validation.csv", rows)


def conc():
    tb = Testbed("conc", OUT)
    trials, levels = [], []
    try:
        tb.up()
        for alg in CONC_ALGS:
            for prof in CONC_PROFILES:
                for k in CONC_LEVELS:
                    tb.profile = prof
                    tb.start_server(f"{alg}_srv.crt", f"{alg}_srv.key")   # fresh: per-level memory peak
                    a = tb.cgroup()
                    rows = tb.hs(k, SIG_ALGS[alg]["ca"], mode="conc")
                    z = tb.cgroup()
                    for r in rows:
                        c = checks(r, alg)
                        trials.append({"run_id": RUN_ID, "alg": alg, "profile": prof, "level": k,
                                       **{x: y for x, y in r.items() if x != "mode"}, **c,
                                       "timeout": (not c["success"]) and
                                                  r["t_elapsed_ms"] >= 0.95 * HANDSHAKE_TIMEOUT_S * 1000})
                    levels.append({"run_id": RUN_ID, "alg": alg, "profile": prof, "level": k,
                                   "attempted": k, "rows_returned": len(rows),
                                   "server_cpu_usec_delta": z["cpu_usec"] - a["cpu_usec"],
                                   "server_mem_before_bytes": a["mem_current"],
                                   "server_mem_peak_bytes": z["mem_peak"],
                                   "batch_wall_s": round(z["t"] - a["t"], 3)})
                    (LOGS / f"server_conc_{alg}_{prof}_{k}.log").write_text(tb.server_log())
                    ok = sum(t["success"] for t in trials[-len(rows):]) if rows else 0
                    log.info(f"  conc {alg:<8} {prof:<8} {k:>3} clients: {ok}/{k} ok")
    finally:
        tb.down()
    write_csv(RAW / "concurrency_trials.csv", trials)
    write_csv(RAW / "concurrency_levels.csv", levels)


if __name__ == "__main__":
    RAW.mkdir(parents=True, exist_ok=True)
    LOGS.mkdir(parents=True, exist_ok=True)
    (OUT / "network").mkdir(parents=True, exist_ok=True)
    steps = {"micro": micro, "matrix": matrix, "pcap": pcap, "conc": conc}
    if len(sys.argv) != 2 or sys.argv[1] not in steps:
        raise SystemExit(f"usage: 03_benchmark.py {'|'.join(steps)}")
    steps[sys.argv[1]]()
