#!/usr/bin/env python3
"""
06_analyze.py — statistics, tables, figures and acceptance checks for ONE run directory.

Reads only <run>/raw, <run>/network, <run>/certs, <run>/manifest.json. Writes:
  stats/    latency_summary.csv, latency_tests.csv (Mann–Whitney vs ECDSA, Holm per profile)
  tables/   *.csv and *.tex generated from the data (nothing typed by hand)
  figures/  *.png / *.pdf
  acceptance.json   publication acceptance criteria; exit 1 if any required check fails
"""

import json
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy import stats

from config.settings import (run_dir, SIG_ALGS, ALGO_LABELS, NTN_PROFILES, NTN_ORDER, TRIALS,
                             CPU_BATCHES, KEM_GROUP)

OUT = run_dir()
RAW, STATS, TABLES, FIGS = OUT / "raw", OUT / "stats", OUT / "tables", OUT / "figures"
ALGS = list(SIG_ALGS)
LATENCY = {"t_tcp_ms": "TCP connection establishment",
           "t_tls_ms": "TLS 1.3 negotiation (after TCP)",
           "t_total_ms": "total connection establishment (TCP + TLS)"}


def read(name: str) -> pd.DataFrame:
    return pd.read_csv(RAW / name)


def latex(df: pd.DataFrame, path, caption: str):
    """Minimal booktabs table (no jinja2 dependency)."""
    cols = list(df.columns)
    esc = lambda x: str(x).replace("_", r"\_").replace("%", r"\%").replace("&", r"\&")
    lines = [r"\begin{table}[t]", r"\centering", rf"\caption{{{esc(caption)}}}",
             r"\begin{tabular}{" + "l" * len(cols) + "}", r"\toprule",
             " & ".join(esc(c) for c in cols) + r" \\", r"\midrule"]
    lines += [" & ".join(esc(v) for v in row) + r" \\" for row in df.itertuples(index=False)]
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    path.write_text("\n".join(lines) + "\n")


def save(df: pd.DataFrame, name: str, caption: str):
    df.to_csv(TABLES / f"{name}.csv", index=False)
    latex(df, TABLES / f"{name}.tex", caption)


def fig_save(fig, name: str):
    for ext in ("png", "pdf"):
        fig.savefig(FIGS / f"{name}.{ext}", dpi=300, bbox_inches="tight")
    plt.close(fig)


def holm(p: np.ndarray) -> np.ndarray:
    order = np.argsort(p)
    adj, running = np.empty(len(p)), 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (len(p) - rank) * p[i]))
        adj[i] = running
    return adj


def ci95_mean(x) -> float:
    x = np.asarray(x, float)
    return float(stats.t.ppf(0.975, len(x) - 1) * stats.sem(x)) if len(x) > 1 else float("nan")


# ══════════════════════════════════════════════════════════
def main():
    for d in (STATS, TABLES, FIGS):
        d.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((OUT / "manifest.json").read_text())
    acc = {}                                     # acceptance criteria

    # ── network validation ────────────────────────────────
    net = pd.read_csv(OUT / "network" / "validation.csv")
    t = pd.DataFrame({
        "profile": net["profile"], "target RTT (ms)": 2 * net["cfg_delay_ms"],
        "RTT mean (ms)": net["ping_rtt_avg"].round(1), "RTT std (ms)": net["ping_rtt_std"].round(1),
        "expected RTT std (ms)": net.get("expected_rtt_std_ms", pd.Series(dtype=float)).round(1),
        "RT loss (%)": net["ping_loss_pct"].round(2), "expected RT loss (%)": net["expected_rt_loss_pct"],
        "rate c2s (Mbit/s)": net["rate_c2s_mbit"].round(2), "rate s2c (Mbit/s)": net["rate_s2c_mbit"].round(2),
        "expected rate (Mbit/s)": net["expected_rate_mbit"], "passed": net["passed"]})
    save(t, "network_validation", "Measured NTN profile parameters (loss applied independently per "
                                  "direction; RT loss = 1-(1-p)^2)")
    acc["network_profiles_within_tolerance"] = bool(net["passed"].all())

    # ── trials ────────────────────────────────────────────
    df = read("benchmark_trials.csv")
    counts = df.groupby(["alg", "profile"]).size()
    acc["matrix_complete"] = (set(df["alg"]) == set(ALGS) and set(df["profile"]) == set(NTN_ORDER)
                              and bool((counts == TRIALS).all())
                              and len(df) == len(ALGS) * len(NTN_ORDER) * TRIALS)
    acc["matrix_rows"] = int(len(df))
    acc["failed_trials_retained"] = int((~df["success"]).sum())
    ok = df[df["success"]]
    acc["successful_trials_fully_checked"] = bool(
        (ok["protocol"] == "TLSv1.3").all() and (ok["group"].str.lower() == KEM_GROUP.lower()).all()
        and (~ok["cipher"].isin(["NONE", ""])).all()
        and (ok["peer_sig"] == ok["expected_sig"]).all() and (ok["verify_code"] == 0).all())
    acc["physically_impossible_trials"] = int((~df["phys_ok"]).sum())
    df[~df["phys_ok"]].to_csv(STATS / "flag_physically_impossible.csv", index=False)

    # failures table
    fail = df[~df["success"]]
    save(fail.groupby(["alg", "profile", "failure_stage"]).size().reset_index(name="n")
         if len(fail) else pd.DataFrame({"alg": [], "profile": [], "failure_stage": [], "n": []}),
         "failures", "Failed trials by stage (retained in the dataset)")

    # ── latency summary (medians / IQR / p95 primary) ─────
    summ = []
    for (alg, prof), g in df.groupby(["alg", "profile"]):
        s = g[g["success"]]
        for m in LATENCY:
            x = s[m]
            summ.append({"alg": alg, "profile": prof, "metric": m, "n_attempted": len(g),
                         "n_success": len(s), "median": x.median(), "q1": x.quantile(.25),
                         "q3": x.quantile(.75), "p95": x.quantile(.95), "max": x.max(),
                         "mean": x.mean(), "ci95_mean": ci95_mean(x)})
    summ = pd.DataFrame(summ)
    summ.to_csv(STATS / "latency_summary.csv", index=False)
    for m, label in LATENCY.items():
        piv = summ[summ["metric"] == m].assign(
            cell=lambda d: d.apply(lambda r: f"{r['median']:.1f} [{r['q1']:.1f}-{r['q3']:.1f}] p95 {r['p95']:.1f}", axis=1)
        ).pivot(index="alg", columns="profile", values="cell").reindex(ALGS)[NTN_ORDER]
        piv.insert(0, "configuration", [ALGO_LABELS[a] for a in piv.index])
        save(piv.reset_index(drop=True), f"latency_{m}",
             f"{label}: median [IQR] and 95th percentile, ms (KEM fixed: {KEM_GROUP})")

    # ── hypothesis tests: each config vs ECDSA, Holm within profile ──
    tests = []
    for m in ("t_tls_ms", "t_total_ms"):
        for prof in NTN_ORDER:
            base = ok[(ok["alg"] == "ecdsa") & (ok["profile"] == prof)][m]
            rows = []
            for alg in ALGS[1:]:
                x = ok[(ok["alg"] == alg) & (ok["profile"] == prof)][m]
                if len(x) < 3 or len(base) < 3:
                    continue
                u, p = stats.mannwhitneyu(x, base, alternative="two-sided")
                r = 1 - 2 * u / (len(x) * len(base))      # rank-biserial; negative ⇒ config slower
                rows.append({"metric": m, "profile": prof, "alg": alg, "n_alg": len(x),
                             "n_ecdsa": len(base), "median_alg": x.median(), "median_ecdsa": base.median(),
                             "U": u, "p": p, "rank_biserial_r": r,
                             "effect": "large" if abs(r) >= .5 else "medium" if abs(r) >= .3 else "small"})
            if rows:
                ps = holm(np.array([r["p"] for r in rows]))
                for r, ph in zip(rows, ps):
                    r["p_holm"] = ph
                    r["significant_holm"] = ph < 0.05
                tests += rows
    tests = pd.DataFrame(tests)
    tests.to_csv(STATS / "latency_tests.csv", index=False)
    tt = tests[tests["metric"] == "t_tls_ms"].copy()
    save(pd.DataFrame({"profile": tt["profile"], "configuration": tt["alg"].map(ALGO_LABELS),
                       "n": tt["n_alg"].astype(str) + "/" + tt["n_ecdsa"].astype(str),
                       "median Δ (ms)": (tt["median_alg"] - tt["median_ecdsa"]).round(2),
                       "U": tt["U"].round(0), "p": tt["p"].map("{:.2e}".format),
                       "p (Holm)": tt["p_holm"].map("{:.2e}".format),
                       "r_rb": tt["rank_biserial_r"].round(2), "effect": tt["effect"]}),
         "latency_tests", "TLS negotiation time vs ECDSA: two-sided Mann-Whitney U, Holm-adjusted "
                          "within each profile, rank-biserial r (negative = slower than ECDSA)")

    # ── bytes ─────────────────────────────────────────────
    certs = pd.read_csv(OUT / "certs" / "cert_sizes.csv").set_index("name")
    b = ok[ok["profile"] == "baseline"].groupby("alg")[["bytes_c2s", "bytes_s2c"]].agg(["median", "min", "max"])
    # ECDSA (DER) and FALCON (compressed) signatures vary by a few bytes; ML-DSA is fixed-size.
    spread = ok.groupby("alg")[["bytes_c2s", "bytes_s2c"]].agg(lambda x: x.max() - x.min())
    acc["logical_bytes_stable_per_config"] = bool((spread <= 16).all().all())
    rows = []
    for alg in ALGS:
        c2s, s2c = b.loc[alg, ("bytes_c2s", "median")], b.loc[alg, ("bytes_s2c", "median")]
        cs = certs.loc[f"{alg}_srv"]
        row = {"configuration": ALGO_LABELS[alg], "c2s (B)": int(c2s), "s2c (B)": int(s2c),
               "s2c range (B)": f"{int(b.loc[alg, ('bytes_s2c', 'min')])}-{int(b.loc[alg, ('bytes_s2c', 'max')])}",
               "total (B)": int(c2s + s2c),
               "x ECDSA": round((c2s + s2c) / (b.loc["ecdsa", ("bytes_c2s", "median")] +
                                              b.loc["ecdsa", ("bytes_s2c", "median")]), 2),
               "leaf DER (B)": int(cs["der_cert_bytes"]), "leaf PEM (B)": int(cs["pem_cert_bytes"]),
               "chain sent": int(cs["sent_chain_length"]), "chain DER (B)": int(cs["sent_chain_der_bytes"]),
               "cert share of total (%)": round(100 * cs["sent_chain_der_bytes"] / (c2s + s2c), 1),
               "public key DER (B)": int(cs["der_pubkey_bytes"])}
        for prof in NTN_ORDER:   # full duplex: C per direction
            C = NTN_PROFILES[prof]["bw_mbit"] * 1e6
            row[f"R_hs {prof} (handshakes/s)"] = int(min(C / (8 * c2s), C / (8 * s2c)))
        rows.append(row)
    save(pd.DataFrame(rows), "handshake_bytes",
         "Logical TLS handshake bytes (OpenSSL record-layer counters at handshake completion, "
         "excluding TCP/IP headers). R_hs = min(C_up/(8 B_c2s), C_down/(8 B_s2c)) is a theoretical "
         "bandwidth-limited handshake RATE (handshakes per second, full-duplex link), not concurrency")

    pc = read("pcap_validation.csv")
    acc["pcap_logical_bytes_match_record_boundaries"] = bool(pc["pcap_ok"].all())
    save(pc.groupby(["alg", "profile"]).agg(
        trials=("trial", "count"), record_boundary_match=("pcap_ok", "sum"),
        logical_c2s=("logical_c2s", "median"), logical_s2c=("logical_s2c", "median"),
        wire_ip_c2s=("wire_ip_bytes_c2s", "median"), wire_ip_s2c=("wire_ip_bytes_s2c", "median"),
        retransmitted_segments=("retransmitted_segments", "sum")).reset_index(),
         "wire_bytes", "Packet-capture validation. wire_ip_* = IPv4 bytes for the WHOLE connection "
                       "(handshake, app data, close, retransmissions) — not comparable to logical bytes")

    # ── CPU (cgroup batches) ──────────────────────────────
    cpu = read("cpu_batches.csv")
    acc["cpu_batches_per_combination"] = bool((cpu.groupby(["alg", "profile"]).size() == CPU_BATCHES).all())
    c = cpu.groupby(["alg", "profile"])["cpu_ms_per_handshake"].agg(
        batches="count", median="median", mean="mean", ci95=ci95_mean, min="min", max="max").reset_index()
    for part in ("user", "system"):
        col = f"{part}_ms_per_handshake"
        if col in cpu:
            c = c.merge(cpu.groupby(["alg", "profile"])[col].median().rename(f"{part}_median").reset_index())
    ec = c[c["alg"] == "ecdsa"].set_index("profile")["median"]
    c["x ECDSA (median)"] = (c["median"] / c["profile"].map(ec)).round(2)
    c.to_csv(STATS / "cpu_summary.csv", index=False)
    cb = c[c["profile"] == "baseline"].set_index("alg").reindex(ALGS).reset_index()
    save(pd.DataFrame({"configuration": cb["alg"].map(ALGO_LABELS), "batches": cb["batches"],
                       "CPU ms/handshake (median)": cb["median"].round(3),
                       "mean ± CI95 (batches)": cb["mean"].round(3).astype(str) + " ± " + cb["ci95"].round(3).astype(str),
                       "user ms (median)": cb.get("user_median", np.nan),
                       "system ms (median)": cb.get("system_median", np.nan),
                       "x ECDSA": cb["x ECDSA (median)"]}).round(3),
         "server_cpu", "Server-container CPU time per handshake (cgroup cpu.stat, idle-corrected; "
                       "CI over independent batches), baseline profile. user = s_server (TLS, crypto); "
                       "system = kernel networking charged to the container")
    cp = c.pivot(index="alg", columns="profile", values="median").reindex(ALGS)[NTN_ORDER].round(3)
    cp.insert(0, "configuration", [ALGO_LABELS[a] for a in cp.index])
    save(cp.reset_index(drop=True), "server_cpu_by_profile",
         "Server CPU ms per handshake (median over batches) by profile; growth with delay reflects "
         "kernel network processing (system time), see cpu_summary.csv")

    # ── microbenchmarks ───────────────────────────────────
    mb = read("microbench.csv")
    mp = mb.pivot(index="alg", columns="op", values="ms_per_op").reindex(ALGS)
    prov = mb[mb["op"] == "sign"].set_index("alg")["provider"]
    ops = mb.pivot(index="alg", columns="op", values="ops").reindex(ALGS)
    save(pd.DataFrame({"configuration": [ALGO_LABELS[a] for a in ALGS], "provider": prov.reindex(ALGS).values,
                       "keygen (ms)": mp["keygen"].round(4).values, "sign (ms)": mp["sign"].round(4).values,
                       "verify (ms)": mp["verify"].round(4).values,
                       "ops k/s/v": (ops["keygen"].astype(int).astype(str) + "/" + ops["sign"].astype(int).astype(str)
                                     + "/" + ops["verify"].astype(int).astype(str)).values}),
         "microbench", "In-process EVP keygen/sign/verify (warm-up, time-based loop; provider that "
                       "decodes the server key). 'default' = OpenSSL built-in, 'oqsprovider' = liboqs")

    # ── concurrency ───────────────────────────────────────
    ct, cl = read("concurrency_trials.csv"), read("concurrency_levels.csv")
    cs = ct.groupby(["alg", "profile", "level"]).apply(lambda g: pd.Series({
        "successful": int(g["success"].sum()), "failed": int((~g["success"]).sum()),
        "timeouts": int(g["timeout"].sum()),
        "median total (ms)": g.loc[g["success"], "t_total_ms"].median(),
        "p95 total (ms)": g.loc[g["success"], "t_total_ms"].quantile(.95)}), include_groups=False).reset_index()
    cs = cs.merge(cl, on=["alg", "profile", "level"])
    cs["server CPU (ms)"] = (cs["server_cpu_usec_delta"] / 1000).round(1)
    cs["server mem peak (MiB)"] = (cs["server_mem_peak_bytes"] / 2**20).round(1)
    save(cs[["alg", "profile", "level", "attempted", "successful", "failed", "timeouts", "median total (ms)",
             "p95 total (ms)", "server CPU (ms)", "server mem peak (MiB)"]].round(1),
         "concurrency", "Barrier-synchronised concurrent clients (load observation; s_server is "
                        "single-threaded, not a DoS-resistance claim)")

    # ── security ──────────────────────────────────────────
    sec = read("security_observations.csv")
    acc["no_local_rejection_reported_as_server_defence"] = bool(
        not ((sec["classification"] == "observed_server_rejection") & (sec["reached_server"] == False)).any())  # noqa: E712
    acc["security_outcomes_match_expectation"] = bool(sec["matches_expectation"].all())
    def evidence(r):
        if pd.notna(r["server_alert"]):
            return f"server alert {int(r['server_alert'])}"
        if pd.notna(r["verify_code"]) and int(r["verify_code"]) != 0:
            return f"verify {int(r['verify_code'])} ({r['verify_msg']})"
        if r["classification"] == "observed_acceptance":
            return f"handshake completed, verify 0, group {r['group']}"
        if r["classification"] == "not_exercised" and isinstance(r["local_error"], str):
            return f"client-local: {r['local_error'][-80:]}"
        return r["interpretation"]
    ev = sec.apply(evidence, axis=1)
    save(pd.DataFrame({"ID": sec["id"], "category": sec["category"], "attempted condition": sec["attempted"],
                       "profile": sec["profile"], "ClientHello reached server": sec["reached_server"],
                       "classification": sec["classification"], "evidence": ev}),
         "security_observations", "Security observations (classification derived from observed evidence)")
    save(sec.groupby("classification").size().reset_index(name="scenarios"),
         "security_summary", "Security observation counts by classification")

    # ── figures ───────────────────────────────────────────
    fig, axes = plt.subplots(1, 4, figsize=(15, 3.6))
    for ax, prof in zip(axes, NTN_ORDER):
        data = [ok[(ok["alg"] == a) & (ok["profile"] == prof)]["t_tls_ms"] for a in ALGS]
        ax.boxplot(data, showfliers=True, flierprops={"markersize": 2})
        ax.set_xticks(range(1, len(ALGS) + 1), [ALGO_LABELS[a] for a in ALGS], rotation=60, ha="right", fontsize=7)
        ax.set_title(f"{prof.upper()}  (n={TRIALS}/config)", fontsize=9)
        ax.set_ylabel("TLS negotiation (ms)" if prof == "baseline" else "")
    fig_save(fig, "fig_latency_tls")

    bt = pd.DataFrame(rows)
    fig, ax = plt.subplots(figsize=(7, 3.6))
    y = np.arange(len(bt))
    ax.barh(y, bt["c2s (B)"], label="client→server")
    ax.barh(y, bt["s2c (B)"], left=bt["c2s (B)"], label="server→client")
    ax.scatter(bt["chain DER (B)"], y, color="k", marker="|", s=200, label="certificate chain (DER)")
    ax.set_yticks(y, bt["configuration"], fontsize=8)
    ax.set_xlabel(f"logical TLS handshake bytes (KEM {KEM_GROUP})")
    ax.legend(fontsize=7)
    fig_save(fig, "fig_handshake_bytes")

    fig, ax = plt.subplots(figsize=(7, 3.6))
    ax.barh(np.arange(len(cb)), cb["median"], xerr=cb["ci95"], capsize=3)
    ax.set_yticks(np.arange(len(cb)), cb["alg"].map(ALGO_LABELS), fontsize=8)
    ax.set_xlabel("server CPU ms per handshake (cgroup, baseline; CI over batches)")
    fig_save(fig, "fig_server_cpu")

    fig, axes = plt.subplots(1, 3, figsize=(13, 3.4))
    for ax, op in zip(axes, ("keygen", "sign", "verify")):
        ax.barh(np.arange(len(ALGS)), mp[op].values)
        ax.set_xscale("log")
        ax.set_yticks(np.arange(len(ALGS)), [ALGO_LABELS[a] for a in ALGS], fontsize=7)
        ax.set_title(f"{op} (ms/op, log scale)", fontsize=9)
    fig_save(fig, "fig_microbench")

    fig, ax = plt.subplots(figsize=(6, 3.6))
    for (alg, prof), g in cs.groupby(["alg", "profile"]):
        ax.plot(g["level"], g["median total (ms)"], marker="o", label=f"{ALGO_LABELS[alg]} / {prof}")
    ax.set_xlabel("concurrent clients (barrier start)")
    ax.set_ylabel("median connection establishment (ms)")
    ax.set_yscale("log")
    ax.legend(fontsize=7)
    fig_save(fig, "fig_concurrency")

    # ── acceptance ────────────────────────────────────────
    host = manifest["host"]
    publication = manifest["run_kind"] == "publication"
    acc["platform_x86_64_linux"] = (host["os"].startswith("Linux") and
                                    host["machine"] in ("x86_64", "AMD64")) if publication else \
        "not applicable (validation run)"
    acc["trials_per_combination"] = TRIALS
    acc["latency_excludes_connection_close"] = True        # by construction: timer stops at SSL_connect()
    acc["holm_correction_applied"] = True
    required = ["network_profiles_within_tolerance", "matrix_complete", "successful_trials_fully_checked",
                "pcap_logical_bytes_match_record_boundaries", "cpu_batches_per_combination",
                "no_local_rejection_reported_as_server_defence", "security_outcomes_match_expectation",
                "logical_bytes_stable_per_config"]
    failed = [k for k in required if acc[k] is not True]
    if acc["physically_impossible_trials"]:
        failed.append("physically_impossible_trials")
    if publication and acc["platform_x86_64_linux"] is not True:
        failed.append("platform_x86_64_linux")
    if publication and TRIALS != 50:
        failed.append("trials_per_combination")
    acc["failed_criteria"] = failed
    acc["accepted"] = not failed
    (OUT / "acceptance.json").write_text(json.dumps(acc, indent=2, default=str))
    print(json.dumps(acc, indent=2, default=str))
    if failed:
        raise SystemExit(f"✗ acceptance criteria not met: {failed}")


if __name__ == "__main__":
    main()
