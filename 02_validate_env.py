#!/usr/bin/env python3
"""
02_validate_env.py — run manifest, environment capture, NTN profile validation.

Writes to <run>/:
  manifest.json                 host / runtime / crypto-library / image facts
  config_snapshot.json          config/settings.py values used by this run
  env/*.txt                     openssl version -a, providers, TLS groups, signature algorithms
  network/validation.csv|json   measured RTT, jitter, loss, per-direction rate per profile
  network/qdisc_validate_<profile>.txt
Exits 1 if any profile is outside the tolerances in settings.TOL.
"""

import datetime
import json
import os
import platform
import re
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config.settings as S
from config.settings import run_dir, TESTBED_IMAGE, OQS_IMAGE, NTN_ORDER
from modules.utils import run, log, write_json, write_csv
from modules.testbed import Testbed

OUT = run_dir()


def sh(cmd: str) -> str:
    r = run(cmd)
    return (r.stdout or r.stderr).strip()


def in_image(cmd: str) -> str:
    r = run(["docker", "run", "--rm", TESTBED_IMAGE, "sh", "-c", cmd])
    return (r.stdout + r.stderr).strip()


def host_facts() -> dict:
    u = platform.uname()
    if u.system == "Linux":
        cpu = sh("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2")
        mem = sh("grep MemTotal /proc/meminfo")
        gov = sh("cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a")
        freq = sh("cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq 2>/dev/null | head -4 | tr '\\n' ' ' || echo n/a")
        temp = sh("cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null | tr '\\n' ' ' || echo n/a")
    else:
        cpu = sh("sysctl -n machdep.cpu.brand_string")
        mem = f"{int(sh('sysctl -n hw.memsize')) / 2**30:.1f} GiB"
        gov = freq = temp = "n/a (not Linux)"
    return {"cpu_model": cpu, "logical_cores": os.cpu_count(), "memory": mem,
            "os": f"{u.system} {u.release}", "kernel_version": u.version, "machine": u.machine,
            "hostname": u.node, "python": platform.python_version(),
            "cpufreq_governor": gov, "cpufreq_cur_khz": freq, "thermal_millideg": temp,
            "top_processes": sh("ps -eo pcpu,pmem,comm -r 2>/dev/null | head -11 || "
                                "ps -eo pcpu,pmem,comm --sort=-pcpu | head -11")}


def main():
    run_kind = os.environ.get("PQC_RUN_KIND", "validation")
    providers = in_image("openssl list -providers -verbose")
    info = json.loads(sh("docker info --format '{{json .}}'"))
    manifest = {
        "run_id": OUT.name,
        "run_kind": run_kind,
        "date_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "host": host_facts(),
        "container_runtime": {
            "docker_client": sh("docker version --format '{{.Client.Version}}'"),
            "docker_server": sh("docker version --format '{{.Server.Version}}'"),
            "runtime_os": info.get("OperatingSystem"), "runtime_kernel": info.get("KernelVersion"),
            "runtime_arch": info.get("Architecture"), "runtime_cpus": info.get("NCPU"),
            "runtime_mem_bytes": info.get("MemTotal"), "cgroup_driver": info.get("CgroupDriver"),
            "cgroup_version": info.get("CgroupVersion"),
        },
        "image": {"base": OQS_IMAGE,
                  "base_repo_digests": sh(f"docker image inspect {OQS_IMAGE} --format '{{{{json .RepoDigests}}}}'"),
                  "testbed": TESTBED_IMAGE,
                  "testbed_image_id": sh(f"docker image inspect {TESTBED_IMAGE} --format '{{{{.Id}}}}'")},
        "openssl_version": in_image("openssl version"),
        "oqsprovider": re.search(r"OQS Provider v\.?([\w.]+)", providers).group(1)
                       if "OQS Provider" in providers else "missing",
        "liboqs": (re.search(r"liboqs v\.?([\w.]+)", providers) or [None, "unknown"])[1],
        "kem_group": S.KEM_GROUP,
        "runtime_cpufreq_governor": in_image(
            "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a"),
    }
    write_json(OUT / "manifest.json", manifest)
    write_json(OUT / "config_snapshot.json",
               {k: v for k, v in vars(S).items() if k.isupper()})

    env = OUT / "env"
    env.mkdir(exist_ok=True)
    for name, cmd in {
        "openssl_version_a": "openssl version -a",
        "openssl_providers": "openssl list -providers -verbose",
        "tls_groups": "openssl list -tls-groups -tls1_3",
        "tls_signature_algorithms": "openssl list -tls-signature-algorithms",
        "signature_algorithms": "openssl list -signature-algorithms",
        "kem_algorithms": "openssl list -kem-algorithms",
        "openssl_cnf": "cat /opt/openssl/ssl/openssl.cnf",
    }.items():
        (env / f"{name}.txt").write_text(in_image(cmd) + "\n")
    groups = (env / "tls_groups.txt").read_text()
    if S.KEM_GROUP not in groups:
        raise SystemExit(f"{S.KEM_GROUP} not offered by this OpenSSL build")

    log.info("Validating NTN profiles")
    tb = Testbed("val", OUT)
    rows = []
    try:
        tb.up()
        tb.start_server("mldsa65_srv.crt", "mldsa65_srv.key")
        for prof in NTN_ORDER:
            tb.apply(prof)
            state = tb.qdisc_state()
            (OUT / "network").mkdir(exist_ok=True)
            (OUT / "network" / f"qdisc_validate_{prof}.txt").write_text(
                "\n".join(f"## {c}\n{s}" for c, s in state.items()))
            v = tb.validate(prof)
            rows.append(v)
            log.info(f"  {prof:<8} RTT {v.get('ping_rtt_avg', -1):7.1f} ms  std "
                     f"{v.get('ping_rtt_std', -1):5.1f}  RT-loss {v.get('ping_loss_pct', -1):4.1f}% "
                     f"(exp {v.get('expected_rt_loss_pct')})  rate c2s/s2c "
                     f"{v.get('rate_c2s_mbit', -1):.2f}/{v.get('rate_s2c_mbit', -1):.2f} Mbit  "
                     f"{'PASS' if v['passed'] else 'FAIL'}")
    finally:
        tb.down()
    write_csv(OUT / "network" / "validation.csv", rows)
    write_json(OUT / "network" / "validation.json", rows)
    if not all(r["passed"] for r in rows):
        raise SystemExit("✗ network validation failed — see network/validation.csv")
    log.info("✓ environment captured, all profiles within tolerance")


if __name__ == "__main__":
    main()
