#!/usr/bin/env python3
"""
run_all.py — the one documented command.

  python3 run_all.py --publication     # x86-64 Linux only; 50 trials; acceptance enforced
  python3 run_all.py                   # validation run on any Docker host (methodology check)
  python3 run_all.py --smoke           # 10 trials per combination, quick end-to-end check

Creates runs/<run_id>/ (never reused, never merged) and runs, each as a checked subprocess:
  env → setup (image + certs) → validate (manifest + network) → micro → matrix → pcap
  → conc → security → analyze (stats, tables, figures, acceptance) → SHA256SUMS
The analysis environment (.venv, pinned by requirements.txt) is created automatically.
"""

import argparse
import datetime
import hashlib
import os
import platform
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VENV = HERE / ".venv"
VPY = VENV / "bin" / "python"

STAGES = [
    ("setup",    ["01_setup.py"]),
    ("validate", ["02_validate_env.py"]),
    ("micro",    ["03_benchmark.py", "micro"]),
    ("matrix",   ["03_benchmark.py", "matrix"]),
    ("pcap",     ["03_benchmark.py", "pcap"]),
    ("conc",     ["03_benchmark.py", "conc"]),
    ("security", ["05_security_observations.py"]),
    ("analyze",  ["06_analyze.py"]),
]


def ensure_venv():
    req = (HERE / "requirements.txt").read_text()
    stamp = VENV / ".requirements"
    if VPY.exists() and stamp.exists() and stamp.read_text() == req:
        return
    print("Creating .venv from requirements.txt", flush=True)
    subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=True)
    subprocess.run([str(VPY), "-m", "pip", "install", "-q", "-r", str(HERE / "requirements.txt")],
                   check=True)
    stamp.write_text(req)


def run_stage(name: str, argv: list[str], env: dict, log_dir: Path):
    print(f"\n{'═' * 60}\n  {name}\n{'═' * 60}", flush=True)
    with open(log_dir / f"pipeline_{name}.log", "w") as logf:
        p = subprocess.Popen([str(VPY), *argv], cwd=HERE, env=env, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout:
            sys.stdout.write(line)
            logf.write(line)
        p.wait()
    if p.returncode:
        sys.exit(f"✗ stage '{name}' failed (exit {p.returncode}) — see {log_dir}/pipeline_{name}.log")


def checksums(run_dir: Path):
    lines = []
    for f in sorted(run_dir.rglob("*")):
        if f.is_file() and f.name != "SHA256SUMS":
            lines.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(run_dir)}")
    (run_dir / "SHA256SUMS").write_text("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--publication", action="store_true", help="publication run (x86-64 Linux, 50 trials)")
    ap.add_argument("--smoke", action="store_true", help="10 trials per combination")
    ap.add_argument("--only", choices=[s for s, _ in STAGES], help="re-run one stage in --run-dir")
    ap.add_argument("--run-dir", help="existing run directory (only with --only)")
    a = ap.parse_args()

    if a.publication and (platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64")):
        sys.exit("--publication requires the x86-64 Linux testbed host")
    if a.publication and a.smoke:
        sys.exit("--publication and --smoke are exclusive")

    if a.only:
        if not a.run_dir:
            sys.exit("--only needs --run-dir")
        run_dir = Path(a.run_dir).resolve()
        kind = (run_dir / "run_kind").read_text().strip()
    else:
        kind = "publication" if a.publication else "smoke" if a.smoke else "validation"
        run_id = (f"{datetime.datetime.now():%Y%m%d-%H%M%S}_{platform.node().split('.')[0]}_"
                  f"{platform.machine()}_{kind}")
        run_dir = HERE / "runs" / run_id
        run_dir.mkdir(parents=True)                # fails if it exists: never overwrite a run
        (run_dir / "run_kind").write_text(kind + "\n")
    (run_dir / "logs").mkdir(exist_ok=True)

    ensure_venv()
    env = dict(os.environ, PQC_RUN_DIR=str(run_dir), PQC_RUN_KIND=kind,
               PQC_TRIALS="10" if kind == "smoke" else "50", PYTHONUNBUFFERED="1")
    print(f"Run: {run_dir.name}  kind={kind}", flush=True)
    for name, argv in STAGES:
        if not a.only or a.only == name:
            run_stage(name, argv, env, run_dir / "logs")
    checksums(run_dir)
    print(f"\n✓ pipeline complete — {run_dir}")


if __name__ == "__main__":
    main()
