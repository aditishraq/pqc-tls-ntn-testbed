"""
modules/testbed.py — the ONE network-emulation + container implementation.

Topology (fresh Docker bridge network per Testbed instance):
  client  : persistent container, runs hsclient / s_client / ping / iperf3 client
  server  : s_server (restarted per configuration), iperf3 server, tcpdump
  monitor : --cgroupns host, reads the server's cgroup counters from OUTSIDE the
            server, so the probe's own CPU is never charged to the server

Emulation: one netem qdisc on eth0 (egress) of client AND server:
  delay ± jitter (uniform), loss (independent per direction), rate (per direction).
  Nothing is applied on host interfaces. netem jitter can reorder packets.
"""

import math
import re
import time
from pathlib import Path

from config.settings import (CERT_DIR, TESTBED_IMAGE, SERVER_PORT, SERVER_NAME, KEM_GROUP,
                             NTN_PROFILES, TOL, PING_COUNT, PING_INTERVAL_S, IPERF_SECONDS,
                             HANDSHAKE_TIMEOUT_S)
from modules.utils import run, log, parse_jsonl

UDP_PAYLOAD = 1200


class Testbed:

    def __init__(self, name: str, out_dir: Path):
        tag = out_dir.name.replace(".", "-")[-24:]
        self.net, self.srv = f"pqc_{name}_{tag}", f"{name}_srv_{tag}"
        self.cli, self.mon = f"{name}_cli_{tag}", f"{name}_mon_{tag}"
        self.out = out_dir
        self.pcap_dir = out_dir / "pcap"
        self.srv_ip, self.profile, self.cg_path = "", "baseline", ""

    # ── lifecycle ──────────────────────────────────────────
    def up(self):
        self.down()
        self.pcap_dir.mkdir(parents=True, exist_ok=True)
        run(["docker", "network", "create", "--driver", "bridge", self.net])
        self._start(self.cli, ["sleep", "infinity"])
        run(["docker", "run", "-d", "--rm", "--name", self.mon, "--cgroupns", "host",
             "-v", "/sys/fs/cgroup:/sys/fs/cgroup:ro", TESTBED_IMAGE, "sleep", "infinity"])

    def down(self):
        run(["docker", "rm", "-f", self.srv, self.cli, self.mon])
        run(["docker", "network", "rm", self.net])

    def _start(self, name: str, cmd: list[str]) -> bool:
        r = run(["docker", "run", "-d", "--rm", "--name", name, "--network", self.net,
                 "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
                 "-v", f"{CERT_DIR}:/certs:ro", "-v", f"{self.pcap_dir}:/pcap",
                 TESTBED_IMAGE, *cmd])
        if r.returncode:
            log.error(f"  docker run {name}: {r.stderr.strip()[:200]}")
        return r.returncode == 0

    def exec(self, container: str, cmd: str, timeout: int = 900) -> str:
        r = run(["docker", "exec", container, "sh", "-c", cmd], timeout=timeout)
        return r.stdout + r.stderr

    def start_server(self, cert: str, key: str, groups: str = KEM_GROUP, extra: str = "",
                     www: bool = True) -> str:
        """(Re)start s_server with the current profile. No -CAfile: only the leaf
        (plus any explicit -cert_chain) is sent. www=False makes s_server print the
        (early) application data it receives, which is the server-side evidence for 0-RTT."""
        run(["docker", "rm", "-f", self.srv])
        self.srv_ip = ""
        cmd = (f"openssl s_server -cert /certs/{cert} -key /certs/{key} -accept {SERVER_PORT} "
               f"{'-www' if www else ''} -tls1_3 -groups {groups} {extra}")
        feed = "exec" if www else "sleep infinity |"          # non-www s_server quits on stdin EOF
        if not self._start(self.srv, ["sh", "-c", f"iperf3 -s -D >/dev/null; {feed} {cmd}"]):
            return ""
        ip = run(["docker", "inspect", "-f",
                  "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", self.srv]).stdout.strip()
        for _ in range(100):
            if "open" in self.exec(self.cli, f"nc -z -w1 {ip} {SERVER_PORT} && echo open"):
                self.srv_ip = ip
                break
            time.sleep(0.1)
        if not self.srv_ip:
            log.error(f"  s_server not listening: {self.server_log()[-300:]}")
            return ""
        sid = run(["docker", "inspect", "-f", "{{.Id}}", self.srv]).stdout.strip()
        self.cg_path = self.exec(self.mon, f"find /sys/fs/cgroup -maxdepth 4 -type d "
                                           f"-name '*{sid}*' | head -1").strip()
        self.apply(self.profile)
        return ip

    def server_log(self) -> str:
        r = run(["docker", "logs", self.srv])
        return r.stdout + r.stderr

    # ── NTN emulation ──────────────────────────────────────
    def apply(self, profile: str):
        """Replace (never stack) the root qdisc on both containers and verify the result."""
        p = NTN_PROFILES[profile]
        self.profile = profile
        netem = (f"netem delay {p['delay_ms']}ms {p['jitter_ms']}ms "
                 f"loss {p['loss_pct']}% rate {p['bw_mbit']}mbit") if p["delay_ms"] else \
                f"netem rate {p['bw_mbit']}mbit"
        for c in (self.cli, self.srv):
            self.exec(c, "tc qdisc del dev eth0 root 2>/dev/null; "
                         f"tc qdisc add dev eth0 root handle 1: {netem}")
        state = self.qdisc_state()
        for c in (self.cli, self.srv):
            n = state[c].count("qdisc netem")
            if n != 1:
                raise RuntimeError(f"{c}: expected exactly 1 netem qdisc, found {n}:\n{state[c]}")

    def qdisc_state(self) -> dict:
        return {c: self.exec(c, "tc -s qdisc show dev eth0") for c in (self.cli, self.srv)}

    # ── network validation ─────────────────────────────────
    def ping(self, count: int = PING_COUNT, interval: float = PING_INTERVAL_S) -> dict:
        out = self.exec(self.cli, f"ping -q -c {count} -i {interval} -W 5 {self.srv_ip}")
        m = re.search(r"(\d+) packets transmitted, (\d+) received", out)
        r = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
        if not (m and r):
            return {"error": out[-200:]}
        tx, rx = int(m.group(1)), int(m.group(2))
        return {"sent": tx, "received": rx, "loss_pct": 100 * (tx - rx) / tx,
                "rtt_min": float(r.group(1)), "rtt_avg": float(r.group(2)),
                "rtt_max": float(r.group(3)), "rtt_std": float(r.group(4))}

    def udp_rate(self, mbit: float, reverse: bool) -> dict:
        """UDP goodput (1200-byte payloads) at 1.25× the configured rate. Retried: the iperf3
        TCP control connection itself can fail under GEO delay + loss."""
        d = "s2c" if reverse else "c2s"
        for attempt in range(1, 4):
            out = self.exec(self.cli, f"iperf3 -c {self.srv_ip} -u -b {mbit * 1.25:.2f}M -l {UDP_PAYLOAD} "
                                      f"-t {IPERF_SECONDS} --json {'-R' if reverse else ''}",
                            timeout=IPERF_SECONDS * 6 + 60)
            m = re.search(r'"sum_received"\s*:\s*\{[^}]*?"bits_per_second"\s*:\s*([\d.e+]+)', out)
            if m:
                return {"direction": d, "offered_mbit": mbit * 1.25, "attempts": attempt,
                        "received_mbit": float(m.group(1)) / 1e6}
            err = re.search(r'"error"\s*:\s*"([^"]*)"', out)
            log.warning(f"  iperf3 {d} attempt {attempt} failed: {err.group(1) if err else out[-120:]}")
        return {"direction": d, "attempts": 3, "error": err.group(1) if err else out[-200:]}

    def validate(self, profile: str) -> dict:
        """Measure RTT, jitter, loss and per-direction rate; compare to the profile."""
        p = NTN_PROFILES[profile]
        res = {"profile": profile, **{f"cfg_{k}": v for k, v in p.items()}}
        ping = self.ping()
        res.update({f"ping_{k}": v for k, v in ping.items()})
        for r in (self.udp_rate(p["bw_mbit"], rev) for rev in (False, True)):
            res[f"rate_{r['direction']}_mbit"] = r.get("received_mbit", float("nan"))
            res[f"rate_{r['direction']}_attempts"] = r["attempts"]
            res[f"rate_{r['direction']}_error"] = r.get("error", "")

        checks = {}
        if "error" in ping:
            checks["ping"] = False
        else:
            target = 2 * p["delay_ms"]
            if target == 0:
                checks["rtt"] = ping["rtt_avg"] <= TOL["baseline_rtt_ms"]
            else:
                checks["rtt"] = abs(ping["rtt_avg"] - target) <= max(TOL["rtt_rel"] * target,
                                                                     TOL["rtt_abs_ms"])
            q = p["loss_pct"] / 100
            exp_rt = 1 - (1 - q) ** 2
            sigma = math.sqrt(exp_rt * (1 - exp_rt) / ping["sent"]) * 100
            res["expected_rt_loss_pct"] = round(exp_rt * 100, 3)
            checks["loss"] = abs(ping["loss_pct"] - exp_rt * 100) <= TOL["loss_sigma"] * sigma + TOL["loss_abs_pct"]
            if p["jitter_ms"]:
                exp_std = p["jitter_ms"] * math.sqrt(2 / 3)
                res["expected_rtt_std_ms"] = round(exp_std, 2)
                checks["jitter"] = abs(ping["rtt_std"] - exp_std) <= TOL["jitter_rel"] * exp_std
        # netem's rate counts Ethernet+IP+UDP headers (42 B); iperf3 reports payload only.
        exp_rate = p["bw_mbit"] * (1 - p["loss_pct"] / 100) * UDP_PAYLOAD / (UDP_PAYLOAD + 42)
        res["expected_rate_mbit"] = round(exp_rate, 3)
        for d in ("c2s", "s2c"):
            v = res.get(f"rate_{d}_mbit", float("nan"))
            checks[f"rate_{d}"] = abs(v - exp_rate) <= TOL["bw_rel"] * exp_rate
        res.update({f"check_{k}": v for k, v in checks.items()})
        res["passed"] = all(checks.values())
        return res

    # ── measurement ────────────────────────────────────────
    def hs(self, n: int, ca: str, groups: str = KEM_GROUP, mode: str = "hs") -> list[dict]:
        """n sequential handshakes (mode=hs) or n barrier-synchronised clients (mode=conc)."""
        out = self.exec(self.cli, f"hsclient {mode} {self.srv_ip} {SERVER_PORT} /certs/{ca}.crt "
                                  f"{groups} {SERVER_NAME} {n} {HANDSHAKE_TIMEOUT_S}",
                        timeout=HANDSHAKE_TIMEOUT_S * (n + 2))
        rows = parse_jsonl(out)
        if len(rows) != n:
            log.warning(f"  hsclient returned {len(rows)}/{n} rows: {out[-200:]}")
        return rows

    def cgroup(self) -> dict:
        """Server cgroup counters, read from the monitor container."""
        out = self.exec(self.mon, f"cat {self.cg_path}/cpu.stat {self.cg_path}/memory.current "
                                  f"{self.cg_path}/memory.peak")
        stat = dict(re.findall(r"^(\w+_usec) (\d+)$", out, re.M))
        nums = [int(x) for x in re.findall(r"^(\d+)$", out, re.M)]
        return {"cpu_usec": int(stat.get("usage_usec", -1)),
                "user_usec": int(stat.get("user_usec", -1)),        # s_server (TLS + crypto)
                "system_usec": int(stat.get("system_usec", -1)),    # kernel: TCP, netem, softirq
                "mem_current": nums[0] if nums else -1, "mem_peak": nums[1] if len(nums) > 1 else -1,
                "t": time.monotonic()}

    def idle_cpu_rate(self, seconds: float) -> float:
        """Server CPU µs per second while idle (subtracted from batch deltas)."""
        a = self.cgroup()
        time.sleep(seconds)
        b = self.cgroup()
        return (b["cpu_usec"] - a["cpu_usec"]) / (b["t"] - a["t"])

    def tcpdump_start(self, name: str):
        self.exec(self.srv, f"rm -f /pcap/{name}.pcap; (tcpdump -i eth0 -U -s 0 -w /pcap/{name}.pcap "
                            f"tcp port {SERVER_PORT} >/dev/null 2>&1 &) ; sleep 1")

    def tcpdump_stop(self, name: str) -> Path:
        import os
        self.exec(self.srv, f"sleep 1; pkill -INT tcpdump; sleep 1; "
                            f"chown {os.getuid()}:{os.getgid()} /pcap/{name}.pcap")
        return self.pcap_dir / f"{name}.pcap"
