#!/usr/bin/env python3
"""
05_security_observations.py — the ONE security-test implementation.

Every scenario restarts the server, captures server-side traffic (tcpdump), runs one
attempt and stores: command, server config, expectation, whether client traffic
reached the server, observed alert / verification result / negotiated parameters,
raw client + server logs, pcap path, and a classification derived ONLY from what was
observed:

  observed_server_rejection             server sent a TLS alert / rejected the attempt
  observed_client_validation_rejection  client certificate/hostname validation failed
  observed_acceptance                   the attempt completed (handshake succeeded)
  not_exercised                         the client never sent it (local refusal) — no server claim
  configuration_dependent               outcome is a deployment/migration policy choice
  load_observation                      limited load measurement, not a DoS claim
  observed_property                     measured property (e.g. ServerHello.random uniqueness)
  analytical_or_operational             not tested; stated from specification/operations

Output: raw/security_observations.csv|json, logs/security/*, pcap/security_*.pcap
"""

import os
import sys
import uuid
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import (run_dir, KEM_GROUP, SERVER_NAME, SERVER_PORT, SECURITY_PROFILE,
                             RANDOMNESS_SAMPLES)
from modules.utils import (log, write_csv, write_json, sclient_facts, read_pcap,
                           payload_packets_to, client_hello_reached)
from modules.testbed import Testbed

OUT = run_dir()
SLOG = OUT / "logs" / "security"

# id, category, attempted condition, server cert, client trust anchor, extra client args,
# expected classification, expected alert / verify code
SCENARIOS = [
    ("S01", "version_downgrade", "TLS 1.2 ClientHello", "mldsa65", "ca",
     "-tls1_2 -groups X25519:P-256", "observed_server_rejection", "alert 70"),
    ("S02", "version_downgrade", "TLS 1.1 ClientHello (client SECLEVEL=0)", "mldsa65", "ca",
     "-tls1_1 -cipher DEFAULT@SECLEVEL=0 -groups X25519:P-256", "observed_server_rejection", "alert 70"),
    ("S03", "version_downgrade", "SSLv3 ClientHello", "mldsa65", "ca",
     "-ssl3", "not_exercised", ""),
    ("S04", "kem_downgrade", f"classical groups only (X25519, P-256) vs server pinned {KEM_GROUP}",
     "mldsa65", "ca", "-groups X25519:P-256", "observed_server_rejection", "alert 40"),
    ("S05", "kem_downgrade", "empty supported_groups", "mldsa65", "ca",
     "-groups ''", "not_exercised", ""),
    ("S06", "weak_cipher", "RC4 cipher suite (TLS 1.2)", "mldsa65", "ca",
     "-tls1_2 -cipher RC4-SHA", "not_exercised", ""),
    ("S07", "weak_cipher", "single-DES / 3DES cipher suite (TLS 1.2)", "mldsa65", "ca",
     "-tls1_2 -cipher DES-CBC3-SHA", "not_exercised", ""),
    ("S08", "certificate", "leaf issued by an untrusted (rogue) CA", "rogue", "ca",
     "", "observed_client_validation_rejection", "verify 20"),
    ("S09", "certificate", "classical-CA leaf, client trusts only the PQC root", "ecdsa", "ca",
     "", "observed_client_validation_rejection", "verify 20"),
    ("S10", "certificate", "self-signed server certificate", "selfsigned", "ca",
     "", "observed_client_validation_rejection", "verify 18"),
    ("S11", "certificate", "expired certificate (notAfter 2020-01-02)", "expired", "ca",
     "", "observed_client_validation_rejection", "verify 10"),
    ("S12", "certificate", "valid chain, SAN does not match expected host", "mismatch", "ca",
     "", "observed_client_validation_rejection", "verify 62"),
    ("S13", "certificate", "intermediate stripped from chain (leaf only)", "chain", "ca",
     "", "observed_client_validation_rejection", "verify 20"),
    ("S13c", "certificate", "control: complete chain (leaf + intermediate)", "chain", "ca",
     "", "observed_acceptance", "verify 0"),
    ("S14", "client_configuration", "client without any trust anchor", "mldsa65", None,
     "", "observed_client_validation_rejection", "verify 20"),
    ("S15", "migration_policy", "classical-only client vs hybrid-certificate server pinned to "
     f"{KEM_GROUP}", "p384_mldsa65", "ca", "-groups X25519:P-256:P-384",
     "configuration_dependent", "alert 40"),
]


def classify(facts: dict, reached: bool) -> str:
    if not reached:
        return "not_exercised"
    # TLS 1.3 fixes cipher + group in ServerHello, BEFORE certificate validation,
    # so a failed verification must be checked first.
    if facts["verify_code"] not in ("", "0"):
        return "observed_client_validation_rejection"
    if facts["cipher"] not in ("", "(NONE)") and facts["group"] not in ("", "<NULL>"):
        return "observed_acceptance"
    if facts["server_alert"]:
        return "observed_server_rejection"
    return "observed_failure_unclassified"


class Sec:

    def __init__(self):
        self.tb = Testbed("sec", OUT)
        self.rows = []

    def server(self, cert: str, profile: str, extra: str = "", www: bool = True):
        self.tb.profile = profile
        ip = self.tb.start_server(f"{cert}_srv.crt", f"{cert}_srv.key", extra=extra, www=www)
        if not ip:
            raise RuntimeError(f"server {cert} failed")
        return ip

    def sclient(self, ca, args: str) -> str:
        ca_opt = f"-CAfile /certs/{ca}.crt" if ca else ""
        if "-groups" not in args and "-ssl3" not in args:
            args += f" -groups {KEM_GROUP}"          # never fall back to openssl.cnf (frodo640aes)
        return (f"echo Q | timeout 120 openssl s_client -connect {self.tb.srv_ip}:{SERVER_PORT} "
                f"-servername {SERVER_NAME} -verify_hostname {SERVER_NAME} -verify_return_error "
                f"{ca_opt} {args} 2>&1")

    def record(self, sid, category, attempted, server_cfg, command, client_out, expected,
               expected_detail, classification=None, interpretation="", profile=SECURITY_PROFILE,
               pcap=None, extra=None):
        (SLOG / f"{sid}_client.log").write_text(client_out)
        (SLOG / f"{sid}_server.log").write_text(self.tb.server_log())
        facts = sclient_facts(client_out)
        pkts = read_pcap(pcap) if pcap and pcap.exists() else None
        pk = payload_packets_to(pkts, SERVER_PORT) if pkts is not None else None
        hello = client_hello_reached(pkts, SERVER_PORT) if pkts is not None else None
        observed = classification or classify(facts, bool(hello))
        detail = (f"alert {facts['server_alert']}" if facts["server_alert"] else
                  f"verify {facts['verify_code']}" if facts["verify_code"] else "")
        row = {
            "id": sid, "category": category, "initiator": "client", "profile": profile,
            "attempted": attempted, "server_config": server_cfg, "command": command,
            "expected": expected, "expected_detail": expected_detail,
            "client_payload_packets_at_server": pk, "reached_server": hello,
            "classification": observed,
            "matches_expectation": observed == expected and
                                   (not expected_detail or expected_detail.split()[-1] in detail.split()),
            "server_alert": facts["server_alert"], "verify_code": facts["verify_code"],
            "verify_msg": facts["verify_msg"], "protocol": facts["protocol"], "cipher": facts["cipher"],
            "group": facts["group"], "peer_sig": facts["peer_sig"], "local_error": facts["local_error"],
            "interpretation": interpretation,
            "client_log": f"logs/security/{sid}_client.log",
            "server_log": f"logs/security/{sid}_server.log",
            "pcap": str(pcap.relative_to(OUT)) if pcap else "", **(extra or {}),
        }
        self.rows.append(row)
        log.info(f"  {sid:<5} {observed:<38} {detail:<10} "
                 f"reached={row['reached_server']}  {'✓' if row['matches_expectation'] else '✗ UNEXPECTED'}")

    # ── scenario runners ───────────────────────────────────
    def handshake_scenarios(self):
        for sid, cat, attempted, cert, ca, args, expected, exp_detail in SCENARIOS:
            extra = "-cert_chain /certs/inter_ca.crt" if sid == "S13c" else ""
            self.server(cert, SECURITY_PROFILE, extra)
            cmd = self.sclient(ca, args)
            self.tb.tcpdump_start(f"security_{sid}")
            out = self.tb.exec(self.tb.cli, cmd)
            pcap = self.tb.tcpdump_stop(f"security_{sid}")
            interp = {
                "not_exercised": "Rejected locally by the client; no claim about server behaviour.",
                "configuration_dependent": "Strict PQC-only policy locks out classical clients; "
                                           "a transition deployment may choose otherwise.",
            }.get(expected, "")
            self.record(sid, cat, attempted,
                        f"s_server {cert}_srv -groups {KEM_GROUP} {extra}".strip(), cmd, out,
                        expected, exp_detail, interpretation=interp, pcap=pcap,
                        classification="configuration_dependent"
                        if expected == "configuration_dependent" and sclient_facts(out)["server_alert"] else None)

    def zero_rtt(self, sid: str, early_enabled: bool):
        marker = f"EARLY-{OUT.name}-{uuid.uuid4().hex[:12]}"
        self.server("mldsa65", SECURITY_PROFILE, "-early_data" if early_enabled else "", www=False)
        base = (f"openssl s_client -connect {self.tb.srv_ip}:{SERVER_PORT} -CAfile /certs/ca.crt "
                f"-groups {KEM_GROUP} -servername {SERVER_NAME} -verify_hostname {SERVER_NAME}")
        # 1) obtain a ticket; wait until it is fully written and parseable (GEO delay/loss)
        get_ticket = (f"rm -f /tmp/t; for i in 1 2 3; do (sleep 8; echo Q) | {base} -sess_out /tmp/t "
                      f">/dev/null 2>&1; openssl sess_id -in /tmp/t -noout -text 2>/dev/null "
                      f"| grep -q 'Max Early Data' && break; done; "
                      f"openssl sess_id -in /tmp/t -noout -text | grep 'Max Early Data'")
        ticket = self.tb.exec(self.tb.cli, get_ticket)
        # 2) send identifiable early data, then replay the SAME ticket and data
        send = (f"printf '{marker}\\n' > /tmp/ed; "
                f"for k in 1 2; do echo \"== attempt $k\"; (sleep 8; echo Q) | {base} "
                f"-sess_in /tmp/t -early_data /tmp/ed 2>&1; done")
        self.tb.tcpdump_start(f"security_{sid}")
        out = self.tb.exec(self.tb.cli, send)
        pcap = self.tb.tcpdump_stop(f"security_{sid}")
        attempts = [a for a in out.split("== attempt ")[1:]]
        status = [sclient_facts(a)["early_data"] or "?" for a in attempts]
        seen = self.tb.server_log().count(marker)
        max_ed = ticket.split(":")[-1].strip() if ":" in ticket else "?"
        if not early_enabled:
            cls = "configuration_dependent"
            interp = (f"Ticket max_early_data={max_ed}: the server does not offer 0-RTT, so the client "
                      f"sent no early data ({status}). Replay was not exercised.")
        elif len(status) == 2 and "accepted" in status[0] and "rejected" in status[1] and seen == 1:
            cls = "observed_server_rejection"
            interp = (f"First early data accepted, replay of the same ticket+data rejected; "
                      f"marker received by the server {seen}×.")
        elif seen >= 2:
            cls, interp = "observed_acceptance", f"Replayed early data reached the application ({seen}×)."
        else:
            cls, interp = "not_exercised", f"Ticket/early data not established: {status}, marker seen {seen}×."
        self.record(sid, "replay", "0-RTT early data replay" + ("" if early_enabled else " (default server)"),
                    f"s_server mldsa65_srv {'-early_data' if early_enabled else '(default, no -early_data)'}",
                    get_ticket + " ; " + send, ticket + "\n" + out,
                    "observed_server_rejection" if early_enabled else "configuration_dependent", "",
                    classification=cls, interpretation=interp, pcap=pcap,
                    extra={"early_data_status": " | ".join(status), "marker_count_server": seen,
                           "ticket_max_early_data": max_ed})

    def randomness(self):
        self.server("mldsa65", "baseline")
        rows = self.tb.hs(RANDOMNESS_SAMPLES, "ca")
        rnd = [r["server_random"] for r in rows if r.get("server_random")]
        dup = len(rnd) - len(set(rnd))
        self.record("S16", "replay", f"ServerHello.random uniqueness over {len(rnd)} handshakes",
                    "s_server mldsa65_srv", f"hsclient hs × {RANDOMNESS_SAMPLES}",
                    "\n".join(rnd), "observed_property", "", profile="baseline",
                    classification="observed_property",
                    interpretation=f"{dup} duplicate 32-byte server randoms in {len(rnd)} samples.",
                    extra={"samples": len(rnd), "duplicates": dup})

    def load(self, k: int = 20):
        self.server("mldsa65", SECURITY_PROFILE)
        rows = self.tb.hs(k, "ca", mode="conc")
        ok = [r for r in rows if r.get("stage") == "ok"]
        t = sorted(r["t_total_ms"] for r in ok)
        self.record("S17", "load", f"{k} barrier-synchronised clients", "s_server mldsa65_srv (single-threaded)",
                    f"hsclient conc {k}", "\n".join(map(str, rows)), "load_observation", "",
                    classification="load_observation",
                    interpretation=(f"{len(ok)}/{k} completed; median/max connection establishment "
                                    f"{t[len(t) // 2] if t else float('nan'):.0f}/{t[-1] if t else float('nan'):.0f} ms. "
                                    "Limited load observation — not evidence of DoS resistance. "
                                    "See concurrency stage for 1–50 clients."),
                    extra={"completed": len(ok), "attempted": k})

    def analytical(self):
        self.record("S18", "revocation", "revoked-but-unexpired certificate during coverage gap",
                    "none", "not executed", "", "analytical_or_operational", "",
                    classification="analytical_or_operational",
                    interpretation="No OCSP/CRL experiment implemented: revocation is UNTESTED. "
                                   "Short-lived certificates / OCSP stapling discussed as mitigations.")

    def run(self):
        SLOG.mkdir(parents=True, exist_ok=True)
        self.tb.up()
        try:
            self.handshake_scenarios()
            self.zero_rtt("S19", early_enabled=False)
            self.zero_rtt("S20", early_enabled=True)
            self.randomness()
            self.load()
            self.analytical()
        finally:
            self.tb.down()
        write_csv(OUT / "raw" / "security_observations.csv", self.rows)
        write_json(OUT / "raw" / "security_observations.json", self.rows)
        bad = [r["id"] for r in self.rows if not r["matches_expectation"]]
        log.info(f"✓ {len(self.rows)} scenarios recorded; unexpected outcomes: {bad or 'none'}")


if __name__ == "__main__":
    Sec().run()
