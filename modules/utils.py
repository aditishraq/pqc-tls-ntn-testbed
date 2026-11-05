"""
modules/utils.py — shell runner, logging, file writers, s_client parsers, pcap reader.
"""

import csv
import json
import logging
import re
import struct
import subprocess
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger("pqc_ntn")


def run(cmd, timeout: int = 600) -> subprocess.CompletedProcess:
    """Run a command (list → no shell, str → shell). Never raises on non-zero exit."""
    try:
        return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(cmd, 124, e.stdout or "", "TIMEOUT")


def write_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, default=str))


def write_csv(path: Path, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(dict.fromkeys(k for r in rows for k in r))   # union, first-seen order
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def parse_jsonl(text: str) -> list[dict]:
    return [json.loads(l) for l in text.splitlines() if l.startswith("{")]


# ── s_client output (security scenarios only) ──────────────
def sclient_facts(out: str) -> dict:
    def grab(pattern):
        m = re.search(pattern, out)
        return m.group(1) if m else ""
    return {
        "connected": "CONNECTED(" in out,
        "server_alert": grab(r"SSL alert number (\d+)"),
        "verify_code": grab(r"Verify return code: (\d+)"),
        "verify_msg": grab(r"Verify return code: \d+ \(([^)]*)\)"),
        "protocol": grab(r"Protocol: (\S+)"),
        "cipher": grab(r"Cipher is (\S+)"),
        "group": grab(r"Negotiated TLS1\.3 group: (\S+)"),
        "peer_sig": grab(r"Peer signature type: (\S+)"),
        "early_data": grab(r"(Early data was [a-z ]+)"),
        "local_error": next((l.strip() for l in out.splitlines()
                             if "Unknown option" in l or "no cipher match" in l
                             or "no protocols available" in l or "No groups enabled" in l
                             or "no suitable groups" in l), ""),
    }


# ── pcap (Ethernet / IPv4 / TCP) ───────────────────────────
def read_pcap(path: Path) -> list[dict]:
    data = Path(path).read_bytes()
    if len(data) < 24:
        return []
    endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    pkts, off = [], 24
    while off + 16 <= len(data):
        sec, frac, incl, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        frame = data[off + 16: off + 16 + incl]
        off += 16 + incl
        if len(frame) < 34 or frame[12:14] != b"\x08\x00" or frame[23] != 6:
            continue
        ip = frame[14:]
        ihl, ip_len = (ip[0] & 0x0F) * 4, struct.unpack(">H", ip[2:4])[0]
        tcp = ip[ihl:]
        sport, dport, seq = struct.unpack(">HHI", tcp[:8])
        doff = (tcp[12] >> 4) * 4
        payload = tcp[doff: ip_len - ihl]
        pkts.append({"ts": sec + frac / 1e6, "src": ".".join(map(str, ip[12:16])),
                     "dst": ".".join(map(str, ip[16:20])), "sport": sport, "dport": dport,
                     "seq": seq, "flags": tcp[13], "ip_len": ip_len, "payload": payload})
    return pkts


def payload_packets_to(pkts: list[dict], port: int) -> int:
    """Client→server TCP segments carrying data."""
    return sum(1 for p in pkts if p["dport"] == port and p["payload"])


def client_hello_reached(pkts: list[dict], port: int) -> bool:
    """Did a TLS handshake record (type 0x16, i.e. a ClientHello) reach the server?
    A bare alert after a local failure does not count."""
    return any(p["dport"] == port and p["payload"][:1] == b"\x16" for p in pkts)


def _stream(pkts: list[dict]) -> tuple[bytes, int]:
    """Reassemble one direction by sequence number; return (bytes, retransmitted segments)."""
    seen, segs, retrans = set(), {}, 0
    for p in pkts:
        if not p["payload"]:
            continue
        if p["seq"] in seen:
            retrans += 1
            continue
        seen.add(p["seq"])
        segs[p["seq"]] = p["payload"]
    out = b"".join(segs[s] for s in sorted(segs))   # ponytail: no seq wrap handling (fresh conns)
    return out, retrans


def tls_record_boundaries(stream: bytes) -> list[int]:
    pos, ends = 0, []
    while pos + 5 <= len(stream):
        pos += 5 + struct.unpack(">H", stream[pos + 3: pos + 5])[0]
        ends.append(pos)
    return ends


def validate_connection_bytes(pkts: list[dict], port: int, c2s: int, s2c: int) -> dict:
    """Check logical handshake byte counters against the captured TLS record stream of the
    FIRST connection in the capture, and report on-wire bytes for that connection."""
    syn = next((p for p in pkts if p["dport"] == port and p["flags"] & 0x02), None)
    if not syn:
        return {"pcap_ok": False, "reason": "no connection"}
    cport = syn["sport"]
    up = [p for p in pkts if p["sport"] == cport and p["dport"] == port]
    down = [p for p in pkts if p["sport"] == port and p["dport"] == cport]
    s_up, r_up = _stream(up)
    s_down, r_down = _stream(down)
    b_up, b_down = tls_record_boundaries(s_up), tls_record_boundaries(s_down)
    return {
        "pcap_ok": c2s in b_up and s2c in b_down,
        "c2s_on_record_boundary": c2s in b_up, "s2c_on_record_boundary": s2c in b_down,
        "tls_stream_c2s_bytes": len(s_up), "tls_stream_s2c_bytes": len(s_down),
        "wire_ip_bytes_c2s": sum(p["ip_len"] for p in up),
        "wire_ip_bytes_s2c": sum(p["ip_len"] for p in down),
        "packets_c2s": len(up), "packets_s2c": len(down),
        "retransmitted_segments": r_up + r_down,
    }


if __name__ == "__main__":
    # self-check: record walker + boundary validation on a synthetic stream
    rec = lambda n: b"\x16\x03\x03" + struct.pack(">H", n) + b"x" * n
    s = rec(10) + rec(300) + rec(4)
    assert tls_record_boundaries(s) == [15, 320, 329]
    assert sclient_facts("SSL alert number 70\nProtocol: TLSv1.3")["server_alert"] == "70"
    print("utils self-check ok")
