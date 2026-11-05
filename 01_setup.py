#!/usr/bin/env python3
"""
01_setup.py — build the testbed image and generate all certificates for this run.

Certificates (written to <run>/certs as the invoking user, never root-owned):
  ca            ML-DSA-65 root (trust anchor for PQC/hybrid configs)
  classical_ca  ECDSA P-256 root (trust anchor for the ECDSA config)
  inter_ca      ML-DSA-65 intermediate under ca (chain-stripping test)
  rogue_ca      unrelated ML-DSA-65 root (rogue-CA test)
  <alg>_srv     server leaf per configuration, SAN=DNS:ntn-server
  rogue_srv, selfsigned_srv, expired_srv, mismatch_srv, chain_srv   security tests

<run>/certs/cert_sizes.csv records PEM, DER, DER public/private key sizes and the
DER size of the chain the server actually sends (leaf only unless stated).
"""

import csv
import io
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import (BASE_DIR, OQS_IMAGE, TESTBED_IMAGE, SIG_ALGS, SERVER_NAME,
                             run_dir)
from modules.utils import run, log

UID = f"{os.getuid()}:{os.getgid()}"
CERTS = run_dir() / "certs"
SAN = f"-addext subjectAltName=DNS:{SERVER_NAME}"


def ossl(script: str):
    """Run an openssl shell script inside the image, in <run>/certs, as the invoking user."""
    r = run(["docker", "run", "--rm", "--user", UID, "-v", f"{CERTS}:/certs", "-w", "/certs",
             TESTBED_IMAGE, "sh", "-ec", script])
    if r.returncode:
        raise SystemExit(f"openssl failed:\n{script}\n{r.stderr[-500:]}")
    return r.stdout


def leaf(name: str, keyalg: str, ca: str, subj_cn: str = SERVER_NAME, san: str = SAN,
         validity: str = "-days 365") -> str:
    return (f"openssl req -new -newkey {keyalg} -keyout {name}.key -out {name}.csr -nodes "
            f"-subj /CN={subj_cn}/O=6G-NTN/C=SE {san}\n"
            f"openssl x509 -req -in {name}.csr -CA {ca}.crt -CAkey {ca}.key -CAcreateserial "
            f"-copy_extensions copy {validity} -out {name}.crt\n")


def root(name: str, keyalg: str, cn: str) -> str:
    return (f"openssl req -x509 -new -newkey {keyalg} -keyout {name}.key -out {name}.crt "
            f"-nodes -days 3650 -subj /CN={cn}/O=6G-NTN-Research/C=SE\n")


def main():
    CERTS.mkdir(parents=True, exist_ok=True)

    log.info(f"Building {TESTBED_IMAGE} on {OQS_IMAGE}")
    r = run(["docker", "build", "-q", "-f", "docker/Dockerfile", "--build-arg",
             f"OQS_IMAGE={OQS_IMAGE}", "-t", TESTBED_IMAGE, str(BASE_DIR)], timeout=1800)
    if r.returncode:
        raise SystemExit(f"image build failed: {r.stderr[-800:]}")

    ec = "ec -pkeyopt ec_paramgen_curve:P-256"
    script = (root("ca", "mldsa65", "PQC-NTN-RootCA") + root("classical_ca", ec, "Classical-NTN-RootCA")
              + root("rogue_ca", "mldsa65", "Rogue-RootCA")
              + "openssl req -new -newkey mldsa65 -keyout inter_ca.key -out inter_ca.csr -nodes "
                "-subj /CN=PQC-NTN-IntermediateCA/O=6G-NTN-Research/C=SE\n"
                "printf 'basicConstraints=critical,CA:TRUE\\nkeyUsage=critical,keyCertSign,cRLSign\\n' > ca.ext\n"
                "openssl x509 -req -in inter_ca.csr -CA ca.crt -CAkey ca.key -CAcreateserial "
                "-extfile ca.ext -days 3650 -out inter_ca.crt\n")
    for alg, info in SIG_ALGS.items():
        script += leaf(f"{alg}_srv", ec if alg == "ecdsa" else alg, info["ca"])
    script += (leaf("rogue_srv", "mldsa65", "rogue_ca")
               + leaf("mismatch_srv", "mldsa65", "ca", "other-gateway",
                      "-addext subjectAltName=DNS:other-gateway.example")
               + leaf("chain_srv", "mldsa65", "inter_ca")
               + leaf("expired_srv", "mldsa65", "ca",
                      validity="-not_before 20200101000000Z -not_after 20200102000000Z")
               + f"openssl req -x509 -new -newkey mldsa65 -keyout selfsigned_srv.key "
                 f"-out selfsigned_srv.crt -nodes -days 365 -subj /CN={SERVER_NAME} {SAN}\n")
    log.info("Generating certificates")
    ossl(script)

    # Sizes: PEM file, DER cert, DER SubjectPublicKeyInfo, DER private key.
    names = [f"{a}_srv" for a in SIG_ALGS] + ["chain_srv", "inter_ca", "ca", "classical_ca"]
    out = ossl("".join(
        f"echo {n},$(wc -c < {n}.crt),$(openssl x509 -in {n}.crt -outform DER | wc -c),"
        f"$(openssl pkey -in {n}.key -pubout -outform DER | wc -c),"
        f"$(openssl pkey -in {n}.key -outform DER | wc -c)\n" for n in names))
    rows = []
    for name, pem, der, pub, priv in csv.reader(io.StringIO(out)):
        rows.append({"name": name, "pem_cert_bytes": int(pem), "der_cert_bytes": int(der),
                     "der_pubkey_bytes": int(pub), "der_privkey_bytes": int(priv)})
    der = {r["name"]: r["der_cert_bytes"] for r in rows}
    for r in rows:   # what s_server transmits in the benchmark: leaf only (no -CAfile/-cert_chain)
        chain = [r["name"]] + (["inter_ca"] if r["name"] == "chain_srv" else [])
        r["sent_chain_length"] = len(chain) if r["name"].endswith("_srv") else ""
        r["sent_chain_der_bytes"] = sum(der[c] for c in chain) if r["name"].endswith("_srv") else ""
    with open(CERTS / "cert_sizes.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    for r in rows:
        log.info(f"  {r['name']:<18} PEM {r['pem_cert_bytes']:>5}  DER {r['der_cert_bytes']:>5}  "
                 f"pub {r['der_pubkey_bytes']:>5}  priv {r['der_privkey_bytes']:>5}")
    log.info(f"✓ certificates in {CERTS}")


if __name__ == "__main__":
    main()
