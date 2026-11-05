# PQC-TLS NTN Testbed

Measurement code for the paper **"Is Post-Quantum TLS Ready for 6G Satellites? A Measurement Study in Non-Terrestrial Networks"**.

It measures TLS 1.3 handshakes using ML-KEM-768 key exchange and classical, post-quantum and composite server authentication over emulated non-terrestrial network links.

## Requirements

Docker and Python 3.10 or later. Publication runs require an x86-64 Linux host.

## Run

```bash
python3 run_all.py --publication   # full run; x86-64 Linux only
python3 run_all.py                 # validation run on any Docker host
python3 run_all.py --smoke         # quick end-to-end check
```

Each run writes its raw data, statistics, tables, figures and checksums to a new `runs/<run_id>/` folder. Generated runs are not stored in this repository.

## Code map

| Paper section | Code |
|---|---|
| 3.2 Testbed, 3.4 NTN profiles | [`docker/Dockerfile`](docker/Dockerfile), [`modules/testbed.py`](modules/testbed.py), [`config/settings.py`](config/settings.py) |
| 3.3 Cryptographic configurations, Table 2 | [`01_setup.py`](01_setup.py), [`config/settings.py`](config/settings.py) |
| 3.4 Profile validation, Table 4 | [`02_validate_env.py`](02_validate_env.py), [`modules/testbed.py`](modules/testbed.py) |
| 3.5 Timers, byte counters, success checks | [`tools/hsclient.c`](tools/hsclient.c), [`03_benchmark.py`](03_benchmark.py) |
| 3.6 CPU and microbenchmarks | [`03_benchmark.py`](03_benchmark.py), [`modules/testbed.py`](modules/testbed.py), [`tools/hsclient.c`](tools/hsclient.c) |
| 3.7 Statistics, result tables and figures | [`06_analyze.py`](06_analyze.py) |
| 3.8, 4.5 Protocol observations, Table 12 | [`05_security_observations.py`](05_security_observations.py) |
| Packet-capture validation, Table 9 | [`03_benchmark.py`](03_benchmark.py), [`modules/utils.py`](modules/utils.py) |

Script numbers give the pipeline order. There is no `04_` script because its checks are part of `05_security_observations.py`.
