# PQC-NTN testbed image.
# Base pinned by digest: OpenSSL 3.6.0 + oqsprovider 0.11.0 (liboqs 0.15.0).
# The digest is also recorded in config/settings.py (OQS_IMAGE) and in every run manifest.
ARG OQS_IMAGE
FROM ${OQS_IMAGE}

# tc (netem), GNU coreutils, iputils ping (sub-second intervals), iperf3 (bandwidth
# validation), tcpdump (pcaps), compiler for the measurement client.
RUN apk add --no-cache iproute2-tc coreutils iputils iperf3 tcpdump build-base

COPY tools/hsclient.c /src/hsclient.c
RUN gcc -O2 -Wall -o /usr/local/bin/hsclient /src/hsclient.c \
        -I/opt/openssl/include -L/opt/openssl/lib64 -Wl,-rpath,/opt/openssl/lib64 \
        -lssl -lcrypto -lpthread
