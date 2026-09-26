# stealthtap-sensor: the LIVE tap.
#
# Deployed on the monitoring host that sees the mirror/tap traffic. It
# captures a NIC at kernel level (AF_PACKET mmap ring + FANOUT + in-kernel
# BPF), assembles flows in-process, runs the SAME ENG01-13 engines + ONNX
# models as the PCAP-upload path, and POSTs alerts to the API's shared
# PostgreSQL store (STEALTHTAP_API_URL/alerts/ingest).
#
# Stealth posture (enforced by the `sensor` service in docker-compose.yml):
#   * network_mode: host  + cap_drop: ALL + cap_add: NET_RAW, NET_ADMIN only
#   * NO published ports  (the control/SSE API binds to 127.0.0.1 only)
#   * read_only root fs, no-new-privileges
#   * the capture NIC carries no IP (see scripts/setup_netns.sh / the
#     deployment doc) -- nothing routable, no return path.

# --- stage 1: native Rust core (same wheel as the API image; see Dockerfile) ---
FROM python:3.11-slim AS native-build
# `--build-arg NATIVE_FEATURES=afxdp` adds the Linux AF_XDP capture backend
# (needs the NIC driver to support XDP and CAP_BPF at runtime; the sensor's
# compose service drops all caps except NET_RAW/NET_ADMIN, so AF_PACKET remains
# the default and AF_XDP is opt-in for hosts that grant it).
ARG NATIVE_FEATURES=""
RUN apt-get update && apt-get install -y --no-install-recommends build-essential curl ca-certificates     && if [ -n "$NATIVE_FEATURES" ]; then          apt-get install -y --no-install-recommends pkg-config autoconf automake libtool autopoint flex bison gawk make;        fi     && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable     && pip install --no-cache-dir maturin
WORKDIR /src/stealthtap_core
COPY native/stealthtap_core/Cargo.toml native/stealthtap_core/Cargo.lock ./
COPY native/stealthtap_core/src ./src
RUN maturin build --release --compatibility off ${NATIVE_FEATURES:+--features $NATIVE_FEATURES} -o /wheels

# --- stage 2: runtime ---
FROM python:3.11-slim

WORKDIR /opt/stealthtap

# libpcap for scapy's kernel capture path; tcpdump handy for on-box debug.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libpcap0.8 tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 120 --retries 5 -r requirements.txt
COPY --from=native-build /wheels /tmp/wheels
RUN pip install --no-cache-dir /tmp/wheels/*.whl && rm -rf /tmp/wheels
COPY . .

ENV SCAPY_USE_PCAPDNET=1 \
    LIVE_SNAPSHOT_INTERVAL=2.0 \
    LIVE_ALERT_COOLDOWN=30

# `serve` exposes the control + SSE API (bound to 127.0.0.1 by the
# compose service) so the dashboard can pick the interface and start/stop.
ENTRYPOINT ["python", "-m", "src.capture.live_agent"]
CMD ["serve", "--host", "127.0.0.1", "--port", "8100"]
