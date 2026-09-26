# syntax=docker/dockerfile:1
#
# Two stages so the runtime image carries the native Rust core
# (stealthtap_core) without carrying a Rust toolchain.
#
# Why this matters (measured, not assumed): the previous single-stage image
# had NO native module, so every Docker-path analysis ran the pure-Python
# engines against Redis (~1.1ms round-trip per flow, per engine) -- on the
# API event loop. That is what made one 93MB upload (564k flows) freeze the
# whole API. With the native module the same engines run in-process, in
# Rust, with no Redis round-trips (ENG-01 alone: 633k flows/sec vs ~900).

FROM python:3.11-slim AS native-build

# Opt-in: `docker build --build-arg NATIVE_FEATURES=afxdp .` also compiles the
# Linux AF_XDP capture backend (needs autotools/flex/bison for the vendored
# libbpf/elfutils build). Off by default -- this image never captures.
ARG NATIVE_FEATURES=""

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential curl ca-certificates \
    && if [ -n "$NATIVE_FEATURES" ]; then \
         apt-get install -y --no-install-recommends pkg-config autoconf automake libtool autopoint flex bison gawk make; \
       fi \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain stable \
    && pip install --no-cache-dir maturin

WORKDIR /src/stealthtap_core
COPY native/stealthtap_core/Cargo.toml native/stealthtap_core/Cargo.lock ./
COPY native/stealthtap_core/src ./src
RUN maturin build --release --compatibility off \
      ${NATIVE_FEATURES:+--features $NATIVE_FEATURES} -o /wheels


FROM python:3.11-slim

WORKDIR /opt/stealthtap

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 120 --retries 5 -r requirements.txt

COPY --from=native-build /wheels /tmp/wheels
RUN pip install --no-cache-dir /tmp/wheels/*.whl && rm -rf /tmp/wheels \
    && python -c "import stealthtap_core as c; assert hasattr(c, 'LiveFlowAssembler') and hasattr(c, 'NativeEng01'); print('stealthtap_core OK')"

COPY . .

# Default entrypoint; each service in docker-compose.yml overrides this
# (api -> uvicorn, streaming-engine -> faust, log-shipper -> log_shipper).
ENTRYPOINT ["python", "-m", "src.offline_engine"]
