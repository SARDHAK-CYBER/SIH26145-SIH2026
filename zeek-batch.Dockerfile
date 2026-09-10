# zeek-batch: a SEPARATE image from your existing zeek/Dockerfile
# (used for live capture). This one is purpose-built for batch-processing
# uploaded pcaps -- no capture-namespace isolation needed here, since it
# never touches a live interface, only files it's handed.
#
# HONEST NOTE: I don't have verified byte-for-byte content of your
# existing zeek/Dockerfile (I reviewed it early in this project but
# never re-extracted its literal content since). Rather than guess and
# risk silently diverging from your real live-capture image, this is a
# clean, independent build using the same base and the same four ICSNPP
# packages already confirmed present in your setup.

FROM zeek/zeek:6.0.3

# HYPOTHESIS, based on the real failure pattern from the first build
# attempt: icsnpp-modbus and icsnpp-dnp3 (pure Zeek-script packages, no
# compilation needed) installed fine, while icsnpp-s7comm, icsnpp-enip,
# icsnpp-opcua-binary, and icsnpp-profinet-io-cm (all Spicy-based,
# compiled from source) failed at "package build_command failed" --
# consistent with this base image shipping the Spicy *runtime* but not
# the full build toolchain needed to compile a NEW Spicy analyzer via
# zkg. Installing that toolchain explicitly, before touching zkg at all.
# CONFIRMED via the actual CMake error on the previous build attempt
# (not a guess this time): "Could NOT find OpenSSL" -- libssl-dev was
# the one missing piece. cmake/build-essential/bison/flex/libpcap-dev
# already correctly fixed icsnpp-profinet-io-cm; this should get the
# remaining three (enip, opcua-binary, s7comm) past the same wall.
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake build-essential bison flex libpcap-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN zkg autoconfig --force || true

# If this still fails even with the toolchain above, print every
# package's actual build log before failing -- so the real compiler
# error is visible in `docker compose build` output instead of a bare
# "build_command failed" with no detail, which is what we had before.
RUN zkg install --force --skiptests \
        icsnpp-modbus icsnpp-s7comm icsnpp-enip icsnpp-dnp3 \
        icsnpp-opcua-binary icsnpp-profinet-io-cm \
        bzar \
    || (echo "=== zkg build logs (real error is below) ===" && \
        cat /usr/local/zeek/var/lib/zkg/logs/*-build.log 2>/dev/null && \
        exit 1)

# JA4/JA4S TLS fingerprinting for ssl.log (feeds ENG-04 on the upload
# path). Non-fatal: the exact zkg source for FoxIO's Zeek plugin varies
# by mirror, so a failure here must NOT break protocol parsing. ENG-04
# already works on the LIVE-capture path via src/capture/ja4.py (a real,
# spec-compliant JA4 computed from the ClientHello). Set JA4_ZKG_SOURCE
# to your reachable source (e.g. a git URL) to enable it here too.
ARG JA4_ZKG_SOURCE=zeek/ja4
RUN touch /batch_policy_ja4.zeek && \
    ( zkg install --force --skiptests "$JA4_ZKG_SOURCE" \
      && echo "@load ja4" > /batch_policy_ja4.zeek \
      && echo "[zeek-batch] JA4 plugin installed from $JA4_ZKG_SOURCE" ) \
    || echo "[zeek-batch] JA4 plugin NOT installed ($JA4_ZKG_SOURCE) -- ENG-04 upload-path JA4 disabled; live path unaffected"

WORKDIR /zeek-batch
COPY batch_policy.zeek /batch_policy.zeek
COPY watch_and_process.sh /watch_and_process.sh
RUN chmod +x /watch_and_process.sh

ENTRYPOINT ["/watch_and_process.sh"]