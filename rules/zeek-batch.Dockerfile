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

WORKDIR /zeek-batch
COPY batch_policy.zeek /batch_policy.zeek
COPY watch_and_process.sh /watch_and_process.sh
RUN chmod +x /watch_and_process.sh

ENTRYPOINT ["/watch_and_process.sh"]
