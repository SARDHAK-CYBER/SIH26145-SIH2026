# suricata-batch: real Suricata (7.0.3 via apt) + 20,829 verified
# Emerging Threats Open rules, for signature-based network detection
# on uploaded pcaps. Same job-queue pattern as zeek-batch -- separate
# service, no Docker socket access needed, shared incoming/outgoing
# volumes are the only interface with the api container.
#
# HONEST NOTE on the ruleset: sourced from a real but ~2021 mirror of
# ET Open (github.com/vncloudsco/suricata-rules), not a live pull from
# the canonical rules.emergingthreats.net (not reachable from this
# build environment). 20,829 of 20,845 rules confirmed load cleanly;
# 16 rules with genuinely outdated syntax were removed rather than
# patched. Real, working detection -- verified against constructed
# test traffic matching a real rule (ET MALWARE dlink router access
# attempt) -- but not the freshest possible threat intel. Worth
# re-pulling from the official source once you have direct network
# access, via `suricata-update`.

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        suricata ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY rules /rules
COPY suricata.yaml /suricata.yaml
COPY watch_and_process_suricata.sh /watch_and_process_suricata.sh
RUN chmod +x /watch_and_process_suricata.sh

ENTRYPOINT ["/watch_and_process_suricata.sh"]
