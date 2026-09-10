#!/usr/bin/env bash
set -euo pipefail

# Do NOT hand-write a seccomp allowlist for Zeek from memory or a
# generic template -- guessing wrong either breaks capture or leaves
# an unnecessary syscall reachable. Derive it empirically instead,
# against the FULL tests/harness.sh traffic suite (all six engines'
# generators), so rarely-hit analyzer code paths aren't missing a
# syscall they need.

CONTAINER=${1:-stealthtap-zeek}

cat <<EOF
[*] Step 1 -- run the container unconfined, under strace, while the
    full harness traffic is replayed against it:

    docker run --rm --security-opt seccomp=unconfined --cap-drop=ALL \\
      --cap-add=NET_RAW --cap-add=NET_ADMIN --name ${CONTAINER} \\
      --entrypoint strace ${CONTAINER} \\
      -f -c -o /tmp/syscalls.log zeek -i af_packet::eth1 local

[*] Step 2 -- with tests/harness.sh run to completion against it, pull
    the syscall list out:

    docker cp ${CONTAINER}:/tmp/syscalls.log .
    awk '{print \$NF}' syscalls.log | sort -u

[*] Step 3 -- start from Docker's default seccomp profile and trim it
    down to that observed syscall list, not the other way around.
    Re-run the full harness against the trimmed profile before trusting
    it for anything beyond local dev.
EOF
