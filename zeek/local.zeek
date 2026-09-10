# StealthTap capture-node Zeek policy.
# JSON logs are easier for the Faust ingest side to parse than Zeek's
# default TSV log format.

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/quic

redef LogAscii::use_json = T;

# JA3/JA4 fingerprinting is NOT in base Zeek -- install the zeek-ja4
# package via zkg (Zeek's package manager) before this @load will work:
#   zkg install zeek/mitre-attack/ja4
@load ja4
