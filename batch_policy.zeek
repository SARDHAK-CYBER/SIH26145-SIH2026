##! batch_policy.zeek
##!
##! Policy script for the zeek-batch service (uploaded-pcap analysis).
##! Deliberately self-contained rather than depending on the existing
##! zeek/local.zeek (used for live capture) -- I don't have verified
##! byte-for-byte content of that file, so this avoids silently
##! conflicting with whatever it actually contains. Both scripts should
##! produce compatible JSON output shapes; if your live local.zeek
##! diverges from this, reconcile them by hand.
##!
##! HONEST CAVEAT: I could not install Zeek in my own sandbox to run
##! this end-to-end (disk/network constraints) -- this is written
##! correctly per Zeek 6.x / ICSNPP documentation conventions, but you
##! are the first to actually execute it. If a plugin fails to load,
##! the exact error will tell us which line to fix.

# JSON output, matching what offline_engine.py / pcap_analysis.py's
# Zeek-log parsing already expects.
redef LogAscii::use_json = T;

# ICSNPP protocol analyzers for OT traffic -- same six packages
# installed in zeek-batch.Dockerfile. Base protocols (conn, dns, ssl)
# load automatically unless Zeek is run in bare mode (-b), which this
# service never does.
@load icsnpp-modbus
@load icsnpp-s7comm
@load icsnpp-enip
@load icsnpp-dnp3
@load icsnpp-opcua-binary
@load icsnpp-profinet-io-cm

# BZAR (mitre-attack/bzar) -- real, MITRE-authored SMB/DCE-RPC lateral
# movement detection. Writes to notice.log, parsed by eng12_bzar_notices.py.
# Kerberos logging (kerberos.log) needs no @load here -- it's a Zeek
# BASE script (base/protocols/krb/main.zeek), already producing output
# automatically, same as http.log always was.
@load bzar

# JA4/JA4S TLS client fingerprinting -> populates ssl.log's `ja4` field
# for ENG-04. Loaded only if the plugin actually installed
# (zeek-batch.Dockerfile writes this file on success); otherwise skipped
# so protocol parsing still works. ENG-04 also runs on the live path via
# src/capture/ja4.py regardless.
@load ./batch_policy_ja4

# Cleartext-only file extraction (HTTP, FTP, SMB, etc.) -- Zeek never
# decrypts TLS/QUIC, so nothing extracted here was ever encrypted on the
# wire. This is what feeds YARA scanning downstream.
#
# CORRECTED, confirmed via the real error on first actual run: the
# module is FileExtract (singular "Extract"), not FileExtraction -- my
# original name was simply wrong. It's also a BASE script
# (base/files/extract/main.zeek), meaning Zeek loads it automatically;
# only the extract-all-files POLICY script needs an explicit @load, and
# that path needed a policy/ prefix I'd also left out.
@load policy/frameworks/files/extract-all-files
redef FileExtract::prefix = "extracted_files/";