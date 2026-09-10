##! extract-files.zeek
##!
##! Enables Zeek's built-in file-extraction framework. Zeek only extracts
##! file content for protocols it actually parses in the clear -- HTTP,
##! FTP, SMB, and similar. It never decrypts TLS/QUIC, so nothing that
##! was ever encrypted on the wire reaches this extraction directory.
##! That's what keeps this feature inside the "no payload decryption"
##! architectural constraint: it's a property of what Zeek can physically
##! see, not a policy this script has to enforce.
##!
##! CAVEAT: this uses the standard, widely-documented two-line idiom for
##! Zeek's extract-all-files framework. Zeek's own scripting language and
##! its exact variable names have shifted slightly across versions --
##! verify `FileExtraction::prefix` against your Zeek 6.0.3 docs
##! (`zeek -N Zeek::FileExtract` or the local script docs) before relying
##! on this in a demo. File-size capping is deliberately NOT done here in
##! Zeek script; it's enforced on the Python side in eng08_yara_scan.py's
##! max_scan_bytes check instead, since that's a mechanism I can vouch
##! for with full confidence.

@load frameworks/files/extract-all-files
redef FileExtraction::prefix = "extracted_files/";
