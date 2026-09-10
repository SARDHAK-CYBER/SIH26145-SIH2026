# JA4 Threat Intel — License & Attribution

`ja4_threat_intel.json` is derived from **FoxIO's official `ja4plus-mapping.csv`** (https://github.com/FoxIO-LLC/ja4), the creators of the JA4+ fingerprinting standard.

**License:** JA4+ (the mapping/database) is licensed under the **FoxIO License 1.1** — permissive for academic and internal business use, but not for monetization/resale without an OEM license from FoxIO. This project's use (a competition/academic detection pipeline) falls within the permitted use. The core JA4 algorithm itself is separately BSD 3-Clause.

**What this is, honestly:** FoxIO's public mapping has only ~66 total entries. This is real, current, authoritative data (not invented) — but it is genuinely small, reflecting that public JA4 threat intelligence is still an early, actively-growing field industry-wide (confirmed via research, not assumed). 19 fingerprints here map to real malware/C2 tools (Cobalt Strike, Sliver, IcedID, Qakbot, Pikabot, Darkgate, Lumma); 5 map to dual-use tools (SoftEther VPN, ngrok) that are legitimate but frequently abused, kept in a separate tier so they don't get blanket-flagged the same way as confirmed malware.

**Verified, not just copied in:** tested against the real Cobalt Strike v4.9.1 and Sliver Agent fingerprints from FoxIO's own data — both fire correctly at CRITICAL severity. Tested SoftEther VPN's real fingerprint — fires at MEDIUM with an explicit dual-use note, not CRITICAL. Tested an unrelated fingerprint — correctly stays silent.

**Growing this further:** `ja4db.com` (FoxIO's live, actively-developed database) has more entries than this static snapshot but isn't set up for bulk offline download — worth periodically re-checking for a larger exportable dataset as that project matures.
