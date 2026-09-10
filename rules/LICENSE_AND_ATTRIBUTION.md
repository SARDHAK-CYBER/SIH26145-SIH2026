# YARA Rules — License & Attribution

The 401 rules in `malware/`, `packers/`, `webshells/`, `maldocs/`, and `exploit_kits/` are sourced from **Yara-Rules/rules** (https://github.com/Yara-Rules/rules), licensed under **GNU GPLv2** (http://www.gnu.org/licenses/gpl-2.0.html).

Per that license, this notice must be retained and distributed alongside these rule files. Individual rule authors are credited in each file's own `meta:` block (e.g., many are authored by Florian Roth / Neo23x0).

**What changed from the upstream repository:**
- Curated to 5 categories relevant to file extraction from HTTP/FTP/SMB traffic (this pipeline never decrypts TLS, so only cleartext-extractable file types matter here)
- 8 rules removed because they depend on a shared YARA module (`is__elf`) not bundled separately, or use a YARA feature (`hash.md5` with `sync` field) incompatible with this project's yara-python version — verified by actually attempting to compile all 409 original candidates; these 8 failed, the remaining 401 compile and load cleanly
- `eicar_test.yar`, `suspicious_pe_packer.yar`, `harmless_pipeline_test.yar` (in `pipeline_test/`) are original to this project, not from Yara-Rules/rules — kept for pipeline smoke-testing, separate from real-world detection coverage

**Verified, not just copied in:**
- All 401 rules confirmed to actually compile via `yara.compile()`
- The full set loads correctly through this project's real `YaraFileScanner` class
- Tested a real (non-EICAR) rule — `asp_file` (Laudanum ASP webshell, by Florian Roth) — against matching content; fired correctly with the rule name in the alert evidence
- Confirmed no false positive against ordinary benign text content
