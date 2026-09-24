from __future__ import annotations
import hashlib
import time
from pathlib import Path
from typing import Optional

import yara

from src.alert_schema import Alert, FlowIdentifier, MitreAttack

DEFAULT_MAX_SCAN_BYTES = 50 * 1024 * 1024  # 50MB

# Magic-byte signatures for the file categories this project's own YARA
# rule set targets (rules/{malware,packers,maldocs,exploit_kits,webshells}/)
# -- content-sniffed, not guessed from a filename, since Zeek's file
# extraction names files generically (extract-<ts>-<uid>, no extension).
# Answers "what kind of data was transferred", not just its size. No new
# dependency: python-magic needs the libmagic C library, a real Windows
# portability cost for a handful of well-known, stable signatures.
_MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"MZ", "pe_executable"),                    # Windows PE (.exe/.dll)
    (b"\x7fELF", "elf_executable"),               # Linux ELF
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip_or_office_ooxml"),       # .zip, .docx/.xlsx/.pptx, .jar
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole_legacy_office"),  # .doc/.xls/.ppt
    (b"\x1f\x8b", "gzip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"#!", "script_shebang"),
]


def sniff_file_type(header: bytes) -> str:
    for magic, label in _MAGIC_SIGNATURES:
        if header.startswith(magic):
            return label
    return "unknown"


class YaraFileScanner:
    """
    Scans files extracted by Zeek's file-analysis framework against a
    directory of YARA rules.

    Scope note: Zeek can only extract files it actually parsed the content
    of -- HTTP, FTP, SMB, and similar cleartext transfers. It cannot see
    inside TLS/QUIC sessions without decrypting them, and this scanner
    never asks it to. That keeps file scanning inside the "no payload
    decryption" architectural constraint by construction, not by policy:
    there is no code path here that touches encrypted content, because
    encrypted content never reaches this directory in the first place.
    """

    name = "ENG-08-YARA"

    def __init__(self, rules_dir: str = "rules", max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES):
        # rglob, not glob: rules are organized into category subfolders
        # (malware/, packers/, webshells/, maldocs/, exploit_kits/) --
        # non-recursive glob() would silently find zero files in those,
        # which is exactly what happened when this was first tested
        # against the real curated rule set.
        rule_files = {p.stem: str(p) for p in Path(rules_dir).rglob("*.yar")}
        if not rule_files:
            raise FileNotFoundError(f"No .yar rule files found in {rules_dir} (searched recursively)")
        self.rules = yara.compile(filepaths=rule_files)
        self.max_scan_bytes = max_scan_bytes

    def scan_file(self, filepath: Path, flow_context: Optional[dict] = None) -> Optional[Alert]:
        if not filepath.is_file():
            return None

        size = filepath.stat().st_size
        if size > self.max_scan_bytes:
            print(f"[eng08] skipping {filepath.name}: {size} bytes exceeds {self.max_scan_bytes} byte cap")
            return None

        try:
            matches = self.rules.match(str(filepath))
        except yara.Error as exc:
            print(f"[eng08] YARA error scanning {filepath}: {exc}")
            return None

        if not matches:
            return None

        file_hash = self._sha256(filepath)
        flow_context = flow_context or {}
        matched_rules = [m.rule for m in matches]
        with open(filepath, "rb") as f:
            file_type = sniff_file_type(f.read(8))

        return Alert(
            alert_id=f"yara_{file_hash[:12]}",
            timestamp=time.time(),
            severity="CRITICAL",
            confidence_score=90.0,
            threat_class="MALICIOUS_FILE_DETECTED",
            flow_identifier=FlowIdentifier(
                src_ip=flow_context.get("src_ip", "0.0.0.0"),
                src_port=flow_context.get("src_port", 0),
                dst_ip=flow_context.get("dst_ip", "0.0.0.0"),
                dst_port=flow_context.get("dst_port", 0),
                protocol=flow_context.get("proto", "TCP"),
            ),
            mitre_attack=MitreAttack(
                tactic="Command and Control",
                technique_id="T1105",
                technique_name="Ingress Tool Transfer",
            ),
            evidence={
                "filename": filepath.name,
                "file_type": file_type,
                "matched_rules": matched_rules,
                "file_size_bytes": size,
            },
            # Unlike the other engines' placeholder segment_hash, this one
            # is a real computed SHA-256 of the actual file -- a genuine
            # chain-of-custody artifact, not a stub.
            forensics={"raw_segment_hash_sha256": file_hash},
        )

    @staticmethod
    def _sha256(filepath: Path) -> str:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()