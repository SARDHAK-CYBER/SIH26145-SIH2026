"""
YARA file-scan worker.

Two modes:
  --once DIR    Scan every file currently in DIR once, then exit.
                Matches the batch/offline demo pattern used by
                offline_engine.py -- good for testing without Zeek
                actually running yet.
  --watch DIR   Poll DIR for new files and scan each as it appears.
                Intended to run downstream of wherever Zeek's
                extracted-files directory is shared to (a volume mount,
                not a live network path -- Zeek's capture-zone isolation
                is unaffected by this worker).

In both modes, alerts are written straight to OpenSearch via
OpenSearchStorage, mirroring offline_engine.py, so this can be demoed
independently of the relay/streaming path.
"""
from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

from src.engines.eng08_yara_scan import YaraFileScanner
from src.storage.opensearch_client import OpenSearchStorage

POLL_INTERVAL_SECONDS = 5.0


def scan_directory_once(scanner: YaraFileScanner, storage: OpenSearchStorage, directory: Path) -> int:
    count = 0
    for filepath in directory.iterdir():
        if not filepath.is_file():
            continue
        alert = scanner.scan_file(filepath)
        if alert:
            storage.index_alert(alert)
            print(f"[yara_scan_worker] ALERT: {filepath.name} matched {alert.evidence['matched_rules']}")
        count += 1
    return count


def watch_directory(scanner: YaraFileScanner, storage: OpenSearchStorage, directory: Path) -> None:
    seen: set[str] = set()
    print(f"[yara_scan_worker] watching {directory} (polling every {POLL_INTERVAL_SECONDS}s)")
    while True:
        for filepath in directory.iterdir():
            if not filepath.is_file() or filepath.name in seen:
                continue
            seen.add(filepath.name)
            alert = scanner.scan_file(filepath)
            if alert:
                storage.index_alert(alert)
                print(f"[yara_scan_worker] ALERT: {filepath.name} matched {alert.evidence['matched_rules']}")
        time.sleep(POLL_INTERVAL_SECONDS)


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan Zeek-extracted files with YARA.")
    parser.add_argument("--once", metavar="DIR", help="Scan DIR once and exit (batch mode)")
    parser.add_argument("--watch", metavar="DIR", help="Continuously poll DIR for new files (live mode)")
    parser.add_argument("--rules-dir", default="rules", help="Directory of .yar rule files")
    args = parser.parse_args()

    if not args.once and not args.watch:
        parser.error("Specify either --once DIR or --watch DIR")

    scanner = YaraFileScanner(rules_dir=args.rules_dir)
    storage = OpenSearchStorage(
        host=os.environ.get("OPENSEARCH_HOST", "localhost"),
        port=int(os.environ.get("OPENSEARCH_PORT", "9200")),
    )

    if args.once:
        directory = Path(args.once)
        n = scan_directory_once(scanner, storage, directory)
        print(f"[yara_scan_worker] scanned {n} file(s) in {directory}")
    else:
        watch_directory(scanner, storage, Path(args.watch))


if __name__ == "__main__":
    main()
