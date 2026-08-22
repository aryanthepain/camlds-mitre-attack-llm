"""Prepare a clean Suricata-alert dataset from CAM-LDS raw manifestations.

Expected input options:
1. --raw-zip data/raw/manifestations_raw.zip
2. --raw-dir path/to/extracted/manifestations_raw

The script searches recursively for eve.json / eve.jsonl files, keeps only
Suricata alert events, and derives the MITRE ATT&CK ground-truth technique ID
from the directory path, especially paths under manifestations_raw/techniques/Txxxx.
"""

from __future__ import annotations

import argparse
import json
import re
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tqdm import tqdm

from utils import clean_text, compact_json, resolve_path, stable_hash, write_jsonl

TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def extract_zip_if_needed(raw_zip: Path, extract_dir: Path) -> Path:
    if extract_dir.exists() and any(extract_dir.rglob("eve.json*")):
        return extract_dir
    extract_dir.mkdir(parents=True, exist_ok=True)
    print(f"Extracting {raw_zip} to {extract_dir} ...")
    with zipfile.ZipFile(raw_zip, "r") as zf:
        zf.extractall(extract_dir)
    return extract_dir


def find_eve_files(root: Path) -> List[Path]:
    files: List[Path] = []
    for pattern in ["**/eve.json", "**/eve.jsonl", "**/*eve*.json", "**/*eve*.jsonl"]:
        files.extend(root.glob(pattern))
    # Deduplicate while preserving order.
    seen = set()
    unique: List[Path] = []
    for f in files:
        if f.is_file() and f not in seen:
            seen.add(f)
            unique.append(f)
    return unique


def extract_technique_id(path: Path) -> Optional[str]:
    text = str(path)
    matches = TECHNIQUE_RE.findall(text)
    if not matches:
        return None
    # Usually the technique folder is the last T-code in the path.
    return matches[-1]


def alert_to_text(event: Dict[str, Any]) -> str:
    alert = event.get("alert", {}) or {}
    flow = event.get("flow", {}) or {}
    http = event.get("http", {}) or {}
    dns = event.get("dns", {}) or {}
    tls = event.get("tls", {}) or {}
    fileinfo = event.get("fileinfo", {}) or {}

    parts = [
        f"suricata alert signature: {clean_text(alert.get('signature'))}",
        f"category: {clean_text(alert.get('category'))}",
        f"severity: {clean_text(alert.get('severity'))}",
        f"signature id: {clean_text(alert.get('signature_id'))}",
        f"protocol: {clean_text(event.get('proto'))}",
        f"application protocol: {clean_text(event.get('app_proto'))}",
        f"source port: {clean_text(event.get('src_port'))}",
        f"destination port: {clean_text(event.get('dest_port'))}",
        f"flow state: {clean_text(flow.get('state'))}",
        f"flow reason: {clean_text(flow.get('reason'))}",
        f"http hostname: {clean_text(http.get('hostname'))}",
        f"http url: {clean_text(http.get('url'))}",
        f"http method: {clean_text(http.get('http_method'))}",
        f"http user agent: {clean_text(http.get('http_user_agent'))}",
        f"dns query: {clean_text(dns.get('rrname'))}",
        f"dns type: {clean_text(dns.get('rrtype'))}",
        f"tls sni: {clean_text(tls.get('sni'))}",
        f"file name: {clean_text(fileinfo.get('filename'))}",
        f"metadata: {compact_json(alert.get('metadata', {}), max_chars=800)}",
    ]
    return " | ".join([p for p in parts if p and not p.endswith(": ")])


def parse_eve_file(path: Path, root: Path) -> Iterable[Dict[str, Any]]:
    technique_id = extract_technique_id(path)
    if technique_id is None:
        return

    rel_path = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            alert = event.get("alert", {}) or {}
            text = alert_to_text(event)
            row_key = f"{rel_path}:{line_no}:{text}:{technique_id}"
            yield {
                "alert_id": stable_hash(row_key),
                "source_file": rel_path,
                "source_line": line_no,
                "timestamp": event.get("timestamp", ""),
                "gold_technique_id": technique_id,
                "alert_signature": clean_text(alert.get("signature")),
                "alert_category": clean_text(alert.get("category")),
                "alert_severity": alert.get("severity", ""),
                "signature_id": alert.get("signature_id", ""),
                "proto": event.get("proto", ""),
                "app_proto": event.get("app_proto", ""),
                "src_port": event.get("src_port", ""),
                "dest_port": event.get("dest_port", ""),
                "text": text,
                "raw_event_compact": compact_json(event, max_chars=2500),
            }


def cap_per_technique(rows: Iterable[Dict[str, Any]], max_per_technique: int) -> List[Dict[str, Any]]:
    if max_per_technique <= 0:
        return list(rows)
    counts: Dict[str, int] = defaultdict(int)
    capped: List[Dict[str, Any]] = []
    for row in rows:
        tid = row["gold_technique_id"]
        if counts[tid] < max_per_technique:
            capped.append(row)
            counts[tid] += 1
    return capped


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-zip", default="", help="Path to manifestations_raw.zip")
    parser.add_argument("--raw-dir", default="", help="Path to extracted CAM-LDS raw manifestations")
    parser.add_argument("--out", default="data/processed/suricata_alerts.jsonl")
    parser.add_argument("--max-per-technique", type=int, default=300, help="0 means no cap")
    args = parser.parse_args()

    if args.raw_dir:
        root = resolve_path(args.raw_dir)
    elif args.raw_zip:
        raw_zip = resolve_path(args.raw_zip)
        if not raw_zip.exists():
            raise SystemExit(f"Raw zip not found: {raw_zip}")
        root = raw_zip.parent / raw_zip.stem
        root = extract_zip_if_needed(raw_zip, root)
    else:
        raise SystemExit("Provide --raw-zip or --raw-dir")

    eve_files = find_eve_files(root)
    if not eve_files:
        raise SystemExit(f"No eve.json files found under {root}")

    print(f"Found {len(eve_files)} eve files")
    rows: List[Dict[str, Any]] = []
    skipped_no_label = 0
    for f in tqdm(eve_files, desc="Parsing eve files"):
        if extract_technique_id(f) is None:
            skipped_no_label += 1
            continue
        rows.extend(parse_eve_file(f, root) or [])

    rows = cap_per_technique(rows, args.max_per_technique)
    out_path = resolve_path(args.out)
    write_jsonl(rows, out_path)

    counts = Counter(row["gold_technique_id"] for row in rows)
    print(f"Wrote {len(rows)} alert rows to {out_path}")
    print(f"Distinct technique labels: {len(counts)}")
    print(f"Skipped eve files without T-code in path: {skipped_no_label}")
    print("Top labels:")
    for tid, count in counts.most_common(15):
        print(f"  {tid}: {count}")


if __name__ == "__main__":
    main()
