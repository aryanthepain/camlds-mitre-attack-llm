"""Download and parse MITRE ATT&CK Enterprise STIX into technique documents."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from tqdm import tqdm

from utils import clean_text, resolve_path, write_jsonl

DEFAULT_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


def download_if_needed(url: str, path: Path) -> None:
    if path.exists() and path.stat().st_size > 1000000:
        print(f"Using existing STIX file: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading MITRE ATT&CK STIX JSON from {url}")
    with requests.get(url, stream=True, timeout=120) as r:
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0))
        with open(path, "wb") as f, tqdm(total=total, unit="B", unit_scale=True, desc="MITRE STIX") as bar:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)
                    bar.update(len(chunk))


def external_id(obj: Dict[str, Any]) -> Optional[str]:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def external_url(obj: Dict[str, Any]) -> str:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("url"):
            return ref["url"]
    return ""


def tactic_names(obj: Dict[str, Any]) -> List[str]:
    phases = obj.get("kill_chain_phases", []) or []
    return sorted({phase.get("phase_name", "") for phase in phases if phase.get("kill_chain_name") == "mitre-attack"})


def make_doc(obj: Dict[str, Any]) -> Dict[str, Any] | None:
    tid = external_id(obj)
    if not tid or not tid.startswith("T"):
        return None
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return None

    name = clean_text(obj.get("name", ""))
    description = clean_text(obj.get("description", ""))
    detection = clean_text(obj.get("x_mitre_detection", ""))
    platforms = obj.get("x_mitre_platforms", []) or []
    data_sources = obj.get("x_mitre_data_sources", []) or []
    tactics = tactic_names(obj)
    is_subtechnique = bool(obj.get("x_mitre_is_subtechnique"))

    text = " | ".join(
        [
            f"MITRE ATT&CK technique id: {tid}",
            f"name: {name}",
            f"tactics: {', '.join(tactics)}",
            f"platforms: {', '.join(platforms)}",
            f"data sources: {', '.join(data_sources)}",
            f"description: {description}",
            f"detection guidance: {detection}",
        ]
    )

    return {
        "technique_id": tid,
        "name": name,
        "tactics": tactics,
        "platforms": platforms,
        "data_sources": data_sources,
        "description": description,
        "detection": detection,
        "url": external_url(obj),
        "is_subtechnique": is_subtechnique,
        "text": text,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stix-url", default=DEFAULT_STIX_URL)
    parser.add_argument("--stix-json", default="data/mitre/enterprise-attack.json")
    parser.add_argument("--out-jsonl", default="data/mitre/enterprise_techniques.jsonl")
    parser.add_argument("--lookup-json", default="data/mitre/technique_lookup.json")
    args = parser.parse_args()

    stix_path = resolve_path(args.stix_json)
    download_if_needed(args.stix_url, stix_path)

    with open(stix_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    docs: List[Dict[str, Any]] = []
    for obj in bundle.get("objects", []) or []:
        if obj.get("type") == "attack-pattern":
            doc = make_doc(obj)
            if doc is not None:
                docs.append(doc)

    docs = sorted(docs, key=lambda x: x["technique_id"])
    write_jsonl(docs, resolve_path(args.out_jsonl))

    lookup = {doc["technique_id"]: doc for doc in docs}
    lookup_path = resolve_path(args.lookup_json)
    lookup_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lookup_path, "w", encoding="utf-8") as f:
        json.dump(lookup, f, indent=2, ensure_ascii=False)

    print(f"Wrote {len(docs)} MITRE techniques/sub-techniques to {resolve_path(args.out_jsonl)}")
    print(f"Wrote lookup to {lookup_path}")


if __name__ == "__main__":
    main()
