"""Download CAM-LDS files from Zenodo.

Default target: manifestations_raw.zip because Suricata eve.json network alerts
are present in the raw manifestations archive.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import requests
from tqdm import tqdm

ZENODO_RECORD_API = "https://zenodo.org/api/records/18861762"


def download_file(url: str, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with requests.get(url, stream=True, timeout=60) as r:
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0))
        with open(out_path, "wb") as f, tqdm(
            total=total,
            unit="B",
            unit_scale=True,
            desc=f"Downloading {out_path.name}",
        ) as bar:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)
                    bar.update(len(chunk))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", default="manifestations_raw.zip", help="Zenodo file name to download")
    parser.add_argument("--out-dir", default="data/raw", help="Directory to save the file")
    args = parser.parse_args()

    response = requests.get(ZENODO_RECORD_API, timeout=60)
    response.raise_for_status()
    record = response.json()

    files = record.get("files", [])
    match = None
    for item in files:
        if item.get("key") == args.file:
            match = item
            break

    if match is None:
        available = [item.get("key") for item in files]
        raise SystemExit(f"Could not find {args.file}. Available files: {available}")

    # Zenodo API gives a direct self link for file content.
    url = match["links"]["self"]
    out_path = Path(args.out_dir) / args.file
    download_file(url, out_path)
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    main()
