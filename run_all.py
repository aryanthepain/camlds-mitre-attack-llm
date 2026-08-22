"""Convenience runner for the full project pipeline.

Usage examples:
  python run_all.py --download
  python run_all.py --raw-zip data/raw/manifestations_raw.zip --llm none
  python run_all.py --raw-zip data/raw/manifestations_raw.zip --llm ollama
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(cmd: list[str]) -> None:
    print("\n$ " + " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--download", action="store_true", help="Download manifestations_raw.zip first")
    parser.add_argument("--raw-zip", default="data/raw/manifestations_raw.zip")
    parser.add_argument("--max-per-technique", type=int, default=300)
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--llm", choices=["none", "ollama"], default="none")
    parser.add_argument("--ollama-model", default="qwen2.5:7b-instruct")
    args = parser.parse_args()

    py = sys.executable

    if args.download:
        run([py, "src/download_camlds.py", "--file", "manifestations_raw.zip", "--out-dir", "data/raw"])

    run([
        py,
        "src/prepare_dataset.py",
        "--raw-zip",
        args.raw_zip,
        "--out",
        "data/processed/suricata_alerts.jsonl",
        "--max-per-technique",
        str(args.max_per_technique),
    ])
    run([
        py,
        "src/split_dataset.py",
        "--input",
        "data/processed/suricata_alerts.jsonl",
        "--train-out",
        "data/processed/train.jsonl",
        "--test-out",
        "data/processed/test.jsonl",
        "--test-size",
        str(args.test_size),
    ])
    run([
        py,
        "src/build_mitre_kb.py",
        "--out-jsonl",
        "data/mitre/enterprise_techniques.jsonl",
        "--lookup-json",
        "data/mitre/technique_lookup.json",
    ])
    run([
        py,
        "src/build_vector_db.py",
        "--techniques",
        "data/mitre/enterprise_techniques.jsonl",
        "--db-dir",
        "data/vector_db/chroma_mitre",
        "--collection",
        "mitre_enterprise_techniques",
    ])
    cmd = [
        py,
        "src/predict_rag.py",
        "--input",
        "data/processed/test.jsonl",
        "--output",
        "outputs/predictions.jsonl",
        "--db-dir",
        "data/vector_db/chroma_mitre",
        "--collection",
        "mitre_enterprise_techniques",
        "--llm",
        args.llm,
        "--top-k",
        str(args.top_k),
    ]
    if args.llm == "ollama":
        cmd.extend(["--ollama-model", args.ollama_model])
    run(cmd)
    run([
        py,
        "src/evaluate.py",
        "--predictions",
        "outputs/predictions.jsonl",
        "--metrics-out",
        "outputs/metrics.json",
        "--report-out",
        "outputs/classification_report.csv",
        "--confusion-out",
        "outputs/confusion_matrix.csv",
    ])
    run([
        py,
        "src/make_result_summary.py",
        "--metrics",
        "outputs/metrics.json",
        "--report-template",
        "report/project_report_template.md",
        "--out",
        "report/final_report_filled.md",
    ])


if __name__ == "__main__":
    main()
