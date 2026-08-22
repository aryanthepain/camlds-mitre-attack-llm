from __future__ import annotations

import argparse
import json
from pathlib import Path

from utils import resolve_path


def pct(x: float) -> str:
    return f"{100*x:.2f}%"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metrics", default="outputs/metrics.json")
    parser.add_argument("--report-template", default="report/project_report_template.md")
    parser.add_argument("--out", default="report/final_report_filled.md")
    args = parser.parse_args()

    with open(resolve_path(args.metrics), "r", encoding="utf-8") as f:
        metrics = json.load(f)

    with open(resolve_path(args.report_template), "r", encoding="utf-8") as f:
        template = f.read()

    summary = f"""
## Results Summary Filled From Run

- Number of evaluated alerts: {metrics.get('num_predictions')}
- Number of gold MITRE classes: {metrics.get('num_gold_classes')}
- Top-1 accuracy: {pct(metrics.get('top1_accuracy', 0))}
- Macro precision: {pct(metrics.get('macro_precision', 0))}
- Macro recall: {pct(metrics.get('macro_recall', 0))}
- Macro F1: {pct(metrics.get('macro_f1', 0))}
- Weighted precision: {pct(metrics.get('weighted_precision', 0))}
- Weighted recall: {pct(metrics.get('weighted_recall', 0))}
- Weighted F1: {pct(metrics.get('weighted_f1', 0))}
- Top-k recall: {pct(metrics.get('topk_recall', 0))}

Interpretation placeholder: Replace this paragraph after manual inspection of the confusion matrix and sample predictions. Top-k recall measures whether the correct MITRE technique appeared among the retrieved candidate set. If top-k recall is much higher than top-1 accuracy, the retriever is finding useful candidates but the final ranking/LLM decision step needs improvement.
""".strip()

    filled = template.replace("<!-- RESULTS_SUMMARY_PLACEHOLDER -->", summary)
    out_path = resolve_path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(filled)

    print(f"Wrote filled report: {out_path}")


if __name__ == "__main__":
    main()
