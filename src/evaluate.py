from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support

from utils import read_jsonl, resolve_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--predictions", default="outputs/predictions.jsonl")
    parser.add_argument("--metrics-out", default="outputs/metrics.json")
    parser.add_argument("--report-out", default="outputs/classification_report.csv")
    parser.add_argument("--confusion-out", default="outputs/confusion_matrix.csv")
    args = parser.parse_args()

    rows = read_jsonl(resolve_path(args.predictions))
    if not rows:
        raise SystemExit("No predictions found")

    y_true = [row["gold_technique_id"] for row in rows]
    y_pred = [row["predicted_technique_id"] for row in rows]
    labels = sorted(set(y_true) | set(y_pred))

    accuracy = accuracy_score(y_true, y_pred)
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )
    weighted_p, weighted_r, weighted_f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="weighted", zero_division=0
    )
    topk_recall = sum(bool(row.get("topk_contains_gold")) for row in rows) / len(rows)

    metrics: Dict[str, Any] = {
        "num_predictions": len(rows),
        "num_gold_classes": len(set(y_true)),
        "num_predicted_classes": len(set(y_pred)),
        "top1_accuracy": accuracy,
        "macro_precision": macro_p,
        "macro_recall": macro_r,
        "macro_f1": macro_f1,
        "weighted_precision": weighted_p,
        "weighted_recall": weighted_r,
        "weighted_f1": weighted_f1,
        "topk_recall": topk_recall,
    }

    metrics_path = resolve_path(args.metrics_out)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    report = classification_report(y_true, y_pred, labels=labels, output_dict=True, zero_division=0)
    report_df = pd.DataFrame(report).transpose()
    report_path = resolve_path(args.report_out)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_df.to_csv(report_path)

    cm = confusion_matrix(y_true, y_pred, labels=labels)
    cm_df = pd.DataFrame(cm, index=[f"gold_{x}" for x in labels], columns=[f"pred_{x}" for x in labels])
    confusion_path = resolve_path(args.confusion_out)
    cm_df.to_csv(confusion_path)

    print(json.dumps(metrics, indent=2))
    print(f"Wrote metrics: {metrics_path}")
    print(f"Wrote classification report: {report_path}")
    print(f"Wrote confusion matrix: {confusion_path}")


if __name__ == "__main__":
    main()
