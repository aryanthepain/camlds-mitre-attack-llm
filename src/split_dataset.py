from __future__ import annotations

import argparse
from collections import Counter
from typing import Dict, List

from sklearn.model_selection import train_test_split

from utils import read_jsonl, resolve_path, set_seed, write_jsonl


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/processed/suricata_alerts.jsonl")
    parser.add_argument("--train-out", default="data/processed/train.jsonl")
    parser.add_argument("--test-out", default="data/processed/test.jsonl")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    set_seed(args.seed)
    rows = read_jsonl(resolve_path(args.input))
    if not rows:
        raise SystemExit("Input dataset is empty")

    labels = [row["gold_technique_id"] for row in rows]
    counts = Counter(labels)
    can_stratify = all(count >= 2 for count in counts.values()) and len(counts) > 1

    train, test = train_test_split(
        rows,
        test_size=args.test_size,
        random_state=args.seed,
        stratify=labels if can_stratify else None,
    )

    write_jsonl(train, resolve_path(args.train_out))
    write_jsonl(test, resolve_path(args.test_out))
    print(f"Train rows: {len(train)}")
    print(f"Test rows: {len(test)}")
    print(f"Stratified split used: {can_stratify}")


if __name__ == "__main__":
    main()
