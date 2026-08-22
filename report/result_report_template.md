# Result Report Template

Use this after running the pipeline.

## 1. Run Configuration

- Dataset archive used:
- Number of extracted Suricata alerts:
- Number of distinct gold MITRE techniques:
- Max rows per technique:
- Test size:
- Model mode: retrieval-only / Ollama RAG
- Embedding model:
- Top-k retrieval size:
- Ollama model, if used:

## 2. Overall Metrics

| Metric | Value |
|---|---:|
| Top-1 Accuracy |  |
| Macro Precision |  |
| Macro Recall |  |
| Macro F1 |  |
| Weighted Precision |  |
| Weighted Recall |  |
| Weighted F1 |  |
| Top-k Recall |  |

## 3. Strongest Technique Classes

Fill from `outputs/classification_report.csv`.

| Technique ID | Precision | Recall | F1 | Support | Interpretation |
|---|---:|---:|---:|---:|---|
|  |  |  |  |  |  |

## 4. Weakest Technique Classes

| Technique ID | Precision | Recall | F1 | Support | Likely Reason |
|---|---:|---:|---:|---:|---|
|  |  |  |  |  |  |

## 5. Confusion Analysis

Use `outputs/confusion_matrix.csv` to identify repeated mistakes.

Common confusion examples:

1. Gold: ___, Predicted: ___ — likely because ___
2. Gold: ___, Predicted: ___ — likely because ___
3. Gold: ___, Predicted: ___ — likely because ___

## 6. Sample Predictions

Paste 5-10 examples from `outputs/predictions.jsonl`.

## 7. Final Interpretation

Write whether automated AI triage appears useful for SOC analysts. Discuss whether the system is more useful as a direct mapper or as a candidate-generation assistant.
