# 🛡️ Automated Mapping of Network Alerts to MITRE ATT&CK using LLM/RAG

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAyTDIgN2wxMCA1IDEwLTV6Ii8+PC9zdmc+)](https://attack.mitre.org/)
[![ChromaDB](https://img.shields.io/badge/ChromaDB-Vector_DB-orange)](https://www.trychroma.com/)
[![Ollama](https://img.shields.io/badge/Ollama-Local_LLM-black)](https://ollama.com/)

> **An end-to-end defensive AI pipeline that automatically maps Suricata IDS network alerts to MITRE ATT&CK technique identifiers using Retrieval-Augmented Generation (RAG) with optional local LLM reasoning.**

🌐 **[View Showcase Website](https://aryanthepain.github.io/camlds-mitre-attack-llm/)** · 📓 **[Open in Colab](https://colab.research.google.com/)** · 📄 **[Full Report](report/final_report_filled.md)**

---

## 🎯 What This Project Does

Security Operations Center (SOC) analysts manually inspect thousands of intrusion detection alerts daily and must translate them into higher-level adversary behaviors. This project **automates that workflow**:

1. **Ingests** raw Suricata `eve.json` network alerts from the [CAM-LDS](https://zenodo.org/records/18861762) dataset
2. **Builds** a local MITRE ATT&CK Enterprise knowledge base from official STIX JSON
3. **Retrieves** the most relevant MITRE techniques using dense semantic embeddings + ChromaDB
4. **Optionally reasons** using a local LLM (Ollama) to select the best match from candidates
5. **Evaluates** predictions with standard ML metrics (accuracy, precision, recall, F1, top-k recall)

**No paid API keys required.** The default mode uses retrieval-only prediction. Ollama enables local LLM reasoning.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DATA PREPARATION                            │
│                                                                     │
│  CAM-LDS Archive ──► Extract eve.json ──► Parse Alert Events       │
│  (Zenodo)              (Suricata IDS)      (signature, category,   │
│                                             severity, protocol)     │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     KNOWLEDGE BASE CONSTRUCTION                     │
│                                                                     │
│  MITRE ATT&CK  ──►  Parse STIX JSON  ──►  Technique Documents     │
│  Enterprise          (attack-patterns)      (ID, name, tactics,    │
│                                              detection, description)│
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     RAG INFERENCE PIPELINE                          │
│                                                                     │
│  Alert Text ──► SentenceTransformer ──► ChromaDB Vector Search     │
│                 (all-MiniLM-L6-v2)      (top-k candidates)         │
│                                              │                      │
│                              ┌────────────────┴────────────────┐    │
│                              │                                 │    │
│                        [--llm none]                     [--llm ollama]
│                              │                                 │    │
│                     Nearest Candidate              LLM Reranker     │
│                     (retrieval baseline)        (Qwen 2.5 7B)      │
│                              │                                 │    │
│                              └────────────────┬────────────────┘    │
│                                               ▼                     │
│                                    Structured Prediction            │
│                              (technique_id, confidence, reason)     │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         EVALUATION                                  │
│                                                                     │
│  Accuracy · Macro Precision · Macro Recall · Macro F1 · Top-k Recall│
│  Confusion Matrix · Classification Report                           │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🧰 Tech Stack

| Component | Technology |
|-----------|-----------|
| **Language** | Python 3.10+ |
| **Embeddings** | [SentenceTransformers](https://www.sbert.net/) (`all-MiniLM-L6-v2`) |
| **Vector Database** | [ChromaDB](https://www.trychroma.com/) |
| **Local LLM** | [Ollama](https://ollama.com/) + Qwen 2.5 7B Instruct |
| **Fine-tuning** | QLoRA via [Unsloth](https://github.com/unslothai/unsloth) (Colab notebook) |
| **Knowledge Source** | [MITRE ATT&CK Enterprise](https://attack.mitre.org/) STIX JSON |
| **Dataset** | [CAM-LDS](https://zenodo.org/records/18861762) (Suricata alerts) |
| **ML Evaluation** | scikit-learn |
| **Data Processing** | pandas, numpy |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- (Optional) [Ollama](https://ollama.com/) for local LLM mode

### Setup & Run

```bash
# Clone the repository
git clone https://github.com/aryanthepain/camlds-mitre-attack-llm.git
cd camlds-mitre-attack-llm

# Create virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1   # Windows PowerShell
# source .venv/bin/activate   # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Download CAM-LDS data
python src/download_camlds.py --file manifestations_raw.zip --out-dir data/raw

# Run the full pipeline (retrieval-only baseline)
python run_all.py --raw-zip data/raw/manifestations_raw.zip --llm none
```

### With Local LLM (Ollama)

```bash
ollama pull qwen2.5:7b-instruct
python run_all.py --raw-zip data/raw/manifestations_raw.zip --llm ollama
```

---

## 📁 Project Structure

```
camlds-mitre-attack-llm/
├── src/
│   ├── download_camlds.py       # Download CAM-LDS archives from Zenodo
│   ├── prepare_dataset.py       # Extract & parse Suricata alerts
│   ├── split_dataset.py         # Train/test split
│   ├── build_mitre_kb.py        # Build MITRE ATT&CK knowledge base
│   ├── build_vector_db.py       # Build ChromaDB vector database
│   ├── predict_rag.py           # RAG inference (retrieval ± LLM)
│   ├── evaluate.py              # Metrics & confusion matrix
│   ├── make_result_summary.py   # Fill report template with metrics
│   └── utils.py                 # Shared utilities
├── report/
│   ├── final_report_filled.md   # Complete project report
│   └── project_report_template.md
├── docs/                        # GitHub Pages showcase site
├── camlds_qwen_qlora_colab_balanced.ipynb  # QLoRA fine-tuning notebook
├── config.yaml                  # Pipeline configuration
├── run_all.py                   # One-command pipeline runner
├── requirements.txt             # Python dependencies
└── README.md
```

---

## 📊 Results & Current Status

The retrieval-only baseline was evaluated on a small test slice (11 alerts from a single technique class T1059). As expected with a minimal test set and no fine-tuning, the baseline metrics show room for improvement:

| Metric | Value |
|--------|-------|
| Test alerts evaluated | 11 |
| Top-1 Accuracy | 0.0% |
| Top-k Recall (k=5) | 0.0% |
| Macro F1 | 0.0% |

**Why these numbers are expected:** The retrieval-only baseline uses generic sentence embeddings to match free-text Suricata signatures against MITRE technique descriptions. Suricata internal alerts (e.g., `SURICATA STREAM pkt seen on wrong thread`) are infrastructure-level messages that don't semantically match any specific ATT&CK technique. The architecture is designed to improve with:

1. **Larger, diverse test sets** covering multiple technique classes
2. **LLM reranking** (Ollama mode) for contextual reasoning over candidates
3. **QLoRA fine-tuning** (included Colab notebook) to specialize embeddings

---

## 🔮 Future Work

- [ ] Fine-tune with QLoRA on alert→technique pairs (Colab notebook included)
- [ ] Add host-based logs (Wazuh, syslog, audit logs) for multi-source context
- [ ] Multi-label prediction for attacks spanning multiple techniques
- [ ] Scenario-aware context using attack chain history
- [ ] Calibration analysis for confidence scores
- [ ] Benchmark against commercial SIEM mapping tools

---

## 📝 Sample Prediction Output

```json
{
  "alert_id": "abc123",
  "gold_technique_id": "T1046",
  "predicted_technique_id": "T1046",
  "predicted_name": "Network Service Discovery",
  "confidence": 0.78,
  "candidate_ids": ["T1046", "T1595", "T1018", "T1040", "T1135"],
  "topk_contains_gold": true,
  "reason": "The alert signature indicates network scanning / service enumeration."
}
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 👤 Author

**Aryan Gupta**
- 🎓 IIT Guwahati
- 🔗 [GitHub](https://github.com/aryanthepain)
- 🌐 [Portfolio](https://stellar-salamander-6c2.notion.site/Aryan-Gupta-21f5809f0c2180d5a3b9f4d2a26fafec)
