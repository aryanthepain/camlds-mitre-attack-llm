# Automated Mapping of Network Alerts to MITRE ATT&CK using Large Language Models

**Project type:** Defensive cybersecurity analytics / SOC alert triage automation  
**Dataset:** CAM-LDS Cyber Attack Manifestations Log Data Set  
**Primary log source used:** Suricata `eve.json` network intrusion alerts  
**Modeling approach:** Retrieval-Augmented Generation / semantic retrieval with optional local LLM reranking  

---

## 1. Abstract

Security Operations Center analysts are often required to inspect large volumes of low-level intrusion detection alerts and translate them into higher-level adversary behaviors. This project automates part of that workflow by mapping Suricata network alerts to MITRE ATT&CK technique identifiers. The system ingests raw `eve.json` alerts from the CAM-LDS dataset, constructs a local MITRE ATT&CK Enterprise knowledge base, retrieves candidate techniques using dense semantic embeddings, and optionally uses a local instruction-following language model to select the final technique from the retrieved candidates. The final output is a structured prediction containing a MITRE technique ID, technique name, candidate list, confidence score, and explanation.

---

## 2. Motivation

Raw NIDS alerts are useful but difficult to consume at scale. A Suricata signature may identify a suspicious network artifact, but it does not always directly communicate the adversary objective, attack stage, or MITRE ATT&CK behavior. MITRE ATT&CK provides a standardized vocabulary for describing adversary tactics and techniques. Mapping NIDS alerts to ATT&CK therefore helps SOC teams summarize incidents, prioritize investigation, and communicate attacker behavior in a common language.

Manual mapping is time-consuming because it requires both security expertise and contextual reasoning. Large language models and retrieval systems can assist by comparing an observed alert against structured ATT&CK technique descriptions and detection guidance.

---

## 3. Project Scope

### Included

- CAM-LDS dataset ingestion.
- Suricata `eve.json` alert extraction.
- Filtering to alert events only.
- MITRE ATT&CK Enterprise technique knowledge-base creation.
- Dense embedding and vector retrieval using ChromaDB.
- Optional local LLM decision layer using Ollama.
- Structured predictions and evaluation metrics.

### Excluded

- No virtual machine setup.
- No vulnerable lab deployment.
- No active attack execution.
- No Suricata installation or rule tuning.
- No host-based logs in the main pipeline.

---

## 4. Dataset

This project uses CAM-LDS, a public synthetic cyber attack manifestation dataset. CAM-LDS contains logs, alerts, network traffic, and attack labels generated from controlled attack scenarios. The dataset includes attack scenarios mapped to MITRE ATT&CK technique identifiers. For this project, only the Suricata network IDS alerts are used.

The important dataset choice is to use `manifestations_raw.zip` rather than only `manifestations_filtered.zip`, because the raw archive includes `eve.json` network alert files. The filtered archive is useful for many host logs, but the dataset documentation states that network traffic related `eve.json` files are only available in raw manifestations.

---

## 5. Data Preparation

The preparation script recursively searches the CAM-LDS raw manifestations folder for `eve.json` or `eve.jsonl` files. Each line is parsed as JSON. Only events with:

```json
"event_type": "alert"
```

are retained.

For each alert, the following fields are extracted when available:

- Timestamp
- Source file path and line number
- Ground-truth MITRE technique ID from the CAM-LDS directory path
- Suricata alert signature
- Alert category
- Alert severity
- Signature ID
- Protocol and application protocol
- Source and destination ports
- Selected HTTP, DNS, TLS, file, flow, and metadata fields
- Compact raw event string for auditing

The model input text is a compact natural-language representation of the alert, for example:

```text
suricata alert signature: ET SCAN Nmap Scripting Engine User-Agent Detected | category: Attempted Information Leak | severity: 2 | protocol: TCP | application protocol: http | http user agent: Mozilla/5.0 (compatible; Nmap Scripting Engine)
```

Rows are capped per technique to reduce class imbalance and make local experiments faster. This can be disabled by setting `--max-per-technique 0`.

---

## 6. MITRE ATT&CK Knowledge Base

The project downloads the official MITRE ATT&CK Enterprise STIX JSON and parses all non-revoked, non-deprecated `attack-pattern` objects. Each technique document contains:

- Technique ID
- Technique name
- Tactic names
- Platform information
- Data sources
- Description
- Detection guidance
- Official MITRE URL

Each technique is converted into a text document for semantic retrieval. This makes the system independent of a manually curated mapping table.

---

## 7. Modeling Approach

### 7.1 Retrieval-Augmented Generation Design

The main model architecture is RAG:

```text
Suricata alert  ->  alert text encoder  ->  vector search over MITRE techniques  ->  top-k candidate techniques  ->  optional LLM choice  ->  structured MITRE mapping
```

The retrieval layer uses SentenceTransformer embeddings and a ChromaDB vector database. For each alert, the system retrieves the top-k MITRE techniques most semantically similar to the alert.

### 7.2 Retrieval-Only Baseline

In default mode, the system chooses the nearest retrieved technique as the final prediction. This gives a simple, reproducible baseline with no paid model and no GPU requirement.

### 7.3 Optional LLM Reranker

In Ollama mode, the retrieved candidate techniques are passed to a local instruction-following LLM. The LLM must choose only one technique ID from the candidate set and return JSON:

```json
{
  "technique_id": "T1046",
  "confidence": 0.78,
  "reason": "The alert indicates network service scanning behavior."
}
```

Confining the LLM to retrieved candidates reduces hallucination risk and makes the output easier to evaluate.

---

## 8. Evaluation Methodology

The prediction is evaluated against the CAM-LDS ground-truth MITRE technique ID. The main metrics are:

- **Top-1 accuracy:** fraction of alerts where predicted technique ID equals gold technique ID.
- **Macro precision:** average precision across classes, treating each technique equally.
- **Macro recall:** average recall across classes, treating each technique equally.
- **Macro F1:** harmonic mean of macro precision and macro recall.
- **Weighted F1:** F1 weighted by class frequency.
- **Top-k recall:** fraction of alerts where the gold technique appears anywhere in the retrieved candidate list.

Top-k recall is especially important for RAG. If top-k recall is high but top-1 accuracy is lower, the retrieval step is working but the final ranking or LLM selection step needs improvement.

---

## 9. Reproducibility Steps

The project can be run with:

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1  # Windows
pip install -r requirements.txt
python src/download_camlds.py --file manifestations_raw.zip --out-dir data/raw
python run_all.py --raw-zip data/raw/manifestations_raw.zip --llm none
```

For local LLM mode:

```bash
ollama pull qwen2.5:7b-instruct
python run_all.py --raw-zip data/raw/manifestations_raw.zip --llm ollama
```

---

## 10. Results

## Results Summary Filled From Run

- Number of evaluated alerts: 11
- Number of gold MITRE classes: 1
- Top-1 accuracy: 0.00%
- Macro precision: 0.00%
- Macro recall: 0.00%
- Macro F1: 0.00%
- Weighted precision: 0.00%
- Weighted recall: 0.00%
- Weighted F1: 0.00%
- Top-k recall: 0.00%

Interpretation placeholder: Replace this paragraph after manual inspection of the confusion matrix and sample predictions. Top-k recall measures whether the correct MITRE technique appeared among the retrieved candidate set. If top-k recall is much higher than top-1 accuracy, the retriever is finding useful candidates but the final ranking/LLM decision step needs improvement.

---

## 11. Discussion

The system is expected to perform best for alerts whose signatures clearly describe observable attacker behavior, such as scanning, brute-force activity, suspicious HTTP requests, malicious user agents, DNS anomalies, or known exploit indicators. It may perform worse when multiple ATT&CK techniques produce similar network-level artifacts or when the Suricata signature is too generic.

Because only network IDS alerts are used, the model may not see host-level context that is often necessary to distinguish closely related techniques. For example, network scanning and discovery behaviors may be visible in traffic, while privilege escalation and local persistence techniques often require host logs for confident classification. This is a limitation of the project scope rather than only a model limitation.

---

## 12. Limitations

1. **Network-only view:** Some ATT&CK techniques are inherently host-centric and cannot be reliably inferred from Suricata alerts alone.
2. **Synthetic dataset:** CAM-LDS is controlled and reproducible, but real SOC traffic contains benign background noise and organization-specific behavior.
3. **Class imbalance:** Some techniques may generate far more alerts than others.
4. **Path-derived labels:** The current preparation script uses CAM-LDS directory labels as ground truth. This is appropriate for the released dataset structure but should be verified if the dataset format changes.
5. **RAG candidate bottleneck:** If the correct technique is not retrieved in top-k, the LLM cannot select it.

---

## 13. Future Work

- Add host-based logs such as Wazuh, audit logs, syslog, and authentication logs.
- Fine-tune a small instruct model using QLoRA on the prepared alert-to-technique pairs.
- Add multi-label prediction because some attack steps may correspond to multiple techniques.
- Add scenario-aware context so that previous steps in an attack chain inform the current prediction.
- Compare retrieval-only, local LLM RAG, and fine-tuned LLM performance.
- Add calibration analysis for confidence scores.

---

## 14. Conclusion

This project demonstrates an end-to-end defensive AI pipeline for mapping Suricata network alerts to MITRE ATT&CK techniques. The implementation avoids infrastructure setup and attack generation by using CAM-LDS, focuses on clean dataset preparation and reproducible modeling, and produces measurable SOC-style outputs. The RAG architecture is practical because it does not require expensive fine-tuning while still grounding predictions in the official MITRE ATT&CK knowledge base.

---

## References

- CAM-LDS: Cyber Attack Manifestations Log Data Set, Zenodo record 18861762.
- Landauer, M., Hotwagner, W., Boenke, T., Skopik, F., & Wurzenberger, M. CAM-LDS: Cyber Attack Manifestations for Automatic Interpretation of System Logs and Security Alerts.
- MITRE ATT&CK Enterprise Matrix and STIX data.
