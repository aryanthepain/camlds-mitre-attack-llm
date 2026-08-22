"""Predict MITRE ATT&CK technique mappings for Suricata alerts.

Modes:
- --llm none: retrieval-only baseline. Predicts the top Chroma candidate.
- --llm ollama: retrieves top-k candidates, then asks a local Ollama model to choose.
"""

from __future__ import annotations

import argparse
import json
import re
from typing import Any, Dict, List, Tuple

import chromadb
import requests
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

from utils import read_jsonl, resolve_path, write_jsonl

TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def query_candidates(
    collection: Any,
    model: SentenceTransformer,
    alert_text: str,
    top_k: int,
) -> List[Dict[str, Any]]:
    embedding = model.encode([alert_text], normalize_embeddings=True).tolist()[0]
    result = collection.query(query_embeddings=[embedding], n_results=top_k)

    candidates: List[Dict[str, Any]] = []
    ids = result.get("ids", [[]])[0]
    docs = result.get("documents", [[]])[0]
    metas = result.get("metadatas", [[]])[0]
    distances = result.get("distances", [[]])[0]
    for tid, doc, meta, dist in zip(ids, docs, metas, distances):
        similarity = 1 - float(dist) if dist is not None else None
        candidates.append(
            {
                "technique_id": tid,
                "name": meta.get("name", "") if meta else "",
                "tactics": meta.get("tactics", "") if meta else "",
                "url": meta.get("url", "") if meta else "",
                "similarity": similarity,
                "text": doc,
            }
        )
    return candidates


def build_prompt(alert: Dict[str, Any], candidates: List[Dict[str, Any]]) -> str:
    compact_candidates = []
    for c in candidates:
        compact_candidates.append(
            {
                "technique_id": c["technique_id"],
                "name": c["name"],
                "tactics": c["tactics"],
                "similarity": c["similarity"],
                "description_excerpt": c["text"][:900],
            }
        )

    return f"""
You are a SOC analyst. Map the Suricata network alert to exactly one MITRE ATT&CK technique.
You must choose only one technique_id from the candidate list. Do not invent IDs.

Suricata alert text:
{alert.get('text', '')}

Candidate MITRE techniques:
{json.dumps(compact_candidates, indent=2, ensure_ascii=False)}

Return only valid JSON with this schema:
{{
  "technique_id": "Txxxx or Txxxx.xxx",
  "confidence": 0.0,
  "reason": "one concise sentence explaining the mapping"
}}
""".strip()


def call_ollama(prompt: str, host: str, model: str, timeout: int = 120) -> Tuple[str, Dict[str, Any]]:
    url = host.rstrip("/") + "/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.0,
            "num_ctx": 8192,
        },
    }
    response = requests.post(url, json=payload, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    text = data.get("response", "")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.S)
        parsed = json.loads(match.group(0)) if match else {}
    return text, parsed


def choose_prediction(
    alert: Dict[str, Any],
    candidates: List[Dict[str, Any]],
    llm: str,
    ollama_host: str,
    ollama_model: str,
) -> Dict[str, Any]:
    if not candidates:
        return {
            "predicted_technique_id": "",
            "predicted_name": "",
            "confidence": 0.0,
            "reason": "No candidates retrieved.",
            "llm_raw_response": "",
        }

    fallback = candidates[0]
    if llm == "none":
        return {
            "predicted_technique_id": fallback["technique_id"],
            "predicted_name": fallback["name"],
            "confidence": fallback.get("similarity") or 0.0,
            "reason": "Retrieval-only baseline selected the nearest MITRE technique document.",
            "llm_raw_response": "",
        }

    if llm == "ollama":
        prompt = build_prompt(alert, candidates)
        try:
            raw, parsed = call_ollama(prompt, ollama_host, ollama_model)
            candidate_ids = {c["technique_id"] for c in candidates}
            pred_id = str(parsed.get("technique_id", "")).strip()
            if pred_id not in candidate_ids:
                found = TECHNIQUE_RE.findall(raw)
                pred_id = next((x for x in found if x in candidate_ids), fallback["technique_id"])
            pred_candidate = next((c for c in candidates if c["technique_id"] == pred_id), fallback)
            return {
                "predicted_technique_id": pred_candidate["technique_id"],
                "predicted_name": pred_candidate["name"],
                "confidence": parsed.get("confidence", fallback.get("similarity") or 0.0),
                "reason": parsed.get("reason", "Local LLM selected from retrieved candidates."),
                "llm_raw_response": raw,
            }
        except Exception as exc:
            return {
                "predicted_technique_id": fallback["technique_id"],
                "predicted_name": fallback["name"],
                "confidence": fallback.get("similarity") or 0.0,
                "reason": f"Ollama failed; used retrieval fallback. Error: {exc}",
                "llm_raw_response": "",
            }

    raise ValueError(f"Unsupported llm mode: {llm}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/processed/test.jsonl")
    parser.add_argument("--output", default="outputs/predictions.jsonl")
    parser.add_argument("--db-dir", default="data/vector_db/chroma_mitre")
    parser.add_argument("--collection", default="mitre_enterprise_techniques")
    parser.add_argument("--embedding-model", default="sentence-transformers/all-MiniLM-L6-v2")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--llm", choices=["none", "ollama"], default="none")
    parser.add_argument("--ollama-host", default="http://localhost:11434")
    parser.add_argument("--ollama-model", default="qwen2.5:7b-instruct")
    args = parser.parse_args()

    rows = read_jsonl(resolve_path(args.input))
    if not rows:
        raise SystemExit("Input file is empty")

    client = chromadb.PersistentClient(path=str(resolve_path(args.db_dir)))
    collection = client.get_collection(args.collection)
    model = SentenceTransformer(args.embedding_model)

    predictions: List[Dict[str, Any]] = []
    for row in tqdm(rows, desc="Predicting"):
        candidates = query_candidates(collection, model, row.get("text", ""), args.top_k)
        chosen = choose_prediction(row, candidates, args.llm, args.ollama_host, args.ollama_model)
        candidate_ids = [c["technique_id"] for c in candidates]

        out = {
            "alert_id": row.get("alert_id", ""),
            "source_file": row.get("source_file", ""),
            "gold_technique_id": row.get("gold_technique_id", ""),
            "alert_signature": row.get("alert_signature", ""),
            "alert_category": row.get("alert_category", ""),
            "alert_severity": row.get("alert_severity", ""),
            "predicted_technique_id": chosen["predicted_technique_id"],
            "predicted_name": chosen["predicted_name"],
            "confidence": chosen["confidence"],
            "candidate_ids": candidate_ids,
            "candidates": [
                {
                    "technique_id": c["technique_id"],
                    "name": c["name"],
                    "tactics": c["tactics"],
                    "similarity": c["similarity"],
                    "url": c["url"],
                }
                for c in candidates
            ],
            "topk_contains_gold": row.get("gold_technique_id", "") in candidate_ids,
            "reason": chosen["reason"],
            "llm_raw_response": chosen.get("llm_raw_response", ""),
        }
        predictions.append(out)

    write_jsonl(predictions, resolve_path(args.output))
    print(f"Wrote predictions: {resolve_path(args.output)}")


if __name__ == "__main__":
    main()
