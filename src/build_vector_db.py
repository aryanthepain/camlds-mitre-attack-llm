"""Build a ChromaDB vector database over MITRE ATT&CK technique documents."""

from __future__ import annotations

import argparse
from typing import Any, Dict, List

import chromadb
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

from utils import read_jsonl, resolve_path


def batched(rows: List[Dict[str, Any]], size: int):
    for i in range(0, len(rows), size):
        yield rows[i : i + size]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--techniques", default="data/mitre/enterprise_techniques.jsonl")
    parser.add_argument("--db-dir", default="data/vector_db/chroma_mitre")
    parser.add_argument("--collection", default="mitre_enterprise_techniques")
    parser.add_argument("--embedding-model", default="sentence-transformers/all-MiniLM-L6-v2")
    parser.add_argument("--batch-size", type=int, default=64)
    args = parser.parse_args()

    docs = read_jsonl(resolve_path(args.techniques))
    if not docs:
        raise SystemExit("No technique documents found. Run build_mitre_kb.py first.")

    db_dir = resolve_path(args.db_dir)
    db_dir.mkdir(parents=True, exist_ok=True)

    client = chromadb.PersistentClient(path=str(db_dir))
    try:
        client.delete_collection(args.collection)
    except Exception:
        pass
    collection = client.create_collection(name=args.collection, metadata={"hnsw:space": "cosine"})

    model = SentenceTransformer(args.embedding_model)

    for batch in tqdm(list(batched(docs, args.batch_size)), desc="Embedding MITRE docs"):
        texts = [row["text"] for row in batch]
        embeddings = model.encode(texts, normalize_embeddings=True).tolist()
        ids = [row["technique_id"] for row in batch]
        metadatas = [
            {
                "technique_id": row["technique_id"],
                "name": row.get("name", ""),
                "tactics": ", ".join(row.get("tactics", [])),
                "url": row.get("url", ""),
            }
            for row in batch
        ]
        collection.add(ids=ids, documents=texts, embeddings=embeddings, metadatas=metadatas)

    print(f"Built Chroma collection '{args.collection}' in {db_dir}")
    print(f"Technique documents indexed: {len(docs)}")


if __name__ == "__main__":
    main()
