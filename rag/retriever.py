from pathlib import Path
import hashlib
import chromadb
from chromadb.api.types import EmbeddingFunction, Documents, Embeddings

BASE_DIR = Path(__file__).resolve().parents[1]
DB_DIR = BASE_DIR / "chroma_db"

EMBED_DIM = 128


class HashEmbeddingFunction(EmbeddingFunction):
    """Same deterministic embedding used at ingest time."""

    def __call__(self, input: Documents) -> Embeddings:
        results = []
        for text in input:
            vec = [0.0] * EMBED_DIM
            for token in text.lower().split():
                idx = int(hashlib.md5(token.encode()).hexdigest(), 16) % EMBED_DIM
                vec[idx] += 1.0
            norm = sum(x * x for x in vec) ** 0.5
            if norm > 0:
                vec = [x / norm for x in vec]
            results.append(vec)
        return results


def _keyword_score(query: str, document: str) -> float:
    """Keyword overlap score between query and document (primary ranking)."""
    terms = [t.lower() for t in query.split() if len(t) > 3]
    if not terms:
        return 0.0
    doc_lower = document.lower()
    return sum(1 for t in terms if t in doc_lower) / len(terms)


def search_knowledge_base(query: str, n_results: int = 3) -> list[dict]:
    """
    Retrieve the most relevant documents for the query.
    Uses keyword scoring as primary rank (works without semantic embeddings).
    """
    embed_fn   = HashEmbeddingFunction()
    client     = chromadb.PersistentClient(path=str(DB_DIR))
    collection = client.get_or_create_collection(
        name="soc_knowledge_base",
        embedding_function=embed_fn,
        metadata={"hnsw:space": "cosine"},
    )

    count = collection.count()
    if count == 0:
        return []

    all_docs = collection.get(include=["documents", "metadatas"])

    scored = sorted(
        [
            (_keyword_score(query, all_docs["documents"][i]), i)
            for i in range(len(all_docs["documents"]))
        ],
        key=lambda x: -x[0],
    )

    return [
        {
            "content":  all_docs["documents"][i],
            "metadata": all_docs["metadatas"][i],
            "score":    round(score, 3),
        }
        for score, i in scored[:n_results]
    ]


if __name__ == "__main__":
    for q in [
        "netstat port listening state changed",
        "SSH brute force authentication failed",
        "privilege escalation sudo root",
        "malware rootkit file integrity",
        "web attack SQL injection HTTP",
    ]:
        print(f"\nQUERY: {q}")
        for r in search_knowledge_base(q, 1):
            print(f"  → {r['metadata']['filename']}  score={r['score']}")
