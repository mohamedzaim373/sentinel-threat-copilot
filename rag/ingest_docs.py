"""
Ingest markdown playbooks into ChromaDB.
Uses a simple hash-based embedding — no Ollama, no ONNX model download required.
The retriever uses keyword scoring so vector quality doesn't matter.
"""
from pathlib import Path
import hashlib
import chromadb
from chromadb.api.types import EmbeddingFunction, Documents, Embeddings


BASE_DIR = Path(__file__).resolve().parents[1]
DOCS_DIR = BASE_DIR / "rag_docs"
DB_DIR   = BASE_DIR / "chroma_db"

EMBED_DIM = 128


class HashEmbeddingFunction(EmbeddingFunction):
    """Deterministic bag-of-words hash embedding — zero external dependencies."""

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


def chunk_text(text: str, chunk_size: int = 900, overlap: int = 150) -> list[str]:
    chunks, start = [], 0
    while start < len(text):
        chunks.append(text[start:start + chunk_size])
        start += chunk_size - overlap
    return chunks


def ingest_documents():
    embed_fn   = HashEmbeddingFunction()
    client     = chromadb.PersistentClient(path=str(DB_DIR))

    # Delete existing collection to avoid dimension conflicts
    try:
        client.delete_collection("soc_knowledge_base")
        print("[~] Ancienne collection supprimée")
    except Exception:
        pass

    collection = client.create_collection(
        name="soc_knowledge_base",
        embedding_function=embed_fn,
        metadata={"hnsw:space": "cosine"},
    )

    md_files = list(DOCS_DIR.rglob("*.md"))
    if not md_files:
        print("[!] Aucun fichier Markdown trouvé dans rag_docs/")
        return

    ids, documents, metadatas = [], [], []
    counter = 0

    for file_path in sorted(md_files):
        text   = file_path.read_text(encoding="utf-8", errors="ignore")
        chunks = chunk_text(text)
        for i, chunk in enumerate(chunks):
            doc_id = f"{file_path.stem}_{i}_{counter}"
            print(f"[+] {doc_id}")
            ids.append(doc_id)
            documents.append(chunk)
            metadatas.append({
                "source":   str(file_path.relative_to(BASE_DIR)),
                "filename": file_path.name,
            })
            counter += 1

    collection.add(ids=ids, documents=documents, metadatas=metadatas)
    print(f"\n[OK] {len(documents)} chunks indexés dans ChromaDB (hash-embedding, dim={EMBED_DIM}).")


if __name__ == "__main__":
    ingest_documents()
