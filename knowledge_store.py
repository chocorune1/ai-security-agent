from pathlib import Path

import chromadb
from sklearn.feature_extraction.text import TfidfVectorizer


def find_base_dir():
    current = Path(__file__).resolve()
    for candidate in [current.parent, *current.parents]:
        if (candidate / "data" / "knowledge").exists():
            return candidate
    return current.parents[2]


BASE_DIR = find_base_dir()
KNOWLEDGE_DIR = BASE_DIR / "data" / "knowledge"
CHROMA_DIR = BASE_DIR / "data" / "chroma"
VECTORIZER_FILE = BASE_DIR / "data" / "tfidf_vectorizer.joblib"
COLLECTION_NAME = "security_knowledge"


def load_documents():
    documents = []
    if not KNOWLEDGE_DIR.exists():
        return documents

    for file_path in sorted(KNOWLEDGE_DIR.rglob("*.md")):
        if not file_path.is_file():
            continue
        content = file_path.read_text(encoding="utf-8").strip()
        if not content:
            continue

        relative_path = file_path.relative_to(KNOWLEDGE_DIR)
        source = relative_path.as_posix()
        document_id = relative_path.with_suffix("").as_posix().replace("/", "__")
        parts = relative_path.parts
        category = parts[0] if len(parts) > 1 else "general"

        documents.append({
            "id": document_id,
            "text": content,
            "source": source,
            "category": category,
        })

    return documents


def build_knowledge_base():
    documents = load_documents()
    if not documents:
        raise RuntimeError(f"Knowledge 문서를 찾을 수 없습니다: {KNOWLEDGE_DIR}")

    texts = [document["text"] for document in documents]
    vectorizer = TfidfVectorizer(token_pattern=r"(?u)\b\w+\b")
    embeddings = vectorizer.fit_transform(texts).toarray()

    import joblib
    VECTORIZER_FILE.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(vectorizer, VECTORIZER_FILE)

    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))

    # Recreate the collection because TF-IDF vocabulary/dimension can change
    # when knowledge documents are added or removed.
    try:
        client.delete_collection(name=COLLECTION_NAME)
    except Exception:
        pass

    collection = client.create_collection(name=COLLECTION_NAME)

    collection.upsert(
        ids=[document["id"] for document in documents],
        documents=texts,
        embeddings=embeddings.tolist(),
        metadatas=[
            {"source": document["source"], "category": document["category"]}
            for document in documents
        ],
    )

    print(f"Knowledge 문서 {len(documents)}개를 ChromaDB에 저장했습니다.")
    for document in documents:
        print(f"  - [{document['category']}] {document['source']}")


def search_knowledge(query, top_k=3):
    import joblib

    if not VECTORIZER_FILE.exists():
        raise RuntimeError("TF-IDF vectorizer가 없습니다. 먼저 build_rag.py를 실행하세요.")

    vectorizer = joblib.load(VECTORIZER_FILE)
    query_vector = vectorizer.transform([query]).toarray()[0]

    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    collection = client.get_collection(name=COLLECTION_NAME)

    return collection.query(
        query_embeddings=[query_vector.tolist()],
        n_results=top_k,
        include=["documents", "metadatas", "distances"],
    )


if __name__ == "__main__":
    build_knowledge_base()
