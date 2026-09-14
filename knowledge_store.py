from pathlib import Path

import chromadb
from sklearn.feature_extraction.text import TfidfVectorizer


BASE_DIR = Path(__file__).resolve().parents[2]

KNOWLEDGE_DIR = BASE_DIR / "data" / "knowledge"

CHROMA_DIR = BASE_DIR / "data" / "chroma"

VECTORIZER_FILE = BASE_DIR / "data" / "tfidf_vectorizer.joblib"


def load_documents():

    documents = []

    for file_path in KNOWLEDGE_DIR.glob("*.md"):

        content = file_path.read_text(
            encoding="utf-8"
        )

        documents.append({
            "id": file_path.stem,
            "text": content,
            "source": file_path.name
        })

    return documents


def build_knowledge_base():

    documents = load_documents()

    if not documents:
        raise RuntimeError(
            "Knowledge 문서를 찾을 수 없습니다."
        )

    texts = [
        document["text"]
        for document in documents
    ]

    vectorizer = TfidfVectorizer(
        token_pattern=r"(?u)\b\w+\b"
    )

    embeddings = vectorizer.fit_transform(
        texts
    ).toarray()

    import joblib

    joblib.dump(
        vectorizer,
        VECTORIZER_FILE
    )

    client = chromadb.PersistentClient(
        path=str(CHROMA_DIR)
    )

    collection = client.get_or_create_collection(
        name="security_knowledge"
    )

    collection.upsert(
        ids=[
            document["id"]
            for document in documents
        ],
        documents=texts,
        embeddings=embeddings.tolist(),
        metadatas=[
            {
                "source": document["source"]
            }
            for document in documents
        ]
    )

    print(
        f"Knowledge 문서 {len(documents)}개를 "
        "ChromaDB에 저장했습니다."
    )


def search_knowledge(query, top_k=3):

    import joblib

    vectorizer = joblib.load(
        VECTORIZER_FILE
    )

    query_vector = vectorizer.transform(
        [query]
    ).toarray()[0]

    client = chromadb.PersistentClient(
        path=str(CHROMA_DIR)
    )

    collection = client.get_collection(
        name="security_knowledge"
    )

    result = collection.query(
        query_embeddings=[
            query_vector.tolist()
        ],
        n_results=top_k
    )

    return result
