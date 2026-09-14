from rag.knowledge_store import search_knowledge


def main():

    query = """
    사용자 입력값이 SQL 문자열에 직접 연결되는
    SQL Injection 취약점
    """

    results = search_knowledge(
        query,
        top_k=3
    )

    print()
    print("========== RAG 검색 결과 ==========")

    documents = results.get(
        "documents",
        [[]]
    )[0]

    metadatas = results.get(
        "metadatas",
        [[]]
    )[0]

    distances = results.get(
        "distances",
        [[]]
    )[0]

    for index, document in enumerate(
        documents
    ):

        print()
        print(
            f"[{index + 1}] "
            f"{metadatas[index]['source']}"
        )

        print(
            f"유사도 거리: "
            f"{distances[index]:.4f}"
        )

        print()
        print(document[:500])

    print()
    print("===================================")


if __name__ == "__main__":
    main()
