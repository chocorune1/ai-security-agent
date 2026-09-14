import json

from llm.qwen_client import ask_qwen
from rag.knowledge_store import search_knowledge


def build_rag_context(source, rule_findings):
    """
    현재 소스와 Rule Scanner 결과를 기반으로
    관련 보안 지식을 ChromaDB에서 검색한다.
    """

    query_parts = []

    # Rule Scanner에서 발견한 취약점 유형
    for finding in rule_findings:
        query_parts.append(
            finding["type"]
        )

    # Rule 결과가 없더라도 소스 언어를 검색에 활용
    query_parts.append(
        f"{source['extension']} security vulnerability"
    )

    query = " ".join(query_parts)

    results = search_knowledge(
        query,
        top_k=3
    )

    documents = results.get(
        "documents",
        [[]]
    )[0]

    metadatas = results.get(
        "metadatas",
        [[]]
    )[0]

    rag_context = []

    for index, document in enumerate(documents):

        source_name = (
            metadatas[index]["source"]
            if index < len(metadatas)
            else "unknown"
        )

        rag_context.append(
            f"""
[보안 지식 {index + 1}]
출처: {source_name}

{document}
"""
        )

    if not rag_context:
        return "관련 보안 지식을 찾지 못했습니다."

    return "\n".join(rag_context)


def analyze_with_qwen(source, rule_findings):
    """
    소스코드 + Rule Scanner + RAG 지식을
    Qwen에게 전달하여 보안 분석을 수행한다.
    """

    file_name = source["file_name"]
    extension = source["extension"]
    content = source["content"]

    # -----------------------------------
    # Rule 결과 정리
    # -----------------------------------

    rule_summary = []

    for finding in rule_findings:

        rule_summary.append({
            "type": finding["type"],
            "severity": finding["severity"],
            "line": finding["line"],
            "evidence": finding["evidence"]
        })

    rule_summary_text = json.dumps(
        rule_summary,
        ensure_ascii=False,
        indent=2
    )

    # -----------------------------------
    # RAG 검색
    # -----------------------------------

    rag_context = build_rag_context(
        source,
        rule_findings
    )

    # -----------------------------------
    # Qwen Prompt
    # -----------------------------------

    prompt = f"""
당신은 소프트웨어 보안 취약점 분석 전문가입니다.

소스코드, Rule Scanner 결과,
그리고 보안 지식 검색 결과를 참고하여
실제 보안 취약점을 분석하세요.

==============================
파일 정보
==============================

파일명:
{file_name}

파일 유형:
{extension}


==============================
소스코드
==============================

{content}


==============================
Rule Scanner 결과
==============================

{rule_summary_text}


==============================
RAG 보안 지식
==============================

{rag_context}


==============================
분석 지침
==============================

다음 취약점 유형을 중심으로 분석하세요.

1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Command Injection
4. Path Traversal
5. Hard-coded Credential
6. 민감정보 노출
7. 안전하지 않은 입력값 처리

중요:

Rule Scanner 결과를 그대로 믿지 마세요.

실제 소스코드의 데이터 흐름과 실행 흐름을
기준으로 취약점 여부를 판단하세요.

RAG 보안 지식은 취약점 판단과
수정 방법을 결정할 때 참고하세요.

실제 취약점이 존재하는 경우에만 findings에 포함하세요.

==============================
출력 형식
==============================

반드시 아래 JSON 형식으로만 답변하세요.

{{
  "file": "{file_name}",
  "findings": [
    {{
      "type": "SQL Injection",
      "severity": "HIGH",
      "line": 14,
      "evidence": "취약한 코드 한 줄",
      "description": "취약점에 대한 설명",
      "reason": "왜 취약한지 설명",
      "recommendation": "구체적인 수정 방법"
    }}
  ]
}}

취약점이 없으면:

{{
  "file": "{file_name}",
  "findings": []
}}

severity는 다음 중 하나만 사용하세요.

CRITICAL
HIGH
MEDIUM
LOW

JSON 이외의 설명이나 Markdown을 추가하지 마세요.
"""

    response = ask_qwen(prompt)

    return parse_qwen_response(response)


def parse_qwen_response(response):
    """
    Qwen 응답을 JSON으로 변환한다.
    """

    response = response.strip()

    # ```json ... ``` 처리
    if response.startswith("```"):

        lines = response.splitlines()

        if lines[0].startswith("```"):
            lines = lines[1:]

        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        response = "\n".join(lines).strip()

    try:

        return json.loads(response)

    except json.JSONDecodeError:

        return {
            "error": "Qwen 응답을 JSON으로 변환할 수 없습니다.",
            "raw_response": response
        }
