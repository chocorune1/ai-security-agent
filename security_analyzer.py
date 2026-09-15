import json

from llm.qwen_client import ask_qwen
from rag.knowledge_store import search_knowledge


def build_rag_context(source, rule_findings):
    """
    현재 소스와 Rule Scanner 결과를 기반으로
    관련 보안 지식을 ChromaDB에서 검색한다.
    """

    query_parts = []

    for finding in rule_findings:

        if finding.get("type"):
            query_parts.append(
                finding["type"]
            )

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

        if index < len(metadatas):

            source_name = metadatas[index].get(
                "source",
                "unknown"
            )

        else:

            source_name = "unknown"

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

    최종 반환값:
        list
    """

    file_name = source["file_name"]
    extension = source["extension"]
    content = source["content"]

    # ==================================================
    # 1. Rule 결과 정리
    # ==================================================

    rule_summary = []

    for finding in rule_findings:

        rule_summary.append({
            "type": finding.get(
                "type",
                ""
            ),
            "severity": finding.get(
                "severity",
                "MEDIUM"
            ),
            "line": finding.get(
                "line"
            ),
            "evidence": finding.get(
                "evidence",
                ""
            )
        })

    rule_summary_text = json.dumps(
        rule_summary,
        ensure_ascii=False,
        indent=2
    )

    # ==================================================
    # 2. RAG 검색
    # ==================================================

    rag_context = build_rag_context(
        source,
        rule_findings
    )

    # ==================================================
    # 3. Qwen Prompt
    # ==================================================

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

Rule Scanner 결과를 그대로 취약점으로 확정하지 마세요.

반드시 실제 소스코드를 분석하여
취약점 여부를 판단하세요.

다음 3가지 상태 중 하나를 선택하세요.

CONFIRMED
- 실제 보안 취약점이 존재하는 경우

FALSE_POSITIVE
- Rule Scanner가 취약점으로 탐지했지만
  실제로는 안전한 코드인 경우

REVIEW_REQUIRED
- 취약점 가능성은 있으나
  현재 코드만으로 확정하기 어려운 경우

confidence는 다음 중 하나를 선택하세요.

HIGH
- 코드 흐름상 취약점이 명확함

MEDIUM
- 취약점 가능성이 높지만 일부 확인이 필요함

LOW
- 근거가 부족하여 판단하기 어려움

실제 취약점이 존재하는 경우에만
CONFIRMED로 판단하세요.

==============================
출력 형식
==============================

반드시 JSON 형식으로만 답변하세요.

파일명은 반드시 다음 값을 사용하세요.

"{file_name}"

형식:

{{
  "file": "{file_name}",
  "findings": [
    {{
      "type": "SQL Injection",
      "severity": "HIGH",
      "line": 14,
      "evidence": "취약한 코드 한 줄",
      "description": "취약점 설명",
      "reason": "왜 취약한지 설명",
      "recommendation": "구체적인 수정 방법",
      "status": "CONFIRMED",
      "confidence": "HIGH"
    }}
  ]
}}

취약점이 없다면:

{{
  "file": "{file_name}",
  "findings": []
}}

JSON 이외의 설명이나 Markdown을 추가하지 마세요.
"""

    # ==================================================
    # 4. Qwen 호출
    # ==================================================

    response = ask_qwen(prompt)

    # ==================================================
    # 5. Qwen 응답 파싱
    # ==================================================

    parsed = parse_qwen_response(
        response
    )

    # ==================================================
    # 6. Qwen 결과를 LIST로 변환
    # ==================================================

    # Qwen 응답이 오류인 경우
    if not isinstance(parsed, dict):

        print(
            f"[경고] Qwen 응답 형식 오류: "
            f"{file_name}"
        )

        return []

    if "error" in parsed:

        print(
            f"[경고] Qwen JSON 파싱 실패: "
            f"{file_name}"
        )

        return []

    findings = parsed.get(
        "findings",
        []
    )

    if not isinstance(findings, list):

        print(
            f"[경고] Qwen findings 형식 오류: "
            f"{file_name}"
        )

        return []

    # ==================================================
    # 7. 파일명 / 라인 / 기본값 보완
    # ==================================================

    normalized_findings = []

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        finding_type = finding.get(
            "type"
        )

        if not finding_type:
            continue

        # Qwen이 파일명을 빼먹어도
        # 현재 분석 중인 원본 파일명을 사용
        finding_file = finding.get(
            "file"
        )

        if not finding_file:
            finding_file = file_name

        # Qwen이 line을 빼먹은 경우
        # 같은 유형의 Rule Finding에서 보완
        finding_line = finding.get(
            "line"
        )

        if finding_line is None:

            for rule in rule_findings:

                if (
                    rule.get("type")
                    == finding_type
                ):
                    finding_line = rule.get(
                        "line"
                    )
                    break

        normalized_findings.append({
            "type": finding_type,

            "severity": finding.get(
                "severity",
                "MEDIUM"
            ),

            "file": finding_file,

            "line": finding_line,

            "evidence": finding.get(
                "evidence",
                ""
            ),

            "description": finding.get(
                "description",
                ""
            ),

            "reason": finding.get(
                "reason",
                ""
            ),

            "recommendation": finding.get(
                "recommendation",
                ""
            ),

            "status": finding.get(
                "status",
                "CONFIRMED"
            ),

            "confidence": finding.get(
                "confidence",
                "MEDIUM"
            )
        })

    return normalized_findings


def parse_qwen_response(response):
    """
    Qwen 응답을 JSON으로 변환한다.
    """

    if response is None:
        return {
            "error": "Qwen 응답이 없습니다."
        }

    response = response.strip()

    if not response:
        return {
            "error": "Qwen 응답이 비어 있습니다."
        }

    # ==================================================
    # Markdown code fence 제거
    # ==================================================

    if response.startswith("```"):

        lines = response.splitlines()

        if lines:

            first_line = lines[0].strip()

            if first_line.startswith("```"):
                lines = lines[1:]

        if lines:

            last_line = lines[-1].strip()

            if last_line == "```":
                lines = lines[:-1]

        response = "\n".join(
            lines
        ).strip()

    # ==================================================
    # JSON 직접 파싱
    # ==================================================

    try:

        return json.loads(
            response
        )

    except json.JSONDecodeError:
        pass

    # ==================================================
    # 응답 안에서 JSON 영역 추출
    # ==================================================

    start = response.find("{")
    end = response.rfind("}")

    if start != -1 and end != -1 and end > start:

        json_text = response[
            start:end + 1
        ]

        try:

            return json.loads(
                json_text
            )

        except json.JSONDecodeError:
            pass

    return {
        "error":
            "Qwen 응답을 JSON으로 변환할 수 없습니다.",
        "raw_response":
            response
    }


def validate_rule_finding(source, finding):
    """
    Rule Scanner가 발견한 취약점이
    실제 취약점인지 Qwen에게 검증받는다.

    결과:
    VULNERABLE
    SAFE
    REVIEW
    """

    file_name = source["file_name"]
    extension = source["extension"]
    content = source["content"]

    prompt = f"""
당신은 소프트웨어 보안 코드 리뷰 전문가입니다.

아래 소스코드에서 Rule Scanner가
보안 취약점 가능성을 발견했습니다.

하지만 Rule Scanner의 결과를 그대로 믿지 말고
실제 코드 흐름을 분석해서 판단하세요.

==============================
파일
==============================

{file_name}

파일 유형:
{extension}

==============================
전체 소스코드
==============================

{content}

==============================
Rule Scanner 발견
==============================

취약점 유형:
{finding["type"]}

의심 라인:
{finding["line"]}

의심 코드:
{finding["evidence"]}

==============================
판정 기준
==============================

실제로 외부 입력값이 위험한 방식으로 사용되어
보안 취약점이 발생할 수 있으면:

VULNERABLE

안전한 처리 방식이 적용되어 실제 취약점이 아니면:

SAFE

현재 코드만으로 판단하기 어려우면:

REVIEW

==============================
출력 규칙
==============================

반드시 첫 번째 단어로 다음 중 하나만 출력하세요.

VULNERABLE
SAFE
REVIEW

그 뒤에 판단 이유를 한두 문장으로 작성해도 됩니다.

예:

VULNERABLE
사용자 입력값이 SQL 문자열에 직접 연결됩니다.

또는:

SAFE
PreparedStatement의 parameter binding을 사용하고 있습니다.

또는:

REVIEW
외부 메서드에서 전달되는 값의 출처를 확인해야 합니다.
"""

    response = ask_qwen(
        prompt
    )

    response = response.strip()

    upper_response = response.upper()

    if upper_response.startswith(
        "VULNERABLE"
    ):

        status = "VULNERABLE"

    elif upper_response.startswith(
        "SAFE"
    ):

        status = "SAFE"

    elif upper_response.startswith(
        "REVIEW"
    ):

        status = "REVIEW"

    else:

        status = "REVIEW"

    return {
        "type": finding.get(
            "type"
        ),

        "file": finding.get(
            "file",
            file_name
        ),

        "line": finding.get(
            "line"
        ),

        "status": status,

        "reason": response
    }
