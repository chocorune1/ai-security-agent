import json
import re

from llm.qwen_client import ask_qwen
from rag.knowledge_store import search_knowledge


def _clean_json_response(text):
    """
    Qwen 응답에서 JSON 부분만 추출합니다.
    Markdown code fence가 포함되어 있어도 처리합니다.
    """

    if not text:
        return None

    text = text.strip()

    # ```json ... ``` 제거
    text = re.sub(
        r"^```(?:json)?\s*",
        "",
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(
        r"\s*```$",
        "",
        text
    )

    text = text.strip()

    # 전체가 JSON인 경우
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 응답 중 JSON 부분만 추출
    start = text.find("{")
    end = text.rfind("}")

    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(
                text[start:end + 1]
            )
        except json.JSONDecodeError:
            pass

    # 배열인 경우
    start = text.find("[")
    end = text.rfind("]")

    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(
                text[start:end + 1]
            )
        except json.JSONDecodeError:
            pass

    return None


def _normalize_findings(result, source):
    """
    Qwen 결과의 기본 형식을 정리합니다.
    """

    if isinstance(result, dict):
        findings = result.get("findings", [])
    elif isinstance(result, list):
        findings = result
    else:
        findings = []

    if not isinstance(findings, list):
        return []

    normalized = []

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        item = dict(finding)

        item["file"] = (
            item.get("file")
            or source.get("file_name")
        )

        item["type"] = (
            item.get("type")
            or "Unknown"
        )

        item["severity"] = (
            item.get("severity")
            or "Medium"
        )

        item["status"] = (
            item.get("status")
            or "REVIEW"
        ).upper()

        item["confidence"] = (
            item.get("confidence")
            or "MEDIUM"
        ).upper()

        if item.get("line") is None:
            item["line"] = _find_line_from_rule(
                item,
                source
            )

        normalized.append(item)

    return normalized


def _find_line_from_rule(finding, source):
    """
    Qwen이 line을 주지 않은 경우
    evidence 또는 type을 이용하여 대략적인 라인을 찾습니다.
    """

    content = source.get("content", "")
    lines = content.splitlines()

    evidence = finding.get("evidence")

    if evidence:
        evidence_text = str(evidence).strip()

        for index, line in enumerate(lines, start=1):
            if evidence_text and evidence_text in line:
                return index

    return None


def build_rag_context(source, rule_findings):
    """
    Rule 결과를 기반으로 관련 보안 지식을 검색합니다.
    """

    query_parts = []

    for finding in rule_findings:
        finding_type = finding.get("type")

        if finding_type:
            query_parts.append(
                str(finding_type)
            )

    extension = source.get("extension")

    if extension:
        query_parts.append(
            str(extension)
        )

    if not query_parts:
        query_parts.append(
            "source code security"
        )

    query = " ".join(query_parts)

    try:
        documents = search_knowledge(
            query,
            top_k=5
        )
    except Exception:
        documents = []

    if not documents:
        return "관련 보안 지식이 없습니다."

    context_parts = []

    for index, document in enumerate(
        documents,
        start=1
    ):
        context_parts.append(
            f"[보안 지식 {index}]\n"
            f"{document}"
        )

    return "\n\n".join(
        context_parts
    )


def analyze_with_qwen(
    source,
    rule_findings
):
    """
    전체 소스코드를 Qwen에게 전달하여
    보안 취약점을 분석합니다.
    """

    file_name = source.get(
        "file_name",
        "unknown"
    )

    extension = source.get(
        "extension",
        ""
    )

    content = source.get(
        "content",
        ""
    )

    rag_context = build_rag_context(
        source,
        rule_findings
    )

    rule_text = json.dumps(
        rule_findings,
        ensure_ascii=False,
        indent=2
    )

    prompt = f"""
당신은 소스코드 보안 취약점 분석 전문가입니다.

Java, JavaScript, JSP 소스코드를 분석하여
실제로 보안 취약점이 존재하는지 판단하십시오.

중요한 원칙:

1. 단순히 위험해 보이는 API가 있다고 해서
   무조건 취약점으로 판단하지 마십시오.

2. 실제 사용자 입력값이 취약한 코드에 도달하는지
   데이터 흐름을 고려하십시오.

3. 실제 공격 가능성이 확인되지 않으면
   VULNERABLE이 아니라 REVIEW 또는 SAFE를 사용하십시오.

4. 정상적으로 parameter binding, encoding,
   validation 등의 보호조치가 적용된 코드는
   취약점으로 판단하지 마십시오.

5. Rule Scanner 결과는 참고 자료일 뿐이며
   반드시 실제 소스코드와 대조하십시오.

6. 같은 취약점이 여러 번 발견되더라도
   동일한 코드 위치에 대한 중복 결과는 하나로 통합하십시오.

7. 취약점이 실제로 존재하는 경우에는
   반드시 해당 코드를 설명할 수 있는 evidence를 작성하십시오.

8. line은 가능한 경우 실제 취약 코드가 존재하는
   소스코드 라인을 사용하십시오.

9. severity는 다음 기준을 사용하십시오.

   Critical:
   시스템 전체 장악, 원격 코드 실행 등
   매우 심각한 영향

   High:
   SQL Injection, Command Injection,
   인증 우회 등 심각한 공격이 가능한 경우

   Medium:
   일반적인 XSS, Path Traversal 등

   Low:
   영향도가 상대적으로 낮은 보안 문제

10. confidence는 다음 기준을 사용하십시오.

   HIGH:
   실제 취약 코드가 명확하게 확인됨

   MEDIUM:
   취약 가능성이 높지만 일부 정보가 부족함

   LOW:
   추가 확인이 필요함

11. status는 반드시 다음 중 하나만 사용하십시오.

   VULNERABLE
   SAFE
   REVIEW

파일명:
{file_name}

확장자:
{extension}

Rule Scanner 탐지 결과:
{rule_text}

관련 보안 지식:
{rag_context}

분석 대상 소스코드:
--------------------
{content}
--------------------

반드시 JSON만 출력하십시오.

형식:

{{
  "file": "{file_name}",
  "findings": [
    {{
      "type": "SQL Injection",
      "severity": "High",
      "line": 10,
      "evidence": "실제 취약 코드",
      "description": "취약점 설명",
      "reason": "왜 취약한지 설명",
      "recommendation": "개선 방법",
      "status": "VULNERABLE",
      "confidence": "HIGH"
    }}
  ]
}}

취약점이 없다면:

{{
  "file": "{file_name}",
  "findings": []
}}
"""

    try:
        response = ask_qwen(prompt)
    except Exception as e:
        print(
            f"  Qwen 분석 오류: {e}"
        )
        return []

    result = _clean_json_response(
        response
    )

    if result is None:
        print(
            "  Qwen 응답을 JSON으로 "
            "변환하지 못했습니다."
        )
        return []

    return _normalize_findings(
        result,
        source
    )


def validate_rule_finding(
    source,
    finding
):
    """
    Rule Scanner가 발견한 취약점을
    Qwen에게 다시 검증하도록 합니다.

    VULNERABLE / SAFE / REVIEW
    세 가지 상태를 사용합니다.
    """

    file_name = source.get(
        "file_name",
        "unknown"
    )

    content = source.get(
        "content",
        ""
    )

    finding_type = finding.get(
        "type",
        "Unknown"
    )

    line = finding.get(
        "line"
    )

    evidence = finding.get(
        "evidence",
        ""
    )

    prompt = f"""
당신은 소스코드 보안 취약점 검증 전문가입니다.

Rule Scanner가 다음 취약점을 발견했습니다.

파일:
{file_name}

취약점 유형:
{finding_type}

탐지 라인:
{line}

탐지 근거:
{evidence}

전체 소스코드:
--------------------
{content}
--------------------

다음 기준으로 반드시 다시 검증하십시오.

[1] 실제 취약점 여부

단순히 API 이름이나 문자열만 보고 판단하지 마십시오.

실제 사용자 입력이 위험한 sink까지 전달되는지,
그리고 적절한 방어 코드가 존재하는지를 확인하십시오.

[2] SAFE 기준

다음과 같은 보호조치가 확인되면 SAFE로 판단하십시오.

- PreparedStatement parameter binding
- 적절한 HTML encoding
- 입력값 검증
- 안전한 API 사용
- 공격 가능한 데이터 흐름이 존재하지 않음
- 단순 문자열 또는 테스트 코드
- 취약 API가 사용되지만 실제 공격 경로가 없음

[3] REVIEW 기준

소스코드만으로 취약 여부를 확실하게 판단하기 어려우면
REVIEW로 판단하십시오.

[4] VULNERABLE 기준

실제 공격 가능한 코드와 데이터 흐름이
명확하게 확인되는 경우에만 VULNERABLE로 판단하십시오.

반드시 다음 JSON 형식으로만 응답하십시오.

{{
  "type": "{finding_type}",
  "file": "{file_name}",
  "line": {line if line is not None else "null"},
  "status": "VULNERABLE",
  "reason": "판정 근거",
  "confidence": "HIGH"
}}

status는 반드시 다음 중 하나만 사용하십시오.

VULNERABLE
SAFE
REVIEW

confidence는 다음 중 하나입니다.

HIGH
MEDIUM
LOW
"""

    try:
        response = ask_qwen(prompt)
    except Exception as e:
        print(
            f"  Qwen 검증 오류: {e}"
        )

        return {
            "type": finding_type,
            "file": file_name,
            "line": line,
            "status": "REVIEW",
            "reason": "AI 검증 실패",
            "confidence": "LOW"
        }

    result = _clean_json_response(
        response
    )

    if not isinstance(result, dict):
        return {
            "type": finding_type,
            "file": file_name,
            "line": line,
            "status": "REVIEW",
            "reason": "AI 응답 형식 오류",
            "confidence": "LOW"
        }

    status = (
        result.get("status")
        or "REVIEW"
    ).upper()

    if status not in {
        "VULNERABLE",
        "SAFE",
        "REVIEW"
    }:
        status = "REVIEW"

    confidence = (
        result.get("confidence")
        or "MEDIUM"
    ).upper()

    if confidence not in {
        "HIGH",
        "MEDIUM",
        "LOW"
    }:
        confidence = "MEDIUM"

    return {
        "type": (
            result.get("type")
            or finding_type
        ),
        "file": (
            result.get("file")
            or file_name
        ),
        "line": (
            result.get("line")
            if result.get("line") is not None
            else line
        ),
        "status": status,
        "reason": (
            result.get("reason")
            or "AI 검증 결과"
        ),
        "confidence": confidence
    }
