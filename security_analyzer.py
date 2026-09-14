import json

from llm.qwen_client import ask_qwen


def analyze_with_qwen(source, rule_findings):
    """
    소스코드와 Rule Scanner 결과를 Qwen에게 전달하고
    JSON 형식의 보안 분석 결과를 반환한다.
    """

    file_name = source["file_name"]
    extension = source["extension"]
    content = source["content"]

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

    prompt = f"""
당신은 소프트웨어 보안 취약점 분석 전문가입니다.

다음 소스코드를 분석하여 실제 보안 취약점을 찾아주세요.

파일명:
{file_name}

파일 유형:
{extension}

===== 소스코드 =====
{content}
===== 소스코드 끝 =====

===== Rule Scanner 사전 분석 결과 =====
{rule_summary_text}
===== 사전 분석 결과 끝 =====

다음 취약점 유형을 중심으로 분석하세요.

1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Command Injection
4. Path Traversal
5. Hard-coded Credential
6. 민감정보 노출
7. 안전하지 않은 입력값 처리

Rule Scanner 결과를 그대로 믿지 말고
실제 소스코드의 데이터 흐름과 실행 흐름을 기준으로 판단하세요.

취약점이 실제로 존재하는 경우에만 findings에 포함하세요.

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

취약점이 없다면 다음과 같이 반환하세요.

{{
  "file": "{file_name}",
  "findings": []
}}

severity는 다음 중 하나만 사용하세요.

- CRITICAL
- HIGH
- MEDIUM
- LOW

JSON 이외의 설명이나 Markdown을 절대 추가하지 마세요.
"""
    
    response = ask_qwen(prompt)

    return parse_qwen_response(response)


def parse_qwen_response(response):
    """
    Qwen 응답에서 JSON을 추출한다.
    """

    response = response.strip()

    # ```json ... ``` 형태로 응답할 경우 처리
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
