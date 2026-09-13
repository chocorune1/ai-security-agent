from llm.qwen_client import ask_qwen


def analyze_with_qwen(source, rule_findings):
    """
    소스코드와 Rule Scanner 결과를 Qwen에게 전달하여
    AI 기반 보안 분석을 수행한다.
    """

    file_name = source["file_name"]
    extension = source["extension"]
    content = source["content"]

    rule_summary = ""

    if rule_findings:
        for finding in rule_findings:
            rule_summary += (
                f"- {finding['type']} "
                f"(심각도: {finding['severity']}, "
                f"라인: {finding['line']})\n"
            )
    else:
        rule_summary = "Rule Scanner에서 발견된 취약점이 없습니다."

    prompt = f"""
당신은 소프트웨어 보안 취약점 분석 전문가입니다.

다음 소스코드를 분석하여 보안 취약점을 찾아주세요.

파일명:
{file_name}

파일 유형:
{extension}

===== 소스코드 =====
{content}
===== 소스코드 끝 =====

===== Rule Scanner 사전 분석 결과 =====
{rule_summary}
===== 사전 분석 결과 끝 =====

다음 항목을 중심으로 분석하세요.

1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Command Injection
4. Path Traversal
5. Hard-coded Credential
6. 민감정보 노출
7. 안전하지 않은 입력값 처리

Rule Scanner 결과를 그대로 믿지 말고
소스코드의 실제 흐름을 기준으로 판단하세요.

취약점이 발견되면 다음 정보를 포함해서 설명하세요.

- 취약점 유형
- 심각도
- 발생 라인
- 취약한 코드
- 취약한 이유
- 공격 가능성
- 수정 방법

취약점이 없으면 없다고 명확하게 말하세요.

답변은 한국어로 작성하세요.
"""

    return ask_qwen(prompt)
