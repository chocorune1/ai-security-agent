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

반드시 아래 JSON 형식으로만 답변하세요.

{
  "file": "파일명",
  "findings": [
    {
      "type": "SQL Injection",
      "severity": "HIGH",
      "line": 14,
      "evidence": "취약한 코드 한 줄",
      "description": "취약점 설명",
      "reason": "왜 취약한지 설명",
      "recommendation": "구체적인 수정 방법",
      "status": "CONFIRMED",
      "confidence": "HIGH"
    }
  ]
}

취약점이 없거나
Rule Scanner가 오탐한 경우에도
실제 취약점으로 보고하지 마세요.

취약점이 전혀 없다면:

{
  "file": "파일명",
  "findings": []
}

JSON 이외의 설명이나 Markdown을 추가하지 마세요.
