import re


def analyze_source(source):
    """
    소스코드에서 기본적인 보안 취약점 패턴을 탐지한다.
    """

    findings = []

    content = source["content"]
    file_name = source["file_name"]
    extension = source["extension"]

    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):

        # 1. Hard-coded Credential
        if re.search(
            r'(password|passwd|pwd|secret|api[_-]?key)'
            r'\s*=\s*["\'][^"\']+["\']',
            line,
            re.IGNORECASE
        ):
            findings.append({
                "type": "Hard-coded Credential",
                "severity": "HIGH",
                "file": file_name,
                "line": line_number,
                "evidence": line.strip(),
                "description":
                    "소스코드에 비밀번호 또는 인증정보가 직접 포함되어 있습니다.",
                "recommendation":
                    "비밀번호나 인증정보를 소스코드에 직접 저장하지 말고 "
                    "환경변수 또는 안전한 Secret 관리 시스템을 사용하세요."
            })

        # 2. SQL Injection
        if (
            re.search(r'["\'].*SELECT.*["\']', line, re.IGNORECASE)
            and ("+" in line or "userId" in line)
        ):
            findings.append({
                "type": "SQL Injection",
                "severity": "HIGH",
                "file": file_name,
                "line": line_number,
                "evidence": line.strip(),
                "description":
                    "사용자 입력값이 SQL 문장에 직접 연결될 가능성이 있습니다.",
                "recommendation":
                    "PreparedStatement의 파라미터 바인딩을 사용하세요."
            })

        # 3. Command Injection
        if re.search(
            r'Runtime\.getRuntime\(\)\.exec\s*\(',
            line
        ):
            findings.append({
                "type": "Command Injection",
                "severity": "CRITICAL",
                "file": file_name,
                "line": line_number,
                "evidence": line.strip(),
                "description":
                    "외부 입력값이 운영체제 명령 실행에 사용될 가능성이 있습니다.",
                "recommendation":
                    "외부 입력을 직접 명령어 실행에 사용하지 말고 "
                    "허용 목록 기반 검증을 적용하세요."
            })

    return findings
