import re


def analyze_source(source):
    """
    Java / JavaScript / JSP 소스에서
    기본적인 보안 취약점 패턴을 탐지한다.
    """

    findings = []

    content = source["content"]
    file_name = source["file_name"]
    extension = source["extension"]

    lines = content.splitlines()

    for line_number, line in enumerate(
        lines,
        start=1
    ):

        # ==========================================
        # 1. Hard-coded Credential
        # ==========================================

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
                    "소스코드에 비밀번호 또는 인증정보가 "
                    "직접 포함되어 있습니다.",
                "recommendation":
                    "인증정보를 소스코드에 저장하지 말고 "
                    "환경변수 또는 Secret 관리 시스템을 사용하세요."
            })

        # ==========================================
        # 2. SQL Injection
        # ==========================================

        sql_pattern = re.search(
            r'["\'].*\b(SELECT|INSERT|UPDATE|DELETE)'
            r'\b.*["\']',
            line,
            re.IGNORECASE
        )

        if sql_pattern and "+" in line:

            findings.append({
                "type": "SQL Injection",
                "severity": "HIGH",
                "file": file_name,
                "line": line_number,
                "evidence": line.strip(),
                "description":
                    "SQL 문자열에 외부 입력값이 "
                    "직접 연결될 가능성이 있습니다.",
                "recommendation":
                    "PreparedStatement 또는 "
                    "parameterized query를 사용하세요."
            })

        # ==========================================
        # 3. Command Injection
        # ==========================================

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
                    "외부 입력값이 운영체제 명령 실행에 "
                    "사용될 가능성이 있습니다.",
                "recommendation":
                    "외부 입력을 직접 명령 실행에 사용하지 말고 "
                    "allowlist 기반 검증을 적용하세요."
            })

        # ==========================================
        # 4. JavaScript eval
        # ==========================================

        if extension == ".js":

            if re.search(
                r'\beval\s*\(',
                line
            ):

                findings.append({
                    "type": "Dangerous eval",
                    "severity": "HIGH",
                    "file": file_name,
                    "line": line_number,
                    "evidence": line.strip(),
                    "description":
                        "JavaScript eval()을 사용하면 "
                        "문자열이 코드로 실행될 수 있습니다.",
                    "recommendation":
                        "eval() 사용을 제거하고 "
                        "안전한 API를 사용하세요."
                })

        # ==========================================
        # 5. JavaScript DOM XSS
        # ==========================================

        if extension == ".js":

            if re.search(
                r'\.innerHTML\s*=',
                line
            ):

                findings.append({
                    "type": "Cross-Site Scripting (XSS)",
                    "severity": "HIGH",
                    "file": file_name,
                    "line": line_number,
                    "evidence": line.strip(),
                    "description":
                        "외부 입력값이 HTML DOM에 "
                        "직접 삽입될 가능성이 있습니다.",
                    "recommendation":
                        "innerHTML 대신 textContent 등을 사용하고 "
                        "외부 입력값을 적절하게 인코딩하세요."
                })

        # ==========================================
        # 6. JSP 출력 XSS
        # ==========================================

        if extension == ".jsp":

            if re.search(
                r'<%=\s*[^%]+%>',
                line
            ):

                findings.append({
                    "type": "Cross-Site Scripting (XSS)",
                    "severity": "HIGH",
                    "file": file_name,
                    "line": line_number,
                    "evidence": line.strip(),
                    "description":
                        "JSP에서 값을 HTML escaping 없이 "
                        "직접 출력할 가능성이 있습니다.",
                    "recommendation":
                        "출력 시 HTML escaping을 적용하고 "
                        "사용자 입력값을 직접 출력하지 마세요."
                })

    return findings
