import re

def analyze_source(source):
    """
    Java / JavaScript / JSP 소스의 1차 Rule Scanner.
    최종 취약점 여부는 Qwen + Validation에서 판단한다.
    """
    findings = []
    content = source["content"]
    file_name = source["file_name"]
    extension = source["extension"]
    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):

        # 1. Hard-coded Credential
        if re.search(
            r'(password|passwd|pwd|secret|api[_-]?key)\s*=\s*["\'][^"\']+["\']',
            line, re.IGNORECASE
        ):
            findings.append({
                "type": "Hard-coded Credential", "severity": "HIGH",
                "file": file_name, "line": line_number,
                "evidence": line.strip(),
                "description": "소스코드에 비밀번호 또는 인증정보가 직접 포함되어 있습니다.",
                "recommendation": "인증정보를 소스코드에 저장하지 말고 환경변수 또는 Secret 관리 시스템을 사용하세요."
            })

        # 2. SQL Injection 후보
        if re.search(r'["\'].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*["\']',
                     line, re.IGNORECASE):
            findings.append({
                "type": "SQL Injection", "severity": "HIGH",
                "file": file_name, "line": line_number,
                "evidence": line.strip(),
                "description": "SQL 쿼리 문자열이 발견되었습니다. 외부 입력값이 안전하게 처리되는지 확인이 필요합니다.",
                "recommendation": "PreparedStatement 또는 parameterized query를 사용하고 사용자 입력값을 SQL 문자열에 직접 연결하지 마세요."
            })

        # 3. Command Injection
        if re.search(r'Runtime\.getRuntime\(\)\.exec\s*\(', line):
            findings.append({
                "type": "Command Injection", "severity": "CRITICAL",
                "file": file_name, "line": line_number,
                "evidence": line.strip(),
                "description": "외부 입력값이 운영체제 명령 실행에 사용될 가능성이 있습니다.",
                "recommendation": "외부 입력을 직접 명령 실행에 사용하지 말고 allowlist 기반 검증을 적용하세요."
            })

        # 4. JavaScript eval
        if extension == ".js" and re.search(r'\beval\s*\(', line):
            findings.append({
                "type": "Dangerous eval", "severity": "HIGH",
                "file": file_name, "line": line_number,
                "evidence": line.strip(),
                "description": "JavaScript eval()을 사용하면 문자열이 코드로 실행될 수 있습니다.",
                "recommendation": "eval() 사용을 제거하고 안전한 API를 사용하세요."
            })

        # 5. JavaScript DOM XSS
        if extension == ".js" and re.search(r'\.innerHTML\s*=', line):
            findings.append({
                "type": "Cross-Site Scripting (XSS)", "severity": "HIGH",
                "file": file_name, "line": line_number,
                "evidence": line.strip(),
                "description": "외부 입력값이 HTML DOM에 직접 삽입될 가능성이 있습니다.",
                "recommendation": "innerHTML 대신 textContent 등을 사용하고 외부 입력값을 적절하게 인코딩하세요."
            })

        # 6. JSP 출력 XSS
        if extension == ".jsp" and re.search(r'<%=\s*[^%]+%>', line):
            findings.append({
                "type": "Cross-Site Scripting (XSS)", "severity": "HIGH",
                "file": file_name, "line": line_number,
                "evidence": line.strip(),
                "description": "JSP에서 값을 HTML escaping 없이 직접 출력할 가능성이 있습니다.",
                "recommendation": "출력 시 HTML escaping을 적용하고 사용자 입력값을 직접 출력하지 마세요."
            })

        # 7. Path Traversal
        if extension == ".java" and re.search(
            r'\.resolve\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)', line
        ):
            findings.append({
                "type": "Path Traversal", "severity": "HIGH",
                "file": file_name, "line": line_number,
                "evidence": line.strip(),
                "description": "외부 입력으로 전달될 수 있는 파일명이 경로 검증 없이 파일 경로 생성에 사용될 가능성이 있습니다.",
                "recommendation": "경로를 normalize한 후 허용된 기준 경로 하위인지 검증하고 파일명 allowlist 검증을 적용하세요."
            })

        # 8. Insecure Deserialization
        if extension == ".java" and (
            re.search(r'\bObjectInputStream\b.*\b(readObject|readUnshared)\b', line)
            or re.search(r'\.\b(readObject|readUnshared)\s*\(', line)
        ):
            findings.append({
                "type": "Insecure Deserialization", "severity": "HIGH",
                "file": file_name, "line": line_number,
                "evidence": line.strip(),
                "description": "신뢰할 수 없는 데이터에 대해 Java 객체 역직렬화가 수행될 가능성이 있습니다.",
                "recommendation": "신뢰할 수 없는 입력에 Java 기본 역직렬화를 사용하지 말고 JSON 등 안전한 데이터 형식을 사용하세요."
            })

        # 9. CSRF 후보
        if extension == ".jsp" and re.search(
            r'<form\b[^>]*\bmethod\s*=\s*["\']post["\']', line, re.IGNORECASE
        ):
            findings.append({
                "type": "CSRF", "severity": "MEDIUM",
                "file": file_name, "line": line_number,
                "evidence": line.strip(),
                "description": "상태 변경에 사용될 수 있는 POST Form이 발견되었습니다. CSRF Token 등 서버 측 방어가 적용되었는지 확인이 필요합니다.",
                "recommendation": "서버 측에서 CSRF Token을 생성하고 요청마다 검증하며 SameSite Cookie 등 추가 방어수단을 적용하세요."
            })

        # 10. Sensitive Information Exposure in Logs
        if extension == ".java" and re.search(
            r'\b(log|logger)\s*\.\s*(trace|debug|info|warn|error)\s*\('
            r'.*\b(password|passwd|pwd|secret|token|api[_-]?key)\b',
            line, re.IGNORECASE
        ):
            findings.append({
                "type": "Sensitive Information Exposure in Logs", "severity": "MEDIUM",
                "file": file_name, "line": line_number,
                "evidence": line.strip(),
                "description": "비밀번호, 토큰, Secret 등의 민감정보가 로그에 기록될 가능성이 있습니다.",
                "recommendation": "민감정보를 로그에 기록하지 말고 필요한 경우 마스킹 또는 비식별화하여 기록하세요."
            })

    return findings
