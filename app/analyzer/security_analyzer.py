import json
import re

from llm.qwen_client import ask_qwen
from rag.knowledge_store import search_knowledge


RAG_QUERY_TERMS = {
    "sql injection": ["SQL Injection", "CWE-89", "parameterized query", "PreparedStatement"],
    "command injection": ["Command Injection", "CWE-78", "OS command", "Runtime exec", "ProcessBuilder"],
    "xss": ["XSS", "Cross-site Scripting", "CWE-79", "output encoding", "innerHTML"],
    "dom xss": ["DOM XSS", "CWE-79", "innerHTML", "textContent"],
    "dangerous eval": ["Code Injection", "eval", "CWE-79"],
    "eval": ["Code Injection", "eval", "CWE-79"],
    "path traversal": ["Path Traversal", "CWE-22", "pathname", "file download"],
    "hard-coded credential": ["Hard-coded Credentials", "CWE-798", "password", "secret", "API key"],
    "hardcoded credential": ["Hard-coded Credentials", "CWE-798", "password", "secret", "API key"],
    "file upload": ["Unrestricted File Upload", "CWE-434", "file upload", "dangerous file type"],
    "csrf": ["CSRF", "CWE-352", "Cross-Site Request Forgery", "CSRF token"],
    "ssrf": ["SSRF", "CWE-918", "Server-Side Request Forgery", "server-side request"],
    "authorization": ["Missing Authorization", "CWE-862", "access control", "authorization"],
}


def _clean_json_response(text):
    if not text:
        return None
    text = re.sub(r"^```(?:json)?\s*", "", text.strip(), flags=re.I)
    text = re.sub(r"\s*```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for left, right in (("{", "}"), ("[", "]")):
        start, end = text.find(left), text.rfind(right)
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                pass
    return None


def _normalize_findings(result, source):
    findings = result.get("findings", []) if isinstance(result, dict) else result if isinstance(result, list) else []
    if not isinstance(findings, list):
        return []
    normalized = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        item = dict(finding)
        item["file"] = item.get("file") or source.get("file_name")
        item["type"] = item.get("type") or "Unknown"
        item["severity"] = item.get("severity") or "Medium"
        item["status"] = (item.get("status") or "REVIEW").upper()
        item["confidence"] = (item.get("confidence") or "MEDIUM").upper()
        if item.get("line") is None:
            item["line"] = _find_line_from_rule(item, source)
        normalized.append(item)
    return normalized


def _find_line_from_rule(finding, source):
    evidence = str(finding.get("evidence") or "").strip()
    if not evidence:
        return None
    for index, line in enumerate(source.get("content", "").splitlines(), 1):
        if evidence in line:
            return index
    return None


def _expanded_rag_query(finding, extension):
    finding_type = str(finding.get("type") or "").strip()
    normalized = finding_type.lower()
    terms = [finding_type]
    for key, extra in RAG_QUERY_TERMS.items():
        if key in normalized:
            terms.extend(extra)
    if extension:
        terms.append(str(extension))
    return " ".join(dict.fromkeys(t for t in terms if t))


def _extract_rag_items(result):
    if not isinstance(result, dict):
        return []
    docs = result.get("documents") or []
    metas = result.get("metadatas") or []
    distances = result.get("distances") or []
    docs = docs[0] if docs and isinstance(docs[0], list) else []
    metas = metas[0] if metas and isinstance(metas[0], list) else []
    distances = distances[0] if distances and isinstance(distances[0], list) else []
    items = []
    for i, doc in enumerate(docs):
        meta = metas[i] if i < len(metas) and isinstance(metas[i], dict) else {}
        items.append({
            "document": doc,
            "source": meta.get("source", "unknown"),
            "category": meta.get("category", "general"),
            "distance": distances[i] if i < len(distances) else None,
        })
    return items


def build_rag_context(source, rule_findings):
    """Rule 유형별로 RAG를 검색하고 CWE/OWASP 근거를 Qwen 프롬프트에 전달합니다."""
    findings = rule_findings or [{"type": "source code security"}]
    collected, seen = [], set()
    for finding in findings:
        query = _expanded_rag_query(finding, source.get("extension"))
        try:
            result = search_knowledge(query, top_k=3)
        except Exception as e:
            print(f"  RAG 검색 오류: {e}")
            continue
        for item in _extract_rag_items(result):
            if item["source"] in seen:
                continue
            seen.add(item["source"])
            collected.append(item)
    if not collected:
        return "관련 보안 지식이 없습니다."
    parts = []
    for i, item in enumerate(collected[:6], 1):
        distance = item["distance"]
        similarity = f"{max(0.0, 1.0 - float(distance)):.3f}" if isinstance(distance, (int, float)) else "N/A"
        parts.append(
            f"[보안 지식 {i}]\n"
            f"출처: {item['source']}\n"
            f"분류: {item['category']}\n"
            f"검색 유사도(참고값): {similarity}\n"
            f"내용:\n{item['document']}"
        )
    return "\n\n".join(parts)


def analyze_with_qwen(source, rule_findings):
    file_name = source.get("file_name", "unknown")
    extension = source.get("extension", "")
    content = source.get("content", "")
    rag_context = build_rag_context(source, rule_findings)
    rule_text = json.dumps(rule_findings, ensure_ascii=False, indent=2)

    prompt = f"""
당신은 Java, JavaScript, JSP 소스코드 보안 취약점 분석 전문가입니다.

Rule Scanner 결과와 RAG 보안 지식을 참고하되 반드시 실제 소스코드와 데이터 흐름을 확인하십시오.
RAG 문서가 검색되었다는 이유만으로 취약점이라고 단정하지 마십시오.
실제 사용자 입력이 위험한 sink에 도달하고 방어조치가 부족한 경우에만 VULNERABLE을 사용하십시오.
확실하지 않으면 REVIEW, 보호조치가 확인되면 SAFE를 사용하십시오.
동일 코드 위치의 중복 finding은 하나로 통합하십시오.
VULNERABLE에는 실제 취약 코드를 설명하는 evidence와 실제 line을 제공하십시오.
recommendation은 RAG 문서를 참고하여 이 코드에 적용 가능한 구체적인 개선방법을 작성하십시오.

status는 VULNERABLE, SAFE, REVIEW 중 하나만 사용하십시오.
confidence는 HIGH, MEDIUM, LOW 중 하나만 사용하십시오.
severity는 Critical, High, Medium, Low 중 하나만 사용하십시오.

파일명: {file_name}
확장자: {extension}

Rule Scanner 탐지 결과:
{rule_text}

관련 보안 지식:
{rag_context}

분석 대상 소스코드:
--------------------
{content}
--------------------

반드시 JSON만 출력하십시오.
{{
  "file": "{file_name}",
  "findings": [
    {{
      "type": "SQL Injection",
      "severity": "High",
      "line": 10,
      "evidence": "실제 취약 코드",
      "description": "취약점 설명",
      "reason": "취약한 데이터 흐름과 판단 근거",
      "recommendation": "구체적인 개선 방법",
      "status": "VULNERABLE",
      "confidence": "HIGH"
    }}
  ]
}}
취약점이 없으면 findings를 빈 배열로 반환하십시오.
"""
    try:
        response = ask_qwen(prompt)
    except Exception as e:
        print(f"  Qwen 분석 오류: {e}")
        return []
    result = _clean_json_response(response)
    if result is None:
        print("  Qwen 응답을 JSON으로 변환하지 못했습니다.")
        return []
    return _normalize_findings(result, source)


def validate_rule_finding(source, finding):
    file_name = source.get("file_name", "unknown")
    content = source.get("content", "")
    finding_type = finding.get("type", "Unknown")
    line = finding.get("line")
    evidence = finding.get("evidence", "")

    prompt = f"""
당신은 소스코드 보안 취약점 검증 전문가입니다.
Rule Scanner가 발견한 finding을 전체 소스코드와 대조하여 검증하십시오.
실제 공격 가능한 데이터 흐름이 명확한 경우에만 VULNERABLE,
보호조치가 확인되면 SAFE, 판단에 필요한 정보가 부족하면 REVIEW입니다.
단순히 위험 API가 존재한다는 이유로 VULNERABLE로 판단하지 마십시오.

파일: {file_name}
취약점 유형: {finding_type}
탐지 라인: {line}
탐지 근거: {evidence}

전체 소스코드:
--------------------
{content}
--------------------

JSON만 출력하십시오.
{{
  "type": "{finding_type}",
  "file": "{file_name}",
  "line": {line if line is not None else "null"},
  "status": "VULNERABLE",
  "reason": "판정 근거",
  "confidence": "HIGH"
}}
status: VULNERABLE / SAFE / REVIEW
confidence: HIGH / MEDIUM / LOW
"""
    try:
        response = ask_qwen(prompt)
    except Exception as e:
        print(f"  Qwen 검증 오류: {e}")
        return {"type": finding_type, "file": file_name, "line": line, "status": "REVIEW", "reason": "AI 검증 실패", "confidence": "LOW"}
    result = _clean_json_response(response)
    if not isinstance(result, dict):
        return {"type": finding_type, "file": file_name, "line": line, "status": "REVIEW", "reason": "AI 응답 형식 오류", "confidence": "LOW"}
    status = (result.get("status") or "REVIEW").upper()
    if status not in {"VULNERABLE", "SAFE", "REVIEW"}:
        status = "REVIEW"
    confidence = (result.get("confidence") or "MEDIUM").upper()
    if confidence not in {"HIGH", "MEDIUM", "LOW"}:
        confidence = "MEDIUM"
    return {
        "type": result.get("type") or finding_type,
        "file": result.get("file") or file_name,
        "line": result.get("line") if result.get("line") is not None else line,
        "status": status,
        "reason": result.get("reason") or "AI 검증 결과",
        "confidence": confidence,
    }
