def _normalize(value):
    if value is None:
        return ""
    return str(value).strip().lower()


def _canonical_type(value):
    value = _normalize(value)
    if not value:
        return ""
    if "cross-site scripting" in value or value == "xss" or "dom xss" in value:
        return "xss"
    if "dangerous eval" in value or ("code injection" in value and "eval" in value) or value in {"eval", "javascript eval"}:
        return "eval"
    if "sql injection" in value:
        return "sql injection"
    if "command injection" in value:
        return "command injection"
    if "hard-coded credential" in value or "hardcoded credential" in value or "hard coded credential" in value:
        return "hard-coded credential"
    if "path traversal" in value:
        return "path traversal"
    return value


def _is_same_finding(a, b):
    if _normalize(a.get("file")) != _normalize(b.get("file")):
        return False
    if _canonical_type(a.get("type")) != _canonical_type(b.get("type")):
        return False
    line1, line2 = a.get("line"), b.get("line")
    if line1 is None or line2 is None:
        return True
    try:
        return abs(int(line1) - int(line2)) <= 2
    except (ValueError, TypeError):
        return True


def _find_matching(findings, target):
    for finding in findings:
        if _is_same_finding(finding, target):
            return finding
    return None


def _severity_rank(value):
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(_normalize(value).upper(), 0)


def _confidence_rank(value):
    return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(_normalize(value).upper(), 0)


def _merge_detail_fields(target, source):
    # AI가 생성한 수정 전/후 코드도 최종 Finding까지 보존합니다.
    for field in [
        "evidence",
        "description",
        "reason",
        "recommendation",
        "validation_reason",
        "vulnerable_code",
        "fixed_code",
    ]:
        value = source.get(field)
        if value and not target.get(field):
            target[field] = value
        elif value and field in {"vulnerable_code", "fixed_code"}:
            # AI 분석 결과가 있으면 코드 예시는 최신 AI 결과를 사용합니다.
            target[field] = value

    if source.get("severity") and _severity_rank(source.get("severity")) > _severity_rank(target.get("severity")):
        target["severity"] = source.get("severity")
    if source.get("confidence") and _confidence_rank(source.get("confidence")) > _confidence_rank(target.get("confidence")):
        target["confidence"] = source.get("confidence")
    if source.get("line") is not None:
        target["line"] = source.get("line")


def merge_findings(rule_findings, ai_results, validation_results):
    final_findings = []
    safe_validations = []
    vulnerable_validations = []
    review_validations = []

    for validation in validation_results:
        if not isinstance(validation, dict):
            continue
        status = (validation.get("status") or "REVIEW").upper()
        if status == "SAFE":
            safe_validations.append(validation)
        elif status == "VULNERABLE":
            vulnerable_validations.append(validation)
        else:
            review_validations.append(validation)

    for rule in rule_findings:
        if not isinstance(rule, dict):
            continue
        if _find_matching(safe_validations, rule):
            print(f"  [제외] {rule.get('type')} / {rule.get('file')}:{rule.get('line')} → AI 검증 SAFE")
            continue

        merged = dict(rule)
        merged["detection"] = "RULE"
        merged["status"] = "REVIEW_REQUIRED"
        merged["confidence"] = "LOW"

        validation = _find_matching(vulnerable_validations, rule)
        if validation:
            merged["status"] = "CONFIRMED"
            merged["detection"] = "RULE + AI"
            merged["confidence"] = validation.get("confidence") or "HIGH"
            merged["validation_reason"] = validation.get("reason")
        else:
            validation = _find_matching(review_validations, rule)
            if validation:
                merged["status"] = "REVIEW_REQUIRED"
                merged["detection"] = "RULE + AI"
                merged["confidence"] = validation.get("confidence") or "MEDIUM"
                merged["validation_reason"] = validation.get("reason")

        final_findings.append(merged)

    for ai in ai_results:
        if not isinstance(ai, dict):
            continue
        ai_status = (ai.get("status") or "REVIEW").upper()
        if ai_status == "SAFE":
            continue
        if _find_matching(safe_validations, ai):
            print(f"  [제외] {ai.get('type')} / {ai.get('file')}:{ai.get('line')} → 기존 AI 검증 SAFE")
            continue

        matched = _find_matching(final_findings, ai)
        if matched:
            matched["detection"] = "RULE + AI"
            if ai_status == "VULNERABLE":
                matched["status"] = "CONFIRMED"
            elif ai_status == "REVIEW" and matched.get("status") not in {"CONFIRMED", "AI_CONFIRMED"}:
                matched["status"] = "REVIEW_REQUIRED"
            _merge_detail_fields(matched, ai)
            continue

        new_finding = dict(ai)
        new_finding["status"] = "AI_CONFIRMED" if ai_status == "VULNERABLE" else "AI_REVIEW_REQUIRED"
        new_finding["detection"] = "AI"
        final_findings.append(new_finding)

    deduplicated = []
    for finding in final_findings:
        matched = _find_matching(deduplicated, finding)
        if matched is None:
            deduplicated.append(finding)
            continue
        _merge_detail_fields(matched, finding)
        current = matched.get("status") or ""
        new = finding.get("status") or ""
        if new in {"CONFIRMED", "AI_CONFIRMED"} and current not in {"CONFIRMED", "AI_CONFIRMED"}:
            matched["status"] = new
        if finding.get("detection") == "RULE + AI":
            matched["detection"] = "RULE + AI"

    return deduplicated
