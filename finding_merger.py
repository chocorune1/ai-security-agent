def merge_findings(rule_findings, ai_result):
    """
    Rule Scanner와 Qwen AI 결과를 통합한다.

    기본 원칙:
    1. Qwen이 Finding을 반환하면 AI가 취약점으로 판단한 것으로 간주
    2. AI가 명시적으로 FALSE_POSITIVE라고 판단한 경우 제외
    3. Rule + AI가 같은 취약점을 가리키면 CONFIRMED
    4. AI가 status/confidence를 반환하지 않는 경우
       기본값을 CONFIRMED / HIGH로 사용
    """

    merged = []

    ai_findings = ai_result.get(
        "findings",
        []
    )

    # =====================================
    # 1. AI Finding 등록
    # =====================================

    for finding in ai_findings:

        status = finding.get("status")

        confidence = finding.get("confidence")

        # AI가 명시적으로 오탐이라고 판단한 경우
        if status == "FALSE_POSITIVE":
            continue

        # 현재 Qwen 모델이 status를 반환하지 않는 경우
        if status is None:
            status = "CONFIRMED"

        if confidence is None:
            confidence = "HIGH"

        merged.append({
            "type": finding.get("type"),
            "severity": finding.get("severity"),
            "line": finding.get("line"),
            "evidence": finding.get("evidence"),
            "description": finding.get("description"),
            "reason": finding.get(
                "reason",
                "Qwen AI가 해당 코드에서 "
                "보안 취약점을 확인했습니다."
            ),
            "recommendation": finding.get(
                "recommendation"
            ),
            "source": "AI",
            "confidence": confidence,
            "status": status
        })

    # =====================================
    # 2. Rule Scanner 결과와 AI 결과 비교
    # =====================================

    for rule in rule_findings:

        matched = False

        for finding in merged:

            # 취약점 유형 확인
            if finding["type"] != rule["type"]:
                continue

            # 라인 번호 확인
            try:
                ai_line = int(finding["line"])
                rule_line = int(rule["line"])
            except (TypeError, ValueError):
                continue

            if abs(ai_line - rule_line) <= 2:

                matched = True

                # Rule + AI로 탐지
                finding["source"] = "RULE + AI"

                # 두 분석기가 모두 동일한 취약점을 확인
                finding["status"] = "CONFIRMED"

                # Rule + AI 일치이므로 높은 신뢰도
                finding["confidence"] = "HIGH"

                break

        # =================================
        # 3. Rule만 발견된 경우
        # =================================

        if not matched:

            merged.append({
                "type": rule["type"],
                "severity": rule["severity"],
                "line": rule["line"],
                "evidence": rule["evidence"],
                "description": rule["description"],
                "reason":
                    "Rule Scanner에서 의심 패턴이 "
                    "탐지되었으나 AI 분석과 매칭되지 않았습니다.",
                "recommendation": rule["recommendation"],
                "source": "RULE",
                "confidence": "LOW",
                "status": "REVIEW_REQUIRED"
            })

    return merged
