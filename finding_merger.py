def merge_findings(
    rule_findings,
    ai_result,
    validation_results
):
    """
    Rule Scanner + Qwen 분석 + Qwen 검증 결과를 통합한다.
    """

    merged = []

    ai_findings = ai_result.get(
        "findings",
        []
    )

    # =====================================
    # 1. AI 분석 결과
    # =====================================

    for finding in ai_findings:

        status = finding.get(
            "status"
        )

        confidence = finding.get(
            "confidence"
        )

        # 명시적인 FALSE_POSITIVE
        if status == "FALSE_POSITIVE":
            continue

        # 현재 Qwen이 status를 반환하지 않는 경우
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
                "Qwen AI가 보안 취약점을 확인했습니다."
            ),
            "recommendation": finding.get(
                "recommendation"
            ),
            "source": "AI",
            "confidence": confidence,
            "status": status
        })

    # =====================================
    # 2. Rule Finding 처리
    # =====================================

    for rule in rule_findings:

        # ---------------------------------
        # Qwen 검증 결과 찾기
        # ---------------------------------

        validation = None

        for result in validation_results:

            if (
                result["type"] == rule["type"]
                and
                result["line"] == rule["line"]
            ):
                validation = result
                break

        # =================================
        # Qwen이 SAFE라고 판단
        # =================================

        if validation:

            if validation["status"] == "SAFE":

                print(
                    f"[제외] "
                    f"{rule['type']} "
                    f"라인 {rule['line']} "
                    f"→ Qwen SAFE"
                )

                continue

        # =================================
        # AI 분석과 Rule 결과 매칭
        # =================================

        matched = False

        for finding in merged:

            if finding["type"] != rule["type"]:
                continue

            try:
                ai_line = int(
                    finding["line"]
                )

                rule_line = int(
                    rule["line"]
                )

            except (TypeError, ValueError):
                continue

            if abs(ai_line - rule_line) <= 2:

                matched = True

                finding["source"] = "RULE + AI"

                finding["status"] = "CONFIRMED"

                finding["confidence"] = "HIGH"

                break

        # =================================
        # AI와 매칭되지 않은 Rule
        # =================================

        if not matched:

            # Qwen이 REVIEW라고 판단
            if (
                validation
                and
                validation["status"] == "REVIEW"
            ):

                status = "REVIEW_REQUIRED"
                confidence = "LOW"
                reason = validation["reason"]

            else:

                status = "REVIEW_REQUIRED"
                confidence = "LOW"
                reason = (
                    "Rule Scanner에서 의심 패턴이 "
                    "탐지되었으나 AI 분석과 매칭되지 않았습니다."
                )

            merged.append({
                "type": rule["type"],
                "severity": rule["severity"],
                "line": rule["line"],
                "evidence": rule["evidence"],
                "description": rule["description"],
                "reason": reason,
                "recommendation":
                    rule["recommendation"],
                "source": "RULE",
                "confidence": confidence,
                "status": status
            })

    return merged
