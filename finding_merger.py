def merge_findings(rule_findings, ai_result):
    """
    Rule Scanner와 Qwen AI 분석 결과를 통합한다.

    AI가 CONFIRMED로 판단한 취약점은 최종 결과에 포함한다.
    FALSE_POSITIVE는 제외한다.
    REVIEW_REQUIRED는 검토 필요 상태로 포함한다.
    """

    merged = []

    ai_findings = ai_result.get(
        "findings",
        []
    )

    # --------------------------------
    # 1. AI 결과 처리
    # --------------------------------

    for finding in ai_findings:

        status = finding.get(
            "status",
            "REVIEW_REQUIRED"
        )

        confidence = finding.get(
            "confidence",
            "LOW"
        )

        # FALSE_POSITIVE는 최종 결과에서 제외
        if status == "FALSE_POSITIVE":
            continue

        merged.append({
            "type": finding.get("type"),
            "severity": finding.get("severity"),
            "line": finding.get("line"),
            "evidence": finding.get("evidence"),
            "description": finding.get("description"),
            "reason": finding.get("reason"),
            "recommendation": finding.get("recommendation"),
            "source": "AI",
            "confidence": confidence,
            "status": status
        })

    # --------------------------------
    # 2. Rule Scanner 결과 처리
    # --------------------------------

    for rule in rule_findings:

        matched = False

        for ai in ai_findings:

            ai_type = ai.get("type")
            ai_line = ai.get("line")

            if ai_type != rule["type"]:
                continue

            try:
                line_difference = abs(
                    int(ai_line) -
                    int(rule["line"])
                )
            except (TypeError, ValueError):
                continue

            if line_difference <= 2:

                matched = True

                # AI가 FALSE_POSITIVE로 판단
                # → Rule 결과도 제외
                if ai.get("status") == "FALSE_POSITIVE":
                    break

                # AI가 확인
                if ai.get("status") == "CONFIRMED":

                    for merged_finding in merged:

                        if (
                            merged_finding["type"]
                            == rule["type"]
                            and
                            abs(
                                int(
                                    merged_finding["line"]
                                )
                                -
                                int(rule["line"])
                            ) <= 2
                        ):
                            merged_finding["source"] = (
                                "RULE + AI"
                            )

                            merged_finding["confidence"] = (
                                ai.get(
                                    "confidence",
                                    "MEDIUM"
                                )
                            )

                            merged_finding["status"] = (
                                "CONFIRMED"
                            )

                break

        # --------------------------------
        # AI에서 매칭되지 않은 Rule 결과
        # --------------------------------

        if not matched:

            merged.append({
                "type": rule["type"],
                "severity": rule["severity"],
                "line": rule["line"],
                "evidence": rule["evidence"],
                "description": rule["description"],
                "reason":
                    "Rule Scanner에서 의심 패턴이 탐지되었으나 "
                    "AI 분석 결과와 매칭되지 않았습니다.",
                "recommendation":
                    rule["recommendation"],
                "source": "RULE",
                "confidence": "LOW",
                "status": "REVIEW_REQUIRED"
            })

    return merged
