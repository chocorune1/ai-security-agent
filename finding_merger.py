def merge_findings(rule_findings, ai_result):
    """
    Rule Scanner와 Qwen AI 분석 결과를 하나의
    표준 Finding 목록으로 통합한다.
    """

    merged = []

    ai_findings = ai_result.get("findings", [])

    # -----------------------------------
    # AI 결과를 기준으로 먼저 등록
    # -----------------------------------

    for finding in ai_findings:

        merged.append({
            "type": finding.get("type"),
            "severity": finding.get("severity"),
            "line": finding.get("line"),
            "evidence": finding.get("evidence"),
            "description": finding.get("description"),
            "reason": finding.get("reason"),
            "recommendation": finding.get("recommendation"),
            "source": "AI",
            "confidence": "HIGH",
            "status": "CONFIRMED"
        })

    # -----------------------------------
    # Rule 결과 중 AI에서 발견하지 못한 것
    # 추가
    # -----------------------------------

    for rule in rule_findings:

        exists = False

        for ai in ai_findings:

            if (
                ai.get("type") == rule["type"]
                and abs(
                    int(ai.get("line", 0)) -
                    int(rule["line"])
                ) <= 2
            ):
                exists = True
                break

        if exists:
            # Rule + AI 모두 발견
            for merged_finding in merged:

                if (
                    merged_finding["type"] == rule["type"]
                    and abs(
                        int(merged_finding["line"]) -
                        int(rule["line"])
                    ) <= 2
                ):
                    merged_finding["source"] = "RULE + AI"
                    merged_finding["confidence"] = "HIGH"

        else:
            # Rule에서만 발견
            merged.append({
                "type": rule["type"],
                "severity": rule["severity"],
                "line": rule["line"],
                "evidence": rule["evidence"],
                "description": rule["description"],
                "reason": "Rule Scanner에서 의심 패턴이 탐지되었습니다.",
                "recommendation": rule["recommendation"],
                "source": "RULE",
                "confidence": "MEDIUM",
                "status": "REVIEW_REQUIRED"
            })

    return merged
