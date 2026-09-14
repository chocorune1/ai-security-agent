def merge_findings(rule_findings, ai_result):
    """
    Rule Scanner와 Qwen AI 분석 결과를 통합한다.

    - AI가 FALSE_POSITIVE로 판단하면 제외
    - Rule + AI가 같은 취약점을 확인하면 CONFIRMED
    - AI가 status를 누락해도 Rule과 매칭되면 CONFIRMED
    - AI와 Rule이 매칭되지 않으면 REVIEW_REQUIRED
    """

    merged = []

    ai_findings = ai_result.get(
        "findings",
        []
    )

    # =================================
    # 1. AI 결과 처리
    # =================================

    for finding in ai_findings:

        status = finding.get("status")

        confidence = finding.get("confidence")

        # AI가 명시적으로 오탐이라고 판단
        if status == "FALSE_POSITIVE":
            continue

        # status가 없으면 일단 REVIEW_REQUIRED
        if status not in [
            "CONFIRMED",
            "FALSE_POSITIVE",
            "REVIEW_REQUIRED"
        ]:
            status = "REVIEW_REQUIRED"

        if confidence not in [
            "HIGH",
            "MEDIUM",
            "LOW"
        ]:
            confidence = "LOW"

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

    # =================================
    # 2. Rule Scanner 결과와 비교
    # =================================

    for rule in rule_findings:

        matched_ai = None

        for ai in ai_findings:

            if ai.get("type") != rule["type"]:
                continue

            try:
                ai_line = int(ai.get("line", 0))
                rule_line = int(rule["line"])

                line_difference = abs(
                    ai_line - rule_line
                )

            except (TypeError, ValueError):

                continue

            if line_difference <= 2:

                matched_ai = ai
                break

        # =================================
        # 3. Rule + AI 매칭
        # =================================

        if matched_ai:

            # -----------------------------
            # AI가 명시적으로 FALSE_POSITIVE
            # -----------------------------

            if matched_ai.get("status") == "FALSE_POSITIVE":
                continue

            # -----------------------------
            # 기존 merged finding 찾기
            # -----------------------------

            target = None

            for finding in merged:

                try:
                    line_difference = abs(
                        int(finding["line"])
                        -
                        int(rule["line"])
                    )
                except (TypeError, ValueError):
                    continue

                if (
                    finding["type"] == rule["type"]
                    and line_difference <= 2
                ):
                    target = finding
                    break

            # -----------------------------
            # Rule + AI 일치
            # -----------------------------

            if target:

                target["source"] = "RULE + AI"

                # AI가 명시적으로 CONFIRMED
                if matched_ai.get("status") == "CONFIRMED":

                    target["status"] = "CONFIRMED"

                    target["confidence"] = (
                        matched_ai.get(
                            "confidence",
                            "HIGH"
                        )
                    )

                # AI가 status를 누락한 경우
                else:

                    target["status"] = "CONFIRMED"

                    target["confidence"] = "HIGH"

        # =================================
        # 4. Rule만 발견된 경우
        # =================================

        else:

            merged.append({
                "type": rule["type"],
                "severity": rule["severity"],
                "line": rule["line"],
                "evidence": rule["evidence"],
                "description": rule["description"],
                "reason":
                    "Rule Scanner에서 의심 패턴이 "
                    "탐지되었지만 AI 분석과 매칭되지 않았습니다.",
                "recommendation":
                    rule["recommendation"],
                "source": "RULE",
                "confidence": "LOW",
                "status": "REVIEW_REQUIRED"
            })

    return merged
