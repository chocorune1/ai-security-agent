def merge_findings(
    rule_findings,
    ai_result,
    validation_results
):
    """
    Rule Scanner + Qwen 분석 + Qwen 검증 결과를 통합한다.

    입력:
    - rule_findings: Rule Scanner 결과 list
    - ai_result: Qwen 분석 결과 list
    - validation_results: Qwen 검증 결과 list

    출력:
    - 최종 통합 취약점 결과 list
    """

    merged = []

    # ==================================================
    # 0. 입력값 안전 처리
    # ==================================================

    if not isinstance(rule_findings, list):
        rule_findings = []

    if not isinstance(ai_result, list):
        ai_result = []

    if not isinstance(validation_results, list):
        validation_results = []

    # ==================================================
    # 1. AI 분석 결과 처리
    # ==================================================

    for finding in ai_result:

        if not isinstance(finding, dict):
            continue

        finding_type = finding.get("type")

        if not finding_type:
            continue

        status = finding.get(
            "status",
            "CONFIRMED"
        )

        confidence = finding.get(
            "confidence",
            "HIGH"
        )

        # FALSE_POSITIVE는 제외
        if status == "FALSE_POSITIVE":
            continue

        merged.append({
            "type": finding_type,
            "severity": finding.get(
                "severity",
                "MEDIUM"
            ),
            "file": finding.get(
                "file",
                ""
            ),
            "line": finding.get(
                "line"
            ),
            "evidence": finding.get(
                "evidence",
                ""
            ),
            "description": finding.get(
                "description",
                ""
            ),
            "reason": finding.get(
                "reason",
                "Qwen AI가 보안 취약점을 확인했습니다."
            ),
            "recommendation": finding.get(
                "recommendation",
                ""
            ),
            "detection": "AI",
            "confidence": confidence,
            "status": status
        })

    # ==================================================
    # 2. Rule Finding 처리
    # ==================================================

    for rule in rule_findings:

        if not isinstance(rule, dict):
            continue

        rule_type = rule.get("type")
        rule_line = rule.get("line")
        rule_file = rule.get(
            "file",
            ""
        )

        if not rule_type:
            continue

        # ==================================================
        # 2-1. Qwen 검증 결과 찾기
        # ==================================================

        validation = None

        for result in validation_results:

            if not isinstance(result, dict):
                continue

            result_type = result.get("type")
            result_line = result.get("line")
            result_file = result.get(
                "file",
                ""
            )

            if not result_type:
                continue

            if result_type != rule_type:
                continue

            # 파일명이 있으면 파일도 비교
            if (
                result_file
                and
                rule_file
                and
                result_file != rule_file
            ):
                continue

            # line 비교
            try:

                if (
                    result_line is not None
                    and
                    rule_line is not None
                    and
                    int(result_line) == int(rule_line)
                ):
                    validation = result
                    break

            except (TypeError, ValueError):
                continue

        # ==================================================
        # 2-2. Qwen이 SAFE라고 판단
        # ==================================================

        if validation:

            validation_status = validation.get(
                "status"
            )

            if validation_status == "SAFE":

                print(
                    f"[제외] "
                    f"{rule_type} "
                    f"{rule_file}:"
                    f"{rule_line} "
                    f"→ Qwen SAFE"
                )

                continue

        # ==================================================
        # 2-3. AI 분석 결과와 Rule 결과 매칭
        # ==================================================

        matched = False

        for finding in merged:

            if not isinstance(finding, dict):
                continue

            if finding.get("type") != rule_type:
                continue

            # 파일명이 있으면 같은 파일인지 확인
            finding_file = finding.get(
                "file",
                ""
            )

            if (
                finding_file
                and
                rule_file
                and
                finding_file != rule_file
            ):
                continue

            try:

                ai_line = int(
                    finding.get("line")
                )

                current_rule_line = int(
                    rule_line
                )

            except (TypeError, ValueError):

                continue

            # 같은 취약점이고 ±2라인 이내
            if abs(
                ai_line - current_rule_line
            ) <= 2:

                matched = True

                finding["detection"] = "RULE + AI"

                finding["status"] = "CONFIRMED"

                finding["confidence"] = "HIGH"

                break

        # ==================================================
        # 2-4. AI와 매칭되지 않은 Rule
        # ==================================================

        if not matched:

            if (
                validation
                and
                validation.get("status") == "REVIEW"
            ):

                status = "REVIEW_REQUIRED"

                confidence = "LOW"

                reason = validation.get(
                    "reason",
                    "Qwen이 추가 검토가 필요하다고 판단했습니다."
                )

            else:

                status = "REVIEW_REQUIRED"

                confidence = "LOW"

                reason = (
                    "Rule Scanner에서 의심 패턴이 "
                    "탐지되었으나 AI 분석과 매칭되지 않았습니다."
                )

            merged.append({
                "type": rule_type,
                "severity": rule.get(
                    "severity",
                    "MEDIUM"
                ),
                "file": rule_file,
                "line": rule_line,
                "evidence": rule.get(
                    "evidence",
                    ""
                ),
                "description": rule.get(
                    "description",
                    ""
                ),
                "reason": reason,
                "recommendation": rule.get(
                    "recommendation",
                    ""
                ),
                "detection": "RULE",
                "confidence": confidence,
                "status": status
            })

    # ==================================================
    # 3. 최종 결과 반환
    # ==================================================

    return merged
