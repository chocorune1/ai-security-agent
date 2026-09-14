def merge_findings(
    rule_findings,
    ai_result,
    validation_results
):
    """
    Rule Scanner + Qwen 분석 + Qwen 검증 결과를 통합한다.

    핵심 기능:
    1. Qwen 결과의 파일명이 비어 있으면 Rule Scanner 결과로 보완
    2. Qwen 결과의 line이 비어 있으면 Rule Scanner 결과로 보완
    3. Rule + AI가 같은 취약점을 찾으면 하나로 통합
    4. Qwen 검증 결과가 SAFE이면 Rule 결과를 제외
    5. 최종 결과에는 가능한 한 file / line / detection을 항상 표시
    """

    merged = []

    if not isinstance(rule_findings, list):
        rule_findings = []

    if not isinstance(ai_result, list):
        ai_result = []

    if not isinstance(validation_results, list):
        validation_results = []

    # ==================================================
    # 1. Qwen 검증 결과를 빠르게 찾기 위한 함수
    # ==================================================

    def find_validation(rule):

        rule_type = rule.get("type")
        rule_file = rule.get("file", "")
        rule_line = rule.get("line")

        for validation in validation_results:

            if not isinstance(validation, dict):
                continue

            validation_type = validation.get("type")
            validation_file = validation.get("file", "")
            validation_line = validation.get("line")

            # type 비교
            if (
                validation_type
                and rule_type
                and validation_type != rule_type
            ):
                continue

            # 파일명이 둘 다 있으면 비교
            if (
                validation_file
                and rule_file
                and validation_file != rule_file
            ):
                continue

            # line 비교
            if (
                validation_line is not None
                and rule_line is not None
            ):
                try:
                    if int(validation_line) != int(rule_line):
                        continue
                except (TypeError, ValueError):
                    continue

            return validation

        return None

    # ==================================================
    # 2. Qwen 결과와 Rule 결과를 매칭하는 함수
    # ==================================================

    def find_matching_rule(ai_finding):

        ai_type = ai_finding.get("type")
        ai_file = ai_finding.get("file", "")
        ai_line = ai_finding.get("line")

        candidates = []

        for rule in rule_findings:

            if not isinstance(rule, dict):
                continue

            if rule.get("type") != ai_type:
                continue

            rule_file = rule.get("file", "")
            rule_line = rule.get("line")

            # 파일명이 Qwen 결과에 있는 경우
            # 파일명이 같은 것만 후보로 사용
            if (
                ai_file
                and rule_file
                and ai_file != rule_file
            ):
                continue

            # line이 둘 다 있는 경우
            if (
                ai_line is not None
                and rule_line is not None
            ):
                try:
                    distance = abs(
                        int(ai_line) - int(rule_line)
                    )
                except (TypeError, ValueError):
                    continue

                if distance <= 2:
                    candidates.append(
                        (distance, rule)
                    )

            else:
                candidates.append(
                    (999, rule)
                )

        if not candidates:
            return None

        # 가장 가까운 line을 선택
        candidates.sort(
            key=lambda item: item[0]
        )

        return candidates[0][1]

    # ==================================================
    # 3. Qwen 분석 결과 처리
    # ==================================================

    matched_rule_indexes = set()

    for ai_finding in ai_result:

        if not isinstance(ai_finding, dict):
            continue

        finding_type = ai_finding.get("type")

        if not finding_type:
            continue

        status = ai_finding.get(
            "status",
            "CONFIRMED"
        )

        confidence = ai_finding.get(
            "confidence",
            "HIGH"
        )

        # FALSE_POSITIVE 제외
        if status == "FALSE_POSITIVE":
            continue

        # ----------------------------------------------
        # Rule 결과와 매칭
        # ----------------------------------------------

        matching_rule = find_matching_rule(
            ai_finding
        )

        # ----------------------------------------------
        # 파일명 보완
        # ----------------------------------------------

        ai_file = ai_finding.get(
            "file",
            ""
        )

        if not ai_file and matching_rule:
            ai_file = matching_rule.get(
                "file",
                ""
            )

        # ----------------------------------------------
        # line 보완
        # ----------------------------------------------

        ai_line = ai_finding.get(
            "line"
        )

        if ai_line is None and matching_rule:
            ai_line = matching_rule.get(
                "line"
            )

        # ----------------------------------------------
        # evidence 보완
        # ----------------------------------------------

        evidence = ai_finding.get(
            "evidence",
            ""
        )

        if not evidence and matching_rule:
            evidence = matching_rule.get(
                "evidence",
                ""
            )

        # ----------------------------------------------
        # severity 보완
        # ----------------------------------------------

        severity = ai_finding.get(
            "severity"
        )

        if not severity and matching_rule:
            severity = matching_rule.get(
                "severity",
                "MEDIUM"
            )

        # ----------------------------------------------
        # description 보완
        # ----------------------------------------------

        description = ai_finding.get(
            "description",
            ""
        )

        if not description and matching_rule:
            description = matching_rule.get(
                "description",
                ""
            )

        # ----------------------------------------------
        # recommendation 보완
        # ----------------------------------------------

        recommendation = ai_finding.get(
            "recommendation",
            ""
        )

        if (
            not recommendation
            and matching_rule
        ):
            recommendation = matching_rule.get(
                "recommendation",
                ""
            )

        # ----------------------------------------------
        # reason
        # ----------------------------------------------

        reason = ai_finding.get(
            "reason",
            "Qwen AI가 보안 취약점을 확인했습니다."
        )

        # ----------------------------------------------
        # detection
        # ----------------------------------------------

        if matching_rule:

            detection = "RULE + AI"

            matched_rule_indexes.add(
                rule_findings.index(
                    matching_rule
                )
            )

            status = "CONFIRMED"
            confidence = "HIGH"

        else:

            detection = "AI"

        # ----------------------------------------------
        # 최종 결과 추가
        # ----------------------------------------------

        merged.append({
            "type": finding_type,
            "severity": severity or "MEDIUM",
            "file": ai_file,
            "line": ai_line,
            "evidence": evidence,
            "description": description,
            "reason": reason,
            "recommendation": recommendation,
            "detection": detection,
            "confidence": confidence,
            "status": status
        })

    # ==================================================
    # 4. Rule Scanner 결과 처리
    # ==================================================

    for index, rule in enumerate(rule_findings):

        if not isinstance(rule, dict):
            continue

        rule_type = rule.get("type")
        rule_file = rule.get(
            "file",
            ""
        )
        rule_line = rule.get("line")

        if not rule_type:
            continue

        # ----------------------------------------------
        # 이미 AI와 매칭된 Rule이면 skip
        # ----------------------------------------------

        if index in matched_rule_indexes:
            continue

        # ----------------------------------------------
        # Qwen 검증 결과 확인
        # ----------------------------------------------

        validation = find_validation(rule)

        if validation:

            validation_status = validation.get(
                "status"
            )

            # Qwen이 안전하다고 판단
            if validation_status == "SAFE":

                print(
                    f"[제외] "
                    f"{rule_type} "
                    f"{rule_file}:"
                    f"{rule_line} "
                    f"→ Qwen SAFE"
                )

                continue

        # ----------------------------------------------
        # Rule만 탐지된 경우
        # ----------------------------------------------

        if validation:

            status = validation.get(
                "status",
                "REVIEW"
            )

            if status == "REVIEW":
                final_status = "REVIEW_REQUIRED"
                confidence = "LOW"
                reason = validation.get(
                    "reason",
                    "Qwen이 추가 검토가 필요하다고 판단했습니다."
                )

            else:
                final_status = "REVIEW_REQUIRED"
                confidence = "LOW"
                reason = validation.get(
                    "reason",
                    "Rule Scanner에서 의심 패턴이 탐지되었습니다."
                )

        else:

            final_status = "REVIEW_REQUIRED"
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
            "status": final_status
        })

    # ==================================================
    # 5. 최종 결과 정리
    # ==================================================

    # 파일명이 비어 있는 결과가 있는지 확인
    for finding in merged:

        if not finding.get("file"):
            finding["file"] = "UNKNOWN"

        if finding.get("line") is None:
            finding["line"] = "-"

    return merged
