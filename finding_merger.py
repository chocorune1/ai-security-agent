def _normalize(value):
    if value is None:
        return ""

    return str(value).strip().lower()


def _same_file(finding1, finding2):
    return (
        _normalize(
            finding1.get("file")
        )
        == _normalize(
            finding2.get("file")
        )
    )


def _same_type(finding1, finding2):
    return (
        _normalize(
            finding1.get("type")
        )
        == _normalize(
            finding2.get("type")
        )
    )


def _line_close(finding1, finding2):
    line1 = finding1.get("line")
    line2 = finding2.get("line")

    if line1 is None or line2 is None:
        return True

    try:
        return abs(
            int(line1) - int(line2)
        ) <= 2
    except (ValueError, TypeError):
        return True


def _is_same_finding(finding1, finding2):
    """
    같은 파일 + 같은 취약점 유형 + 가까운 라인이면
    동일 취약점으로 판단합니다.
    """

    return (
        _same_file(
            finding1,
            finding2
        )
        and
        _same_type(
            finding1,
            finding2
        )
        and
        _line_close(
            finding1,
            finding2
        )
    )


def _severity_rank(severity):
    ranks = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }

    return ranks.get(
        _normalize(severity).upper(),
        0
    )


def _confidence_rank(confidence):
    ranks = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }

    return ranks.get(
        _normalize(confidence).upper(),
        0
    )


def _select_higher_severity(
    first,
    second
):
    if _severity_rank(
        second.get("severity")
    ) > _severity_rank(
        first.get("severity")
    ):
        first["severity"] = (
            second.get("severity")
        )

    return first


def _select_higher_confidence(
    first,
    second
):
    if _confidence_rank(
        second.get("confidence")
    ) > _confidence_rank(
        first.get("confidence")
    ):
        first["confidence"] = (
            second.get("confidence")
        )

    return first


def merge_findings(
    rule_findings,
    ai_results,
    validation_results
):
    """
    Rule / AI / Validation 결과를 통합합니다.

    핵심 원칙:

    1. Validation SAFE → 제외
    2. Validation VULNERABLE + Rule → CONFIRMED
    3. AI VULNERABLE + Rule → CONFIRMED
    4. AI REVIEW → REVIEW_REQUIRED
    5. 중복 결과 제거
    """

    final_findings = []

    # --------------------------------------------------
    # 1. Validation 결과를 먼저 확인
    # --------------------------------------------------

    validation_map = []

    for validation in validation_results:

        if not isinstance(
            validation,
            dict
        ):
            continue

        status = (
            validation.get("status")
            or "REVIEW"
        ).upper()

        validation_map.append(
            validation
        )

    # --------------------------------------------------
    # 2. Rule 결과 처리
    # --------------------------------------------------

    for rule in rule_findings:

        if not isinstance(
            rule,
            dict
        ):
            continue

        matched_validation = None

        for validation in validation_map:

            if _is_same_finding(
                rule,
                validation
            ):
                matched_validation = validation
                break

        # --------------------------------------------------
        # SAFE → False Positive 제거
        # --------------------------------------------------

        if matched_validation:

            validation_status = (
                matched_validation.get(
                    "status"
                )
                or "REVIEW"
            ).upper()

            if validation_status == "SAFE":

                print(
                    f"  [제외] "
                    f"{rule.get('type')} / "
                    f"{rule.get('file')}:"
                    f"{rule.get('line')} "
                    f"→ AI 검증 SAFE"
                )

                continue

        # --------------------------------------------------
        # Rule 기본 결과 생성
        # --------------------------------------------------

        merged = dict(rule)

        merged["detection"] = "RULE"

        merged["status"] = (
            "REVIEW_REQUIRED"
        )

        merged["confidence"] = "LOW"

        # --------------------------------------------------
        # Validation 결과 반영
        # --------------------------------------------------

        if matched_validation:

            validation_status = (
                matched_validation.get(
                    "status"
                )
                or "REVIEW"
            ).upper()

            validation_confidence = (
                matched_validation.get(
                    "confidence"
                )
                or "MEDIUM"
            ).upper()

            if validation_status == "VULNERABLE":

                merged["status"] = (
                    "CONFIRMED"
                )

                merged["detection"] = (
                    "RULE + AI"
                )

                merged["confidence"] = (
                    validation_confidence
                )

                merged["validation_reason"] = (
                    matched_validation.get(
                        "reason"
                    )
                )

            elif validation_status == "REVIEW":

                merged["status"] = (
                    "REVIEW_REQUIRED"
                )

                merged["detection"] = (
                    "RULE + AI"
                )

                merged["confidence"] = (
                    validation_confidence
                )

                merged["validation_reason"] = (
                    matched_validation.get(
                        "reason"
                    )
                )

        final_findings.append(
            merged
        )

    # --------------------------------------------------
    # 3. Qwen AI 결과 추가
    # --------------------------------------------------

    for ai in ai_results:

        if not isinstance(
            ai,
            dict
        ):
            continue

        ai_status = (
            ai.get("status")
            or "REVIEW"
        ).upper()

        # SAFE는 최종 결과에 추가하지 않음
        if ai_status == "SAFE":
            continue

        matched = None

        for final in final_findings:

            if _is_same_finding(
                final,
                ai
            ):
                matched = final
                break

        # --------------------------------------------------
        # 이미 Rule 결과가 존재
        # --------------------------------------------------

        if matched:

            matched["detection"] = (
                "RULE + AI"
            )

            if ai_status == "VULNERABLE":

                matched["status"] = (
                    "CONFIRMED"
                )

            elif ai_status == "REVIEW":

                if matched.get(
                    "status"
                ) != "CONFIRMED":

                    matched["status"] = (
                        "REVIEW_REQUIRED"
                    )

            _select_higher_severity(
                matched,
                ai
            )

            _select_higher_confidence(
                matched,
                ai
            )

            # AI가 제공한 설명이 더 풍부하면 반영
            for field in [
                "evidence",
                "description",
                "reason",
                "recommendation",
                "severity"
            ]:

                value = ai.get(field)

                if value:
                    matched[field] = value

            if ai.get("line") is not None:
                matched["line"] = ai.get(
                    "line"
                )

            continue

        # --------------------------------------------------
        # Rule에서 발견하지 못한 AI 결과
        # --------------------------------------------------

        new_finding = dict(ai)

        if ai_status == "VULNERABLE":

            new_finding["status"] = (
                "AI_CONFIRMED"
            )

        else:

            new_finding["status"] = (
                "AI_REVIEW_REQUIRED"
            )

        new_finding["detection"] = "AI"

        final_findings.append(
            new_finding
        )

    # --------------------------------------------------
    # 4. 최종 중복 제거
    # --------------------------------------------------

    deduplicated = []

    for finding in final_findings:

        duplicate = None

        for existing in deduplicated:

            if _is_same_finding(
                existing,
                finding
            ):
                duplicate = existing
                break

        if duplicate is None:

            deduplicated.append(
                finding
            )

            continue

        # 더 심각한 severity 유지
        _select_higher_severity(
            duplicate,
            finding
        )

        # 더 높은 confidence 유지
        _select_higher_confidence(
            duplicate,
            finding
        )

        # CONFIRMED 상태 우선
        existing_status = (
            duplicate.get("status")
            or ""
        )

        new_status = (
            finding.get("status")
            or ""
        )

        if (
            new_status in {
                "CONFIRMED",
                "AI_CONFIRMED"
            }
            and
            existing_status not in {
                "CONFIRMED",
                "AI_CONFIRMED"
            }
        ):
            duplicate["status"] = new_status

        # 설명 정보 보강
        for field in [
            "evidence",
            "description",
            "reason",
            "recommendation"
        ]:

            if not duplicate.get(field):
                if finding.get(field):
                    duplicate[field] = (
                        finding.get(field)
                    )

    return deduplicated
