def _normalize(value):
    if value is None:
        return ""

    return str(value).strip().lower()


def _canonical_type(value):
    """
    취약점 명칭이 조금 다르더라도
    실제 동일한 취약점이면 같은 유형으로 취급합니다.
    """

    value = _normalize(value)

    if not value:
        return ""

    # XSS
    if (
        "cross-site scripting" in value
        or value == "xss"
        or "dom xss" in value
    ):
        return "xss"

    # eval
    if (
        "dangerous eval" in value
        or "code injection" in value
        and "eval" in value
        or value == "eval"
        or "javascript eval" in value
    ):
        return "eval"

    # SQL Injection
    if "sql injection" in value:
        return "sql injection"

    # Command Injection
    if "command injection" in value:
        return "command injection"

    # Hard-coded Credential
    if (
        "hard-coded credential" in value
        or "hardcoded credential" in value
        or "hard coded credential" in value
    ):
        return "hard-coded credential"

    # Path Traversal
    if "path traversal" in value:
        return "path traversal"

    return value


def _same_file(
    finding1,
    finding2
):
    return (
        _normalize(
            finding1.get("file")
        )
        ==
        _normalize(
            finding2.get("file")
        )
    )


def _same_type(
    finding1,
    finding2
):
    return (
        _canonical_type(
            finding1.get("type")
        )
        ==
        _canonical_type(
            finding2.get("type")
        )
    )


def _line_close(
    finding1,
    finding2
):
    line1 = finding1.get("line")
    line2 = finding2.get("line")

    if (
        line1 is None
        or line2 is None
    ):
        return True

    try:
        return (
            abs(
                int(line1)
                - int(line2)
            )
            <= 2
        )

    except (
        ValueError,
        TypeError
    ):
        return True


def _is_same_finding(
    finding1,
    finding2
):
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


def _severity_rank(
    severity
):
    ranks = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }

    return ranks.get(
        _normalize(
            severity
        ).upper(),
        0
    )


def _confidence_rank(
    confidence
):
    ranks = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }

    return ranks.get(
        _normalize(
            confidence
        ).upper(),
        0
    )


def _select_higher_severity(
    first,
    second
):
    if (
        _severity_rank(
            second.get("severity")
        )
        >
        _severity_rank(
            first.get("severity")
        )
    ):
        first["severity"] = (
            second.get("severity")
        )

    return first


def _select_higher_confidence(
    first,
    second
):
    if (
        _confidence_rank(
            second.get("confidence")
        )
        >
        _confidence_rank(
            first.get("confidence")
        )
    ):
        first["confidence"] = (
            second.get("confidence")
        )

    return first


def _find_matching(
    findings,
    target
):
    for finding in findings:

        if _is_same_finding(
            finding,
            target
        ):
            return finding

    return None


def merge_findings(
    rule_findings,
    ai_results,
    validation_results
):
    """
    Rule / AI / Validation 결과를 최종 통합합니다.

    처리 원칙:

    1. Validation SAFE
       → 최종 결과에서 완전히 제외

    2. Validation VULNERABLE + Rule
       → CONFIRMED

    3. Validation REVIEW + Rule
       → REVIEW_REQUIRED

    4. AI VULNERABLE + Rule
       → CONFIRMED

    5. AI REVIEW + Rule
       → 기존 상태 유지 또는 REVIEW_REQUIRED

    6. Rule과 AI가 같은 취약점을 발견하면
       하나의 Finding으로 통합

    7. 이미 SAFE로 판정된 동일 취약점은
       AI 결과에서 다시 추가하지 않음

    8. 동일 취약점 중복 제거
    """

    final_findings = []

    # ============================================================
    # 1. Validation 결과 정리
    # ============================================================

    safe_validations = []
    vulnerable_validations = []
    review_validations = []

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

        if status == "SAFE":

            safe_validations.append(
                validation
            )

        elif status == "VULNERABLE":

            vulnerable_validations.append(
                validation
            )

        else:

            review_validations.append(
                validation
            )

    # ============================================================
    # 2. Rule 결과 처리
    # ============================================================

    for rule in rule_findings:

        if not isinstance(
            rule,
            dict
        ):
            continue

        # --------------------------------------------------------
        # SAFE 검증 확인
        # --------------------------------------------------------

        safe_validation = _find_matching(
            safe_validations,
            rule
        )

        if safe_validation:

            print(
                f"  [제외] "
                f"{rule.get('type')} / "
                f"{rule.get('file')}:"
                f"{rule.get('line')} "
                f"→ AI 검증 SAFE"
            )

            continue

        # --------------------------------------------------------
        # 기본 Rule Finding
        # --------------------------------------------------------

        merged = dict(rule)

        merged["detection"] = "RULE"
        merged["status"] = (
            "REVIEW_REQUIRED"
        )
        merged["confidence"] = "LOW"

        # --------------------------------------------------------
        # VULNERABLE 검증
        # --------------------------------------------------------

        vulnerable_validation = (
            _find_matching(
                vulnerable_validations,
                rule
            )
        )

        if vulnerable_validation:

            merged["status"] = (
                "CONFIRMED"
            )

            merged["detection"] = (
                "RULE + AI"
            )

            merged["confidence"] = (
                vulnerable_validation.get(
                    "confidence"
                )
                or "HIGH"
            )

            merged["validation_reason"] = (
                vulnerable_validation.get(
                    "reason"
                )
            )

        else:

            # ----------------------------------------------------
            # REVIEW 검증
            # ----------------------------------------------------

            review_validation = (
                _find_matching(
                    review_validations,
                    rule
                )
            )

            if review_validation:

                merged["status"] = (
                    "REVIEW_REQUIRED"
                )

                merged["detection"] = (
                    "RULE + AI"
                )

                merged["confidence"] = (
                    review_validation.get(
                        "confidence"
                    )
                    or "MEDIUM"
                )

                merged["validation_reason"] = (
                    review_validation.get(
                        "reason"
                    )
                )

        final_findings.append(
            merged
        )

    # ============================================================
    # 3. AI 결과 처리
    # ============================================================

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

        # --------------------------------------------------------
        # SAFE AI 결과는 제외
        # --------------------------------------------------------

        if ai_status == "SAFE":
            continue

        # --------------------------------------------------------
        # 중요:
        # Validation에서 SAFE였던 결과는
        # AI가 REVIEW/VULNERABLE로 다시 발견해도 제외
        # --------------------------------------------------------

        safe_validation = _find_matching(
            safe_validations,
            ai
        )

        if safe_validation:

            print(
                f"  [제외] "
                f"{ai.get('type')} / "
                f"{ai.get('file')}:"
                f"{ai.get('line')} "
                f"→ 기존 AI 검증 SAFE"
            )

            continue

        # --------------------------------------------------------
        # 기존 Finding과 매칭
        # --------------------------------------------------------

        matched = _find_matching(
            final_findings,
            ai
        )

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
                ) not in {
                    "CONFIRMED",
                    "AI_CONFIRMED"
                }:

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

            # ----------------------------------------------------
            # AI가 제공한 상세 정보 반영
            # ----------------------------------------------------

            for field in [
                "evidence",
                "description",
                "reason",
                "recommendation"
            ]:

                value = ai.get(field)

                if value:
                    matched[field] = value

            if ai.get(
                "severity"
            ):
                matched["severity"] = (
                    ai.get("severity")
                )

            if ai.get("line") is not None:

                matched["line"] = (
                    ai.get("line")
                )

            continue

        # --------------------------------------------------------
        # Rule에서 발견하지 못한 AI Finding
        # --------------------------------------------------------

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

    # ============================================================
    # 4. 최종 중복 제거
    # ============================================================

    deduplicated = []

    for finding in final_findings:

        matched = _find_matching(
            deduplicated,
            finding
        )

        if matched is None:

            deduplicated.append(
                finding
            )

            continue

        # --------------------------------------------------------
        # 더 높은 심각도 유지
        # --------------------------------------------------------

        _select_higher_severity(
            matched,
            finding
        )

        # --------------------------------------------------------
        # 더 높은 신뢰도 유지
        # --------------------------------------------------------

        _select_higher_confidence(
            matched,
            finding
        )

        # --------------------------------------------------------
        # CONFIRMED 우선
        # --------------------------------------------------------

        current_status = (
            matched.get("status")
            or ""
        )

        new_status = (
            finding.get("status")
            or ""
        )

        confirmed_statuses = {
            "CONFIRMED",
            "AI_CONFIRMED"
        }

        if (
            new_status
            in confirmed_statuses
            and
            current_status
            not in confirmed_statuses
        ):

            matched["status"] = (
                new_status
            )

        # --------------------------------------------------------
        # Rule + AI 우선
        # --------------------------------------------------------

        if (
            finding.get("detection")
            == "RULE + AI"
        ):

            matched["detection"] = (
                "RULE + AI"
            )

        # --------------------------------------------------------
        # 상세 정보 보완
        # --------------------------------------------------------

        for field in [
            "evidence",
            "description",
            "reason",
            "recommendation",
            "validation_reason"
        ]:

            if not matched.get(field):

                if finding.get(field):

                    matched[field] = (
                        finding.get(field)
                    )

    return deduplicated
