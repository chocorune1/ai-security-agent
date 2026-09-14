from scanner.source_loader import load_source_files
from scanner.rule_analyzer import analyze_source

from analyzer.security_analyzer import (
    analyze_with_qwen,
    validate_rule_finding
)

from analyzer.finding_merger import merge_findings


def main():

    print("STEP 1: main 시작")

    # ==================================================
    # STEP 2. Source Load
    # ==================================================

    source_dir = "../data/source"

    print("STEP 2: source_loader 호출 전")

    sources = load_source_files(source_dir)

    print(
        f"STEP 3: source_loader 완료 - "
        f"{len(sources)}개"
    )

    # ==================================================
    # STEP 3. Rule Scanner
    # ==================================================

    print("STEP 4: rule scanner 시작")

    rule_findings = []

    for source in sources:

        print(
            f"  분석 중: "
            f"{source['file_name']}"
        )

        findings = analyze_source(source)

        print(
            f"  → {len(findings)}개 발견"
        )

        rule_findings.extend(findings)

    print(
        f"STEP 5: Rule Scanner 완료 - "
        f"{len(rule_findings)}개"
    )

    # ==================================================
    # STEP 4. Qwen AI Analysis
    # ==================================================

    print("STEP 6: Qwen 분석 시작")

    ai_results = []

    for source in sources:

        print(
            f"  Qwen 분석 중: "
            f"{source['file_name']}"
        )

        source_rule_findings = [
            finding
            for finding in rule_findings
            if finding.get("file")
            == source["file_name"]
        ]

        result = analyze_with_qwen(
            source,
            source_rule_findings
        )

        if isinstance(result, list):
            ai_results.extend(result)

    print(
        f"STEP 7: Qwen 분석 완료 - "
        f"{len(ai_results)}개"
    )

    # ==================================================
    # STEP 5. Rule Finding Validation
    # ==================================================

    print(
        "STEP 8: Rule Finding 검증 시작"
    )

    validation_results = []

    for finding in rule_findings:

        print(
            f"검증 중: "
            f"{finding.get('type')} / "
            f"{finding.get('file')}:" 
            f"{finding.get('line')}"
        )

        # 해당 원본 파일 찾기
        source = None

        for item in sources:

            if (
                item.get("file_name")
                == finding.get("file")
            ):
                source = item
                break

        if source is None:
            continue

        validation = validate_rule_finding(
            source,
            finding
        )

        if isinstance(validation, dict):

            # ------------------------------------------
            # 검증 결과에 원본 Rule 정보 보완
            # ------------------------------------------

            if not validation.get("type"):
                validation["type"] = finding.get(
                    "type"
                )

            if not validation.get("file"):
                validation["file"] = finding.get(
                    "file"
                )

            if validation.get("line") is None:
                validation["line"] = finding.get(
                    "line"
                )

            validation_results.append(
                validation
            )

    print(
        "STEP 9: Rule Finding 검증 완료"
    )

    # ==================================================
    # STEP 6. Finding Merge
    # ==================================================

    print(
        "STEP 10: Finding Merge 시작"
    )

    final_findings = merge_findings(
        rule_findings,
        ai_results,
        validation_results
    )

    print(
        f"STEP 11: 최종 결과 - "
        f"{len(final_findings)}개"
    )

    # ==================================================
    # STEP 7. Final Report
    # ==================================================

    print()
    print("=" * 70)
    print("최종 보안 점검 결과")
    print("=" * 70)

    if not final_findings:

        print("취약점이 발견되지 않았습니다.")

    else:

        for index, finding in enumerate(
            final_findings,
            start=1
        ):

            print()
            print(
                f"[{index}]"
            )

            print(
                f"취약점: "
                f"{finding.get('type', '-')}"
            )

            print(
                f"심각도: "
                f"{finding.get('severity', '-')}"
            )

            print(
                f"파일: "
                f"{finding.get('file', '-')}"
            )

            print(
                f"라인: "
                f"{finding.get('line', '-')}"
            )

            print(
                f"탐지 방법: "
                f"{finding.get('detection', '-')}"
            )

            print(
                f"상태: "
                f"{finding.get('status', '-')}"
            )

            print(
                f"신뢰도: "
                f"{finding.get('confidence', '-')}"
            )

            print(
                f"증거: "
                f"{finding.get('evidence', '-')}"
            )

            print(
                f"설명: "
                f"{finding.get('description', '-')}"
            )

            print(
                f"판단 근거: "
                f"{finding.get('reason', '-')}"
            )

            print(
                f"개선 방법: "
                f"{finding.get('recommendation', '-')}"
            )

            print("-" * 70)


if __name__ == "__main__":
    main()
