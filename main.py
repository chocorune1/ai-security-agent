from scanner.source_loader import load_source_files
from scanner.rule_analyzer import analyze_source

from analyzer.security_analyzer import (
    analyze_with_qwen,
    validate_rule_finding
)

from analyzer.finding_merger import merge_findings


def main():

    print("STEP 1: main 시작", flush=True)

    source_dir = "../data/source"

    print("STEP 2: source_loader 호출 전", flush=True)

    source_files = load_source_files(source_dir)

    print(
        f"STEP 3: source_loader 완료 - {len(source_files)}개",
        flush=True
    )

    print("STEP 4: rule scanner 시작", flush=True)

    all_rule_findings = []

    for source in source_files:

        print(
            f"  분석 중: {source['file_name']}",
            flush=True
        )

        findings = analyze_source(source)

        print(
            f"  → {len(findings)}개 발견",
            flush=True
        )

        all_rule_findings.extend(findings)

    print(
        f"STEP 5: Rule Scanner 완료 - "
        f"{len(all_rule_findings)}개",
        flush=True
    )

    print("STEP 6: Qwen 분석 시작", flush=True)

    all_ai_findings = []

    for source in source_files:

        print(
            f"  Qwen 분석 중: {source['file_name']}",
            flush=True
        )

        rule_findings = [
            finding
            for finding in all_rule_findings
            if finding["file"] == source["file_name"]
        ]

        result = analyze_with_qwen(
            source,
            rule_findings
        )

        if "findings" in result:
            all_ai_findings.extend(
                result["findings"]
            )

    print(
        f"STEP 7: Qwen 분석 완료 - "
        f"{len(all_ai_findings)}개",
        flush=True
    )

    print("STEP 8: Rule Finding 검증 시작", flush=True)

    validation_results = []

    for source in source_files:

        rule_findings = [
            finding
            for finding in all_rule_findings
            if finding["file"] == source["file_name"]
        ]

        for finding in rule_findings:

            print(
                f"  검증 중: "
                f"{finding['type']} / "
                f"{finding['file']}:{finding['line']}",
                flush=True
            )

            result = validate_rule_finding(
                source,
                finding
            )

            validation_results.append(result)

    print(
        "STEP 9: Rule Finding 검증 완료",
        flush=True
    )

    print("STEP 10: Finding Merge 시작", flush=True)

    final_findings = merge_findings(
        all_rule_findings,
        all_ai_findings,
        validation_results
    )

    print(
        f"STEP 11: 최종 결과 - "
        f"{len(final_findings)}개",
        flush=True
    )

    print()
    print("=" * 60)
    print("최종 보안 점검 결과")
    print("=" * 60)

    for index, finding in enumerate(
        final_findings,
        start=1
    ):
        print()
        print(
            f"[{index}] "
            f"{finding.get('severity', 'UNKNOWN')} - "
            f"{finding.get('type', 'UNKNOWN')}"
        )

        print(
            f"파일 : "
            f"{finding.get('file', '-')}"
        )

        print(
            f"라인 : "
            f"{finding.get('line', '-')}"
        )

        print(
            f"탐지 방식 : "
            f"{finding.get('detection', '-')}"
        )

        print(
            f"신뢰도 : "
            f"{finding.get('confidence', '-')}"
        )

        print(
            f"상태 : "
            f"{finding.get('status', '-')}"
        )

        print(
            f"설명 : "
            f"{finding.get('description', '-')}"
        )

        print(
            f"조치 : "
            f"{finding.get('recommendation', '-')}"
        )

    print()
    print("=" * 60)
    print("분석 완료")
    print("=" * 60)


if __name__ == "__main__":
    main()
