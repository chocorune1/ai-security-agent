from scanner.source_loader import load_source_files
from scanner.rule_analyzer import analyze_source
from analyzer.security_analyzer import analyze_with_qwen


def main():

    source_dir = "../data/source"

    source_files = load_source_files(source_dir)

    print()
    print("===================================")
    print(" AI Security Checker")
    print("===================================")
    print()

    print(f"발견된 소스 파일: {len(source_files)}개")
    print()

    total_rule_findings = 0
    total_ai_findings = 0

    for source in source_files:

        print(f"[분석] {source['file_name']}")

        # ==================================
        # 1. Rule Scanner
        # ==================================

        rule_findings = analyze_source(source)

        total_rule_findings += len(rule_findings)

        print()
        print(f"Rule Scanner 발견: {len(rule_findings)}개")

        for finding in rule_findings:

            print()
            print(
                f"[Rule] {finding['severity']} - "
                f"{finding['type']}"
            )
            print(f"파일 : {finding['file']}")
            print(f"라인 : {finding['line']}")
            print(f"근거 : {finding['evidence']}")

        # ==================================
        # 2. Qwen AI 분석
        # ==================================

        print()
        print("Qwen AI 분석 중...")
        print()

        ai_result = analyze_with_qwen(
            source,
            rule_findings
        )

        # ==================================
        # 3. AI 결과 출력
        # ==================================

        print("========== AI 분석 결과 ==========")

        if "error" in ai_result:

            print("AI 결과 처리 오류")
            print()
            print(ai_result["error"])

        else:

            findings = ai_result.get(
                "findings",
                []
            )

            total_ai_findings += len(findings)

            print(
                f"AI가 확인한 취약점: "
                f"{len(findings)}개"
            )

            for index, finding in enumerate(
                findings,
                start=1
            ):

                print()
                print(
                    f"[{index}] "
                    f"{finding.get('severity')} - "
                    f"{finding.get('type')}"
                )

                print(
                    f"라인 : "
                    f"{finding.get('line')}"
                )

                print(
                    f"근거 : "
                    f"{finding.get('evidence')}"
                )

                print(
                    f"설명 : "
                    f"{finding.get('description')}"
                )

                print(
                    f"원인 : "
                    f"{finding.get('reason')}"
                )

                print(
                    f"조치 : "
                    f"{finding.get('recommendation')}"
                )

                print("-----------------------------------")

        print(
            "===================================="
        )

    # ==================================
    # 최종 요약
    # ==================================

    print()
    print("===================================")
    print(" 최종 분석 요약")
    print("===================================")

    print(
        f"Rule Scanner 발견 : "
        f"{total_rule_findings}개"
    )

    print(
        f"Qwen AI 확인      : "
        f"{total_ai_findings}개"
    )

    print("===================================")


if __name__ == "__main__":
    main()
