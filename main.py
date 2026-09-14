from scanner.source_loader import load_source_files
from scanner.rule_analyzer import analyze_source

from analyzer.security_analyzer import (
    analyze_with_qwen,
    validate_rule_finding
)
from analyzer.finding_merger import merge_findings


def main():

    source_dir = "../data/source"

    source_files = load_source_files(
        source_dir
    )

    print()
    print("===================================")
    print(" AI Security Checker")
    print("===================================")
    print()

    print(
        f"발견된 소스 파일: "
        f"{len(source_files)}개"
    )

    print()

    total_rule_findings = 0
    total_ai_findings = 0
    total_final_findings = 0

    # =====================================
    # 파일별 분석
    # =====================================

    for source in source_files:

        print(
            f"[분석] {source['file_name']}"
        )

        # ---------------------------------
        # 1. Rule Scanner
        # ---------------------------------

        rule_findings = analyze_source(
            source
        )

        total_rule_findings += len(
            rule_findings
        )

        print()
        print(
            f"Rule Scanner 발견: "
            f"{len(rule_findings)}개"
        )

        for finding in rule_findings:

            print()
            print(
                f"[Rule] "
                f"{finding['severity']} - "
                f"{finding['type']}"
            )

            print(
                f"라인 : {finding['line']}"
            )

            print(
                f"근거 : {finding['evidence']}"
            )

        # ---------------------------------
        # 2. RAG + Qwen
        # ---------------------------------

        print()
        print(
            "RAG + Qwen AI 분석 중..."
        )
        print()

        ai_result = analyze_with_qwen(
            source,
            rule_findings
        )

        # ---------------------------------
        # 3. AI 결과 확인
        # ---------------------------------

        if "error" in ai_result:

            print(
                "AI 결과 처리 오류:"
            )

            print(
                ai_result["error"]
            )

            print()

            continue

        ai_findings = ai_result.get(
            "findings",
            []
        )

        total_ai_findings += len(
            ai_findings
        )

        print(
            f"Qwen AI 확인: "
            f"{len(ai_findings)}개"
        )

        # ---------------------------------
        # 4. Rule + AI 통합
        # ---------------------------------

        final_findings = merge_findings(
            rule_findings,
            ai_result
        )

        total_final_findings += len(
            final_findings
        )

        print()
        print(
            "========== 최종 Finding =========="
        )

        for index, finding in enumerate(
            final_findings,
            start=1
        ):

            print()
            print(
                f"[{index}] "
                f"{finding['severity']} - "
                f"{finding['type']}"
            )

            print(
                f"라인 : "
                f"{finding['line']}"
            )

            print(
                f"탐지 방식 : "
                f"{finding['source']}"
            )

            print(
                f"신뢰도 : "
                f"{finding['confidence']}"
            )

            print(
                f"상태 : "
                f"{finding['status']}"
            )

            print(
                f"설명 : "
                f"{finding['description']}"
            )

            print(
                f"조치 : "
                f"{finding['recommendation']}"
            )

            print(
                "-----------------------------------"
            )

    # =====================================
    # 전체 요약
    # =====================================

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

    print(
        f"최종 Finding       : "
        f"{total_final_findings}개"
    )

    print("===================================")


if __name__ == "__main__":
    main()
