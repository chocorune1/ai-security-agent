from scanner.source_loader import load_source_files
from scanner.rule_analyzer import analyze_source

from analyzer.security_analyzer import (
    analyze_with_qwen,
    validate_rule_finding
)

from analyzer.finding_merger import merge_findings


def main():

    # ==========================================
    # 1. Source 경로
    # ==========================================

    source_dir = "../data/source"

    print()
    print("===================================")
    print(" AI Security Checker")
    print("===================================")
    print()

    # ==========================================
    # 2. Source 파일 로딩
    # ==========================================

    try:

        source_files = load_source_files(
            source_dir
        )

    except Exception as e:

        print("소스 파일을 불러오는 중 오류가 발생했습니다.")
        print()
        print(e)

        return

    print(
        f"발견된 소스 파일: "
        f"{len(source_files)}개"
    )

    print()

    # ==========================================
    # 전체 통계
    # ==========================================

    total_rule_findings = 0
    total_ai_findings = 0
    total_final_findings = 0

    total_confirmed = 0
    total_review = 0

    # ==========================================
    # 3. 파일별 분석
    # ==========================================

    for source in source_files:

        print()
        print("===================================")
        print(
            f"[분석] {source['file_name']}"
        )
        print("===================================")

        # ======================================
        # Step 1. Rule Scanner
        # ======================================

        print()
        print("① Rule Scanner 분석 중...")
        print()

        rule_findings = analyze_source(
            source
        )

        total_rule_findings += len(
            rule_findings
        )

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
                f"라인 : "
                f"{finding['line']}"
            )

            print(
                f"근거 : "
                f"{finding['evidence']}"
            )

        # ======================================
        # Step 2. RAG + Qwen 전체 분석
        # ======================================

        print()
        print(
            "② RAG + Qwen AI 분석 중..."
        )
        print()

        try:

            ai_result = analyze_with_qwen(
                source,
                rule_findings
            )

        except Exception as e:

            print()
            print(
                "Qwen 분석 중 오류가 발생했습니다."
            )

            print(e)

            print()

            continue

        # ======================================
        # Qwen 결과 오류 확인
        # ======================================

        if "error" in ai_result:

            print()
            print(
                "Qwen 결과 처리 오류:"
            )

            print(
                ai_result["error"]
            )

            print()

            continue

        # ======================================
        # Qwen Finding
        # ======================================

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

        # ======================================
        # Qwen 원본 Finding 확인
        # ======================================

        print()
        print(
            "---------- Qwen Finding ----------"
        )

        if not ai_findings:

            print(
                "Qwen이 확인한 취약점이 없습니다."
            )

        else:

            for finding in ai_findings:

                print()
                print(
                    f"유형 : "
                    f"{finding.get('type')}"
                )

                print(
                    f"Severity : "
                    f"{finding.get('severity')}"
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
            "-----------------------------------"
        )

        # ======================================
        # Step 3. Rule Finding AI 검증
        # ======================================

        validation_results = []

        print()
        print(
            "③ Rule Finding AI 검증 중..."
        )
        print()

        if not rule_findings:

            print(
                "검증할 Rule Finding이 없습니다."
            )

        else:

            for rule_finding in rule_findings:

                print(
                    f"[검증 요청] "
                    f"{rule_finding['type']} "
                    f"(라인 "
                    f"{rule_finding['line']})"
                )

                try:

                    validation = validate_rule_finding(
                        source,
                        rule_finding
                    )

                except Exception as e:

                    print(
                        "검증 중 오류 발생:"
                    )

                    print(e)

                    validation = {
                        "status": "REVIEW",
                        "reason":
                            "Qwen 검증 중 오류가 발생했습니다."
                    }

                validation_results.append({
                    "type": rule_finding["type"],
                    "line": rule_finding["line"],
                    "status": validation["status"],
                    "reason": validation["reason"]
                })

                print(
                    f"[검증 결과] "
                    f"{rule_finding['type']} "
                    f"(라인 "
                    f"{rule_finding['line']}) "
                    f"→ "
                    f"{validation['status']}"
                )

                print(
                    f"판단 : "
                    f"{validation['reason']}"
                )

                print()

        # ======================================
        # Step 4. Finding Merge
        # ======================================

        print()
        print(
            "④ 최종 Finding 생성 중..."
        )
        print()

        final_findings = merge_findings(
            rule_findings,
            ai_result,
            validation_results
        )

        total_final_findings += len(
            final_findings
        )

        # ======================================
        # Step 5. 최종 Finding 출력
        # ======================================

        print()
        print(
            "========== 최종 Finding =========="
        )

        if not final_findings:

            print()
            print(
                "취약점이 발견되지 않았습니다."
            )

        else:

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
                    f"이유 : "
                    f"{finding['reason']}"
                )

                print(
                    f"조치 : "
                    f"{finding['recommendation']}"
                )

                print(
                    "-----------------------------------"
                )

                # 통계
                if finding["status"] == "CONFIRMED":

                    total_confirmed += 1

                elif finding["status"] == "REVIEW_REQUIRED":

                    total_review += 1

        print()
        print(
            "==================================="
        )

    # ==========================================
    # 6. 전체 분석 요약
    # ==========================================

    print()
    print("===================================")
    print(" 최종 분석 요약")
    print("===================================")

    print()
    print(
        f"분석 파일 수       : "
        f"{len(source_files)}개"
    )

    print(
        f"Rule Scanner 발견  : "
        f"{total_rule_findings}개"
    )

    print(
        f"Qwen AI 확인       : "
        f"{total_ai_findings}개"
    )

    print(
        f"최종 Finding       : "
        f"{total_final_findings}개"
    )

    print(
        f"CONFIRMED          : "
        f"{total_confirmed}개"
    )

    print(
        f"REVIEW_REQUIRED    : "
        f"{total_review}개"
    )

    print()
    print("===================================")


if __name__ == "__main__":
    main()
