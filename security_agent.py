from scanner.source_loader import load_source_files
from scanner.rule_analyzer import analyze_source

from analyzer.security_analyzer import (
    analyze_with_qwen,
    validate_rule_finding
)

from analyzer.finding_merger import merge_findings
from report.html_report import generate_html_report


class SecurityAgent:

    def __init__(self, source_dir="../data/source"):
        self.source_dir = source_dir

    def run(self, progress_callback=None):

        def update_progress(percent, message):
            """
            웹 UI 등에 현재 진행상황을 전달합니다.
            callback이 없어도 기존 CLI 실행에는 영향을 주지 않습니다.
            """

            if progress_callback is not None:
                progress_callback(
                    percent,
                    message
                )

        print()
        print("=" * 70)
        print("AI Security Agent 시작")
        print("=" * 70)

        # --------------------------------------------------
        # 1. Source Loader
        # --------------------------------------------------

        update_progress(
            5,
            "소스코드 수집을 준비하고 있습니다..."
        )

        print()
        print("[1/6] 소스코드 수집")

        sources = load_source_files(
            self.source_dir
        )

        source_count = len(sources)

        print(
            f"  → {source_count}개 파일 수집"
        )

        update_progress(
            15,
            f"소스코드 수집 완료 - {source_count}개 파일"
        )

        if not sources:

            print("분석할 소스코드가 없습니다.")

            update_progress(
                100,
                "분석할 소스코드가 없습니다."
            )

            return {
                "source_count": 0,
                "findings": [],
                "report_file": None
            }

        # --------------------------------------------------
        # 2. Rule Scanner
        # --------------------------------------------------

        update_progress(
            20,
            "Rule Scanner로 소스코드를 분석하고 있습니다..."
        )

        print()
        print("[2/6] Rule 기반 보안점검")

        rule_findings = []

        for source in sources:

            print(
                f"  분석 중: "
                f"{source['file_name']}"
            )

            findings = analyze_source(
                source
            )

            print(
                f"  → {len(findings)}개 발견"
            )

            rule_findings.extend(
                findings
            )

        print(
            f"  → Rule Scanner 총 "
            f"{len(rule_findings)}개"
        )

        update_progress(
            35,
            f"Rule Scanner 완료 - "
            f"{len(rule_findings)}개 항목 발견"
        )

        # --------------------------------------------------
        # 3. Qwen AI Analysis
        # --------------------------------------------------

        update_progress(
            40,
            "Qwen AI가 소스코드의 보안 취약점을 분석하고 있습니다..."
        )

        print()
        print("[3/6] Qwen AI 보안 분석")

        ai_results = []

        total_sources = len(sources)

        for index, source in enumerate(
            sources,
            start=1
        ):

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
                ai_results.extend(
                    result
                )

            # Qwen 단계는 40~60%
            qwen_progress = 40 + int(
                (index / total_sources) * 20
            )

            update_progress(
                qwen_progress,
                f"Qwen AI 분석 중 "
                f"({index}/{total_sources}) - "
                f"{source['file_name']}"
            )

        print(
            f"  → Qwen 분석 결과 "
            f"{len(ai_results)}개"
        )

        update_progress(
            60,
            f"Qwen AI 분석 완료 - "
            f"{len(ai_results)}개 결과"
        )

        # --------------------------------------------------
        # 4. Rule Finding Validation
        # --------------------------------------------------

        update_progress(
            65,
            "Rule 탐지 결과를 AI가 검증하고 있습니다..."
        )

        print()
        print("[4/6] Rule 탐지 결과 AI 검증")

        validation_results = []

        total_findings = len(rule_findings)

        for index, finding in enumerate(
            rule_findings,
            start=1
        ):

            print(
                f"  검증 중: "
                f"{finding.get('type')} / "
                f"{finding.get('file')}:"
                f"{finding.get('line')}"
            )

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

            if isinstance(
                validation,
                dict
            ):

                if not validation.get(
                    "type"
                ):
                    validation["type"] = (
                        finding.get("type")
                    )

                if not validation.get(
                    "file"
                ):
                    validation["file"] = (
                        finding.get("file")
                    )

                if validation.get(
                    "line"
                ) is None:
                    validation["line"] = (
                        finding.get("line")
                    )

                validation_results.append(
                    validation
                )

            # 검증 단계 65~75%
            if total_findings > 0:

                validation_progress = 65 + int(
                    (index / total_findings) * 10
                )

            else:

                validation_progress = 75

            update_progress(
                validation_progress,
                f"AI 검증 중 "
                f"({index}/{total_findings}) - "
                f"{finding.get('type')}"
            )

        print(
            f"  → 검증 완료 "
            f"{len(validation_results)}개"
        )

        update_progress(
            75,
            f"AI 검증 완료 - "
            f"{len(validation_results)}개"
        )

        # --------------------------------------------------
        # 5. Finding Merge
        # --------------------------------------------------

        update_progress(
            80,
            "Rule과 AI 분석 결과를 통합하고 있습니다..."
        )

        print()
        print("[5/6] 보안점검 결과 통합")

        final_findings = merge_findings(
            rule_findings,
            ai_results,
            validation_results
        )

        print(
            f"  → 최종 취약점 "
            f"{len(final_findings)}개"
        )

        update_progress(
            85,
            f"보안점검 결과 통합 완료 - "
            f"최종 취약점 {len(final_findings)}개"
        )

        # --------------------------------------------------
        # 6. Report
        # --------------------------------------------------

        update_progress(
            90,
            "HTML 보안 리포트를 생성하고 있습니다..."
        )

        print()
        print("[6/6] 보안 리포트 생성")

        report_file = generate_html_report(
            final_findings
        )

        print(
            f"  → 리포트 생성 완료"
        )

        update_progress(
            100,
            "보안점검이 완료되었습니다."
        )

        print()
        print("=" * 70)
        print("AI Security Agent 분석 완료")
        print("=" * 70)

        print(
            f"분석 파일: "
            f"{source_count}개"
        )

        print(
            f"최종 취약점: "
            f"{len(final_findings)}개"
        )

        print(
            f"HTML 리포트: "
            f"{report_file}"
        )

        return {
            "source_count": source_count,
            "findings": final_findings,
            "report_file": report_file
        }
