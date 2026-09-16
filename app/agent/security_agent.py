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

    def _deduplicate_rule_findings(
        self,
        findings
    ):
        """
        Rule Scanner에서 동일한 취약점이
        중복 발견되는 경우 하나로 통합합니다.

        같은 파일 + 같은 취약점 유형 +
        같은 라인(또는 매우 가까운 라인)을
        동일 Finding으로 판단합니다.
        """

        unique_findings = []

        for finding in findings:

            if not isinstance(
                finding,
                dict
            ):
                continue

            file_name = str(
                finding.get("file", "")
            ).strip().lower()

            finding_type = str(
                finding.get("type", "")
            ).strip().lower()

            line = finding.get("line")

            duplicate = False

            for existing in unique_findings:

                existing_file = str(
                    existing.get("file", "")
                ).strip().lower()

                existing_type = str(
                    existing.get("type", "")
                ).strip().lower()

                existing_line = existing.get(
                    "line"
                )

                if (
                    file_name
                    != existing_file
                ):
                    continue

                if (
                    finding_type
                    != existing_type
                ):
                    continue

                # 라인이 둘 다 있으면
                # 최대 2줄 차이까지 동일 Finding
                if (
                    line is not None
                    and existing_line is not None
                ):
                    try:
                        if abs(
                            int(line)
                            - int(existing_line)
                        ) > 2:
                            continue
                    except (
                        ValueError,
                        TypeError
                    ):
                        pass

                duplicate = True
                break

            if not duplicate:
                unique_findings.append(
                    finding
                )

        return unique_findings

    def run(
        self,
        progress_callback=None
    ):

        def update(
            percent,
            message
        ):
            if progress_callback:
                progress_callback(
                    percent,
                    message
                )

        print()
        print("=" * 70)
        print("AI Security Agent 시작")
        print("=" * 70)

        update(
            5,
            "AI Security Agent를 준비하고 있습니다..."
        )

        print()
        print("[1/6] 소스코드 수집")

        update(
            10,
            "소스코드를 수집하고 있습니다..."
        )

        sources = load_source_files(
            self.source_dir
        )

        source_count = len(
            sources
        )

        print(
            f"  → {source_count}개 파일 수집"
        )

        if not sources:

            print(
                "분석할 소스코드가 없습니다."
            )

            update(
                100,
                "분석할 소스코드가 없습니다."
            )

            return {
                "source_count": 0,
                "findings": [],
                "report_file": None
            }

        # ========================================================
        # Rule Scanner
        # ========================================================

        print()
        print("[2/6] Rule 기반 보안점검")

        update(
            15,
            "Rule Scanner를 준비하고 있습니다..."
        )

        rule_findings = []

        for index, source in enumerate(
            sources,
            start=1
        ):

            print(
                f"  분석 중: "
                f"{source['file_name']}"
            )

            percent = 15 + int(
                (index / len(sources))
                * 20
            )

            update(
                percent,
                f"Rule Scanner 분석 중: "
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

        # --------------------------------------------------------
        # Rule 중복 제거
        # --------------------------------------------------------

        original_rule_count = len(
            rule_findings
        )

        rule_findings = (
            self._deduplicate_rule_findings(
                rule_findings
            )
        )

        removed_rule_duplicates = (
            original_rule_count
            - len(rule_findings)
        )

        if removed_rule_duplicates > 0:

            print(
                f"  → Rule 중복 "
                f"{removed_rule_duplicates}개 제거"
            )

        print(
            f"  → Rule 최종 "
            f"{len(rule_findings)}개"
        )

        # ========================================================
        # Qwen AI 분석
        # ========================================================

        print()
        print("[3/6] Qwen AI 보안 분석")

        update(
            40,
            "Qwen AI 보안 분석을 시작합니다..."
        )

        ai_results = []

        for index, source in enumerate(
            sources,
            start=1
        ):

            print(
                f"  Qwen 분석 중: "
                f"{source['file_name']}"
            )

            percent = 40 + int(
                (index / len(sources))
                * 20
            )

            update(
                percent,
                f"Qwen AI 분석 중: "
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

            if isinstance(
                result,
                list
            ):
                ai_results.extend(
                    result
                )

            update(
                percent,
                f"Qwen 분석 완료: "
                f"{source['file_name']}"
            )

        print(
            f"  → Qwen 분석 결과 "
            f"{len(ai_results)}개"
        )

        # ========================================================
        # Validation
        # ========================================================

        print()
        print("[4/6] Rule 탐지 결과 AI 검증")

        update(
            65,
            "Rule 탐지 결과를 AI가 검증하고 있습니다..."
        )

        validation_results = []

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

                if not validation.get("type"):
                    validation["type"] = (
                        finding.get("type")
                    )

                if not validation.get("file"):
                    validation["file"] = (
                        finding.get("file")
                    )

                if validation.get("line") is None:
                    validation["line"] = (
                        finding.get("line")
                    )

                validation_results.append(
                    validation
                )

            percent = 65 + int(
                (index / max(
                    len(rule_findings),
                    1
                ))
                * 10
            )

            update(
                min(percent, 75),
                f"AI 검증 중: "
                f"{finding.get('file')}:"
                f"{finding.get('line')}"
            )

        print(
            f"  → 검증 완료 "
            f"{len(validation_results)}개"
        )

        # ========================================================
        # Merge
        # ========================================================

        print()
        print("[5/6] 보안점검 결과 통합")

        update(
            80,
            "Rule + AI 분석 결과를 통합하고 있습니다..."
        )

        final_findings = merge_findings(
            rule_findings,
            ai_results,
            validation_results
        )

        print(
            f"  → 최종 취약점 "
            f"{len(final_findings)}개"
        )

        # ========================================================
        # Report
        # ========================================================

        print()
        print("[6/6] 보안 리포트 생성")

        update(
            90,
            "HTML 보안 리포트를 생성하고 있습니다..."
        )

        report_file = generate_html_report(
            final_findings
        )

        print(
            "  → 리포트 생성 완료"
        )

        update(
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
