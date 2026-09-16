from pathlib import Path
from datetime import datetime
from html import escape


BASE_DIR = Path(
    __file__
).resolve().parents[2]

REPORT_DIR = (
    BASE_DIR / "reports"
)


def _normalize_severity(
    severity
):
    if not severity:
        return "MEDIUM"

    value = str(
        severity
    ).strip().upper()

    if value not in {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW"
    }:
        return "MEDIUM"

    return value


def _normalize_status(
    status
):
    if not status:
        return "REVIEW_REQUIRED"

    return str(
        status
    ).strip().upper()


def _severity_class(
    severity
):
    return _normalize_severity(
        severity
    ).lower()


def _safe_text(value):
    if value is None:
        return "-"

    return escape(
        str(value)
    )


def _count_severity(
    findings,
    severity
):
    return sum(
        1
        for finding in findings
        if _normalize_severity(
            finding.get("severity")
        )
        == severity
    )


def generate_html_report(
    findings
):
    """
    최종 Finding 목록을 이용하여
    HTML 보안점검 리포트를 생성합니다.
    """

    if findings is None:
        findings = []

    # ------------------------------------------------------------
    # 최종 데이터 정리
    # ------------------------------------------------------------

    normalized_findings = []

    for finding in findings:

        if not isinstance(
            finding,
            dict
        ):
            continue

        item = dict(
            finding
        )

        item["severity"] = (
            _normalize_severity(
                item.get("severity")
            )
        )

        item["status"] = (
            _normalize_status(
                item.get("status")
            )
        )

        normalized_findings.append(
            item
        )

    findings = normalized_findings

    # ------------------------------------------------------------
    # 심각도 집계
    # ------------------------------------------------------------

    critical_count = _count_severity(
        findings,
        "CRITICAL"
    )

    high_count = _count_severity(
        findings,
        "HIGH"
    )

    medium_count = _count_severity(
        findings,
        "MEDIUM"
    )

    low_count = _count_severity(
        findings,
        "LOW"
    )

    total_count = len(
        findings
    )

    confirmed_count = sum(
        1
        for finding in findings
        if finding.get("status")
        in {
            "CONFIRMED",
            "AI_CONFIRMED"
        }
    )

    # ------------------------------------------------------------
    # 생성 시간
    # ------------------------------------------------------------

    generated_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # ------------------------------------------------------------
    # 파일명
    # ------------------------------------------------------------

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    report_name = (
        "security_report_"
        + datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )
        + ".html"
    )

    report_path = (
        REPORT_DIR
        / report_name
    )

    # ------------------------------------------------------------
    # 취약점 목록 HTML
    # ------------------------------------------------------------

    finding_rows = []

    for index, finding in enumerate(
        findings,
        start=1
    ):

        vulnerability_type = (
            finding.get(
                "type",
                "-"
            )
        )

        severity = (
            _normalize_severity(
                finding.get(
                    "severity"
                )
            )
        )

        file_name = (
            finding.get(
                "file",
                "-"
            )
        )

        line = (
            finding.get(
                "line",
                "-"
            )
        )

        detection = (
            finding.get(
                "detection",
                "-"
            )
        )

        status = (
            _normalize_status(
                finding.get(
                    "status"
                )
            )
        )

        confidence = (
            finding.get(
                "confidence",
                "-"
            )
        )

        evidence = (
            finding.get(
                "evidence",
                "-"
            )
        )

        description = (
            finding.get(
                "description",
                "-"
            )
        )

        reason = (
            finding.get(
                "reason",
                "-"
            )
        )

        validation_reason = (
            finding.get(
                "validation_reason",
                "-"
            )
        )

        recommendation = (
            finding.get(
                "recommendation",
                "-"
            )
        )

        row = f"""
        <div class="finding">

            <div class="finding-header">

                <div class="finding-number">
                    #{index}
                </div>

                <div class="finding-title">
                    {_safe_text(vulnerability_type)}
                </div>

                <div class="severity {_severity_class(severity)}">
                    {_safe_text(severity)}
                </div>

            </div>

            <div class="finding-meta">

                <div>
                    <strong>파일</strong>
                    <span>{_safe_text(file_name)}</span>
                </div>

                <div>
                    <strong>라인</strong>
                    <span>{_safe_text(line)}</span>
                </div>

                <div>
                    <strong>탐지 방법</strong>
                    <span>{_safe_text(detection)}</span>
                </div>

                <div>
                    <strong>상태</strong>
                    <span>{_safe_text(status)}</span>
                </div>

                <div>
                    <strong>신뢰도</strong>
                    <span>{_safe_text(confidence)}</span>
                </div>

            </div>

            <div class="detail">

                <h3>🔎 취약 코드 / 증거</h3>

                <pre>{_safe_text(evidence)}</pre>

                <h3>설명</h3>

                <p>
                    {_safe_text(description)}
                </p>

                <h3>AI 판단 근거</h3>

                <p>
                    {_safe_text(reason)}
                </p>

                <h3>Validation 판단</h3>

                <p>
                    {_safe_text(validation_reason)}
                </p>

                <h3>🛠 개선 방법</h3>

                <p>
                    {_safe_text(recommendation)}
                </p>

            </div>

        </div>
        """

        finding_rows.append(
            row
        )

    findings_html = "\n".join(
        finding_rows
    )

    if not findings_html:

        findings_html = """
        <div class="no-findings">
            <h2>취약점이 발견되지 않았습니다.</h2>
            <p>
                분석 대상 소스코드에서 최종 확인된
                보안 취약점이 없습니다.
            </p>
        </div>
        """

    # ------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------

    html = f"""
<!DOCTYPE html>

<html lang="ko">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>
AI Source Code Security Report
</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    padding: 40px;
    background: #f4f6f8;
    color: #222;
    font-family:
        Arial,
        "Malgun Gothic",
        sans-serif;
}}

.container {{
    max-width: 1400px;
    margin: 0 auto;
}}

.header {{
    background: #17191c;
    color: white;
    padding: 38px 42px;
    border-radius: 14px;
    margin-bottom: 28px;
}}

.header h1 {{
    margin: 0 0 12px 0;
    font-size: 30px;
}}

.header p {{
    margin: 5px 0;
    color: #d6d6d6;
}}

.summary {{
    display: grid;
    grid-template-columns:
        repeat(6, 1fr);
    gap: 14px;
    margin-bottom: 30px;
}}

.card {{
    background: white;
    border-radius: 12px;
    padding: 24px;
    box-shadow:
        0 2px 8px rgba(
            0,
            0,
            0,
            0.06
        );
}}

.card .number {{
    font-size: 32px;
    font-weight: 700;
    margin-bottom: 8px;
}}

.card .label {{
    color: #666;
    font-size: 14px;
}}

.card.critical {{
    border-top: 5px solid #7f1d1d;
}}

.card.high {{
    border-top: 5px solid #dc2626;
}}

.card.medium {{
    border-top: 5px solid #f59e0b;
}}

.card.low {{
    border-top: 5px solid #22c55e;
}}

.section {{
    background: white;
    border-radius: 14px;
    padding: 30px;
    margin-bottom: 25px;
    box-shadow:
        0 2px 8px rgba(
            0,
            0,
            0,
            0.06
        );
}}

.section h2 {{
    margin-top: 0;
}}

.finding {{
    border: 1px solid #e2e5e8;
    border-radius: 12px;
    margin-bottom: 22px;
    overflow: hidden;
}}

.finding-header {{
    display: flex;
    align-items: center;
    gap: 15px;
    padding: 18px 22px;
    background: #fafafa;
    border-bottom: 1px solid #e5e7eb;
}}

.finding-number {{
    font-weight: bold;
    color: #666;
}}

.finding-title {{
    flex: 1;
    font-size: 19px;
    font-weight: bold;
}}

.severity {{
    padding: 6px 13px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: bold;
}}

.severity.critical {{
    background: #fee2e2;
    color: #991b1b;
}}

.severity.high {{
    background: #ffedd5;
    color: #c2410c;
}}

.severity.medium {{
    background: #fef3c7;
    color: #92400e;
}}

.severity.low {{
    background: #dcfce7;
    color: #166534;
}}

.finding-meta {{
    display: grid;
    grid-template-columns:
        repeat(5, 1fr);
    gap: 15px;
    padding: 20px 22px;
    background: white;
}}

.finding-meta div {{
    display: flex;
    flex-direction: column;
    gap: 5px;
}}

.finding-meta strong {{
    color: #777;
    font-size: 12px;
}}

.finding-meta span {{
    font-size: 14px;
    word-break: break-all;
}}

.detail {{
    padding: 22px;
    border-top: 1px solid #eee;
}}

.detail h3 {{
    margin-top: 22px;
}}

.detail h3:first-child {{
    margin-top: 0;
}}

.detail p {{
    line-height: 1.7;
}}

pre {{
    background: #1f2937;
    color: #f3f4f6;
    padding: 18px;
    border-radius: 8px;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-word;
}}

.no-findings {{
    text-align: center;
    padding: 60px;
}}

.footer {{
    text-align: center;
    color: #888;
    font-size: 13px;
    margin-top: 30px;
}}

@media (
    max-width: 1000px
) {{

    body {{
        padding: 15px;
    }}

    .summary {{
        grid-template-columns:
            repeat(2, 1fr);
    }}

    .finding-meta {{
        grid-template-columns:
            repeat(2, 1fr);
    }}

}}

</style>

</head>

<body>

<div class="container">

    <div class="header">

        <h1>
            AI Source Code Security Report
        </h1>

        <p>
            AI 기반 소스코드 보안점검 결과
        </p>

        <p>
            생성일시:
            {_safe_text(generated_at)}
        </p>

    </div>


    <div class="summary">

        <div class="card">

            <div class="number">
                {total_count}
            </div>

            <div class="label">
                전체 취약점
            </div>

        </div>


        <div class="card critical">

            <div class="number">
                {critical_count}
            </div>

            <div class="label">
                Critical
            </div>

        </div>


        <div class="card high">

            <div class="number">
                {high_count}
            </div>

            <div class="label">
                High
            </div>

        </div>


        <div class="card medium">

            <div class="number">
                {medium_count}
            </div>

            <div class="label">
                Medium
            </div>

        </div>


        <div class="card low">

            <div class="number">
                {low_count}
            </div>

            <div class="label">
                Low
            </div>

        </div>


        <div class="card">

            <div class="number">
                {confirmed_count}
            </div>

            <div class="label">
                Confirmed
            </div>

        </div>

    </div>


    <div class="section">

        <h2>
            취약점 목록
        </h2>

        {findings_html}

    </div>


    <div class="footer">

        AI Source Code Security Analyzer

        <br>

        Rule Scanner + Local Qwen + RAG + Validation

    </div>

</div>

</body>

</html>
"""

    # ------------------------------------------------------------
    # 파일 저장
    # ------------------------------------------------------------

    report_path.write_text(
        html,
        encoding="utf-8"
    )

    return str(
        report_path
        )
