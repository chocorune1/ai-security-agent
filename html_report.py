from pathlib import Path
from datetime import datetime
from html import escape


BASE_DIR = Path(__file__).resolve().parents[2]
REPORT_DIR = BASE_DIR / "reports"


def generate_html_report(findings, output_file=None):

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    if output_file is None:
        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        output_file = (
            REPORT_DIR
            / f"security_report_{timestamp}.html"
        )

    total_count = len(findings)

    critical_count = sum(
        1
        for finding in findings
        if finding.get("severity") == "CRITICAL"
    )

    high_count = sum(
        1
        for finding in findings
        if finding.get("severity") == "HIGH"
    )

    medium_count = sum(
        1
        for finding in findings
        if finding.get("severity") == "MEDIUM"
    )

    low_count = sum(
        1
        for finding in findings
        if finding.get("severity") == "LOW"
    )

    confirmed_count = sum(
        1
        for finding in findings
        if finding.get("status") == "CONFIRMED"
    )

    review_count = sum(
        1
        for finding in findings
        if finding.get("status") == "REVIEW_REQUIRED"
    )

    rows = []

    for index, finding in enumerate(
        findings,
        start=1
    ):

        severity = finding.get(
            "severity",
            "-"
        )

        if severity == "CRITICAL":
            severity_class = "critical"
        elif severity == "HIGH":
            severity_class = "high"
        elif severity == "MEDIUM":
            severity_class = "medium"
        else:
            severity_class = "low"

        rows.append(
            f"""
            <tr>
                <td>{index}</td>

                <td>
                    <strong>
                        {escape(str(
                            finding.get(
                                "type",
                                "-"
                            )
                        ))}
                    </strong>
                </td>

                <td>
                    <span class="severity {severity_class}">
                        {escape(str(severity))}
                    </span>
                </td>

                <td>
                    {escape(str(
                        finding.get(
                            "file",
                            "-"
                        )
                    ))}
                </td>

                <td>
                    {escape(str(
                        finding.get(
                            "line",
                            "-"
                        )
                    ))}
                </td>

                <td>
                    {escape(str(
                        finding.get(
                            "detection",
                            "-"
                        )
                    ))}
                </td>

                <td>
                    {escape(str(
                        finding.get(
                            "status",
                            "-"
                        )
                    ))}
                </td>
            </tr>
            """
        )

    detail_sections = []

    for index, finding in enumerate(
        findings,
        start=1
    ):

        detail_sections.append(
            f"""
            <div class="finding-card">

                <h2>
                    [{index}]
                    {escape(str(
                        finding.get(
                            "type",
                            "-"
                        )
                    ))}
                </h2>

                <div class="detail-grid">

                    <div>
                        <span class="label">
                            심각도
                        </span>
                        <span class="value">
                            {escape(str(
                                finding.get(
                                    "severity",
                                    "-"
                                )
                            ))}
                        </span>
                    </div>

                    <div>
                        <span class="label">
                            상태
                        </span>
                        <span class="value">
                            {escape(str(
                                finding.get(
                                    "status",
                                    "-"
                                )
                            ))}
                        </span>
                    </div>

                    <div>
                        <span class="label">
                            파일
                        </span>
                        <span class="value">
                            {escape(str(
                                finding.get(
                                    "file",
                                    "-"
                                )
                            ))}
                        </span>
                    </div>

                    <div>
                        <span class="label">
                            라인
                        </span>
                        <span class="value">
                            {escape(str(
                                finding.get(
                                    "line",
                                    "-"
                                )
                            ))}
                        </span>
                    </div>

                    <div>
                        <span class="label">
                            탐지 방법
                        </span>
                        <span class="value">
                            {escape(str(
                                finding.get(
                                    "detection",
                                    "-"
                                )
                            ))}
                        </span>
                    </div>

                    <div>
                        <span class="label">
                            신뢰도
                        </span>
                        <span class="value">
                            {escape(str(
                                finding.get(
                                    "confidence",
                                    "-"
                                )
                            ))}
                        </span>
                    </div>

                </div>

                <h3>탐지 증거</h3>

                <pre>{escape(str(
                    finding.get(
                        "evidence",
                        "-"
                    )
                ))}</pre>

                <h3>취약점 설명</h3>

                <p>
                    {escape(str(
                        finding.get(
                            "description",
                            "-"
                        )
                    ))}
                </p>

                <h3>AI 판단 근거</h3>

                <p>
                    {escape(str(
                        finding.get(
                            "reason",
                            "-"
                        )
                    ))}
                </p>

                <h3>개선 방법</h3>

                <p>
                    {escape(str(
                        finding.get(
                            "recommendation",
                            "-"
                        )
                    ))}
                </p>

            </div>
            """
        )

    html = f"""
<!DOCTYPE html>

<html lang="ko">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>AI Source Code Security Report</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    padding: 0;

    font-family:
        "Malgun Gothic",
        "Noto Sans KR",
        Arial,
        sans-serif;

    background: #f4f6f8;
    color: #222;
}}

.container {{
    width: 1200px;
    max-width: 95%;

    margin: 40px auto;
}}

.header {{
    background: #1f2937;
    color: white;

    padding: 32px;

    border-radius: 12px;

    margin-bottom: 24px;
}}

.header h1 {{
    margin: 0 0 10px 0;
    font-size: 30px;
}}

.header p {{
    margin: 4px 0;
    color: #d1d5db;
}}

.summary {{
    display: grid;

    grid-template-columns:
        repeat(5, 1fr);

    gap: 16px;

    margin-bottom: 24px;
}}

.summary-card {{
    background: white;

    padding: 22px;

    border-radius: 10px;

    box-shadow:
        0 2px 8px
        rgba(0, 0, 0, 0.08);
}}

.summary-card .number {{
    font-size: 30px;
    font-weight: bold;
}}

.summary-card .title {{
    color: #666;
    margin-top: 6px;
}}

.section {{
    background: white;

    padding: 24px;

    border-radius: 12px;

    margin-bottom: 24px;

    box-shadow:
        0 2px 8px
        rgba(0, 0, 0, 0.06);
}}

.section h2 {{
    margin-top: 0;
}}

table {{
    width: 100%;

    border-collapse: collapse;
}}

th {{
    background: #f1f3f5;

    padding: 12px;

    text-align: left;

    border-bottom:
        2px solid #ddd;
}}

td {{
    padding: 12px;

    border-bottom:
        1px solid #eee;

    vertical-align: top;
}}

.severity {{
    display: inline-block;

    padding: 4px 9px;

    border-radius: 5px;

    font-weight: bold;

    font-size: 12px;
}}

.severity.critical {{
    background: #fee2e2;
    color: #991b1b;
}}

.severity.high {{
    background: #ffedd5;
    color: #9a3412;
}}

.severity.medium {{
    background: #fef3c7;
    color: #92400e;
}}

.severity.low {{
    background: #dcfce7;
    color: #166534;
}}

.finding-card {{
    border: 1px solid #ddd;

    border-radius: 10px;

    padding: 24px;

    margin-bottom: 20px;
}}

.finding-card h2 {{
    margin-top: 0;
}}

.finding-card h3 {{
    margin-top: 24px;
    margin-bottom: 8px;
}}

.detail-grid {{
    display: grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap: 12px;

    background: #f8f9fa;

    padding: 16px;

    border-radius: 8px;
}}

.detail-grid > div {{
    display: flex;

    flex-direction: column;

    gap: 4px;
}}

.label {{
    font-size: 12px;

    color: #777;
}}

.value {{
    font-weight: bold;
}}

pre {{
    background: #1e1e1e;

    color: #f5f5f5;

    padding: 16px;

    border-radius: 8px;

    overflow-x: auto;

    white-space: pre-wrap;
}}

.footer {{
    text-align: center;

    color: #888;

    padding: 20px;
}}

@media print {{

    body {{
        background: white;
    }}

    .container {{
        width: 100%;
        max-width: 100%;
        margin: 0;
    }}

    .header {{
        border-radius: 0;
    }}

    .finding-card {{
        page-break-inside: avoid;
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
            {datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )}
        </p>

    </div>


    <div class="summary">

        <div class="summary-card">
            <div class="number">
                {total_count}
            </div>
            <div class="title">
                전체 취약점
            </div>
        </div>

        <div class="summary-card">
            <div class="number">
                {critical_count}
            </div>
            <div class="title">
                Critical
            </div>
        </div>

        <div class="summary-card">
            <div class="number">
                {high_count}
            </div>
            <div class="title">
                High
            </div>
        </div>

        <div class="summary-card">
            <div class="number">
                {medium_count}
            </div>
            <div class="title">
                Medium
            </div>
        </div>

        <div class="summary-card">
            <div class="number">
                {confirmed_count}
            </div>
            <div class="title">
                Confirmed
            </div>
        </div>

    </div>


    <div class="section">

        <h2>
            취약점 목록
        </h2>

        <table>

            <thead>

                <tr>
                    <th>No.</th>
                    <th>취약점</th>
                    <th>심각도</th>
                    <th>파일</th>
                    <th>라인</th>
                    <th>탐지 방법</th>
                    <th>상태</th>
                </tr>

            </thead>

            <tbody>

                {"".join(rows)}

            </tbody>

        </table>

    </div>


    <div class="section">

        <h2>
            상세 분석 결과
        </h2>

        {"".join(detail_sections)}

    </div>


    <div class="footer">

        AI Source Code Security Agent

    </div>

</div>

</body>

</html>
"""

    output_file = Path(output_file)

    output_file.write_text(
        html,
        encoding="utf-8"
    )

    return output_file
