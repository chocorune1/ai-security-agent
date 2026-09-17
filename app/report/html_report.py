from pathlib import Path
from datetime import datetime
from html import escape

BASE_DIR = Path(__file__).resolve().parents[2]
REPORT_DIR = BASE_DIR / "reports"


def _safe_text(value):
    return "-" if value is None else escape(str(value))


def _severity(value):
    value = str(value or "MEDIUM").strip().upper()
    return value if value in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "MEDIUM"


def _status(value):
    return str(value or "REVIEW_REQUIRED").strip().upper()


def _count(findings, severity):
    return sum(1 for f in findings if _severity(f.get("severity")) == severity)


def generate_html_report(findings):
    findings = [dict(f) for f in (findings or []) if isinstance(f, dict)]

    for f in findings:
        f["severity"] = _severity(f.get("severity"))
        f["status"] = _status(f.get("status"))

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORT_DIR / (
        f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    )

    # =========================================================
    # 1. 전체 취약점 목록
    # =========================================================
    summary_rows = []

    for index, f in enumerate(findings, 1):
        severity = _severity(f.get("severity"))
        status = _status(f.get("status"))

        summary_rows.append(f"""
        <tr>
            <td class="center">{index}</td>
            <td><b>{_safe_text(f.get("type"))}</b></td>
            <td>
                <span class="severity {_severity(f.get("severity")).lower()}">
                    {_safe_text(severity)}
                </span>
            </td>
            <td>{_safe_text(f.get("file"))}</td>
            <td class="center">{_safe_text(f.get("line"))}</td>
            <td>
                <span class="status status-{status.lower()}">
                    {_safe_text(status)}
                </span>
            </td>
            <td>{_safe_text(f.get("confidence"))}</td>
            <td>{_safe_text(f.get("detection"))}</td>
        </tr>
        """)

    summary_table = "\n".join(summary_rows) if summary_rows else """
        <tr>
            <td colspan="8" class="empty-cell">취약점이 발견되지 않았습니다.</td>
        </tr>
    """

    # =========================================================
    # 2. 취약점 상세 결과
    # =========================================================
    detail_rows = []

    for index, f in enumerate(findings, 1):
        vuln_code = str(f.get("vulnerable_code") or "").strip()
        fixed_code = str(f.get("fixed_code") or "").strip()

        has_fix = bool(
            vuln_code
            and fixed_code
            and _status(f.get("status")) in {"CONFIRMED", "AI_CONFIRMED"}
        )

        fix_section = ""

        if has_fix:
            fix_section = f"""
            <div class="code-fix">
                <h3>🔧 수정 전 / 수정 후 코드</h3>
                <div class="code-grid">
                    <div>
                        <h4>❌ 수정 전 (취약 코드)</h4>
                        <pre class="before">{_safe_text(vuln_code)}</pre>
                    </div>
                    <div>
                        <h4>✅ 수정 후 (권장 코드)</h4>
                        <pre class="after">{_safe_text(fixed_code)}</pre>
                    </div>
                </div>
                <p class="code-note">
                    ※ 수정 후 코드는 AI가 해당 취약점에 대해 제안한 예시이며,
                    실제 적용 전 개발 환경에서 검토 및 테스트가 필요합니다.
                </p>
            </div>
            """

        ai_reason = (
            str(f.get("reason") or "").strip()
            or str(f.get("validation_reason") or "").strip()
        )

        detail_rows.append(f"""
        <article class="finding" id="finding-{index}">
            <div class="finding-header">
                <span class="number">#{index}</span>
                <span class="title">{_safe_text(f.get("type"))}</span>
                <span class="severity {_severity(f.get("severity")).lower()}">
                    {_safe_text(f.get("severity"))}
                </span>
            </div>

            <div class="meta">
                <div>
                    <b>파일</b>
                    <span>{_safe_text(f.get("file"))}</span>
                </div>
                <div>
                    <b>라인</b>
                    <span>{_safe_text(f.get("line"))}</span>
                </div>
                <div>
                    <b>탐지 방법</b>
                    <span>{_safe_text(f.get("detection"))}</span>
                </div>
                <div>
                    <b>상태</b>
                    <span>{_safe_text(f.get("status"))}</span>
                </div>
                <div>
                    <b>신뢰도</b>
                    <span>{_safe_text(f.get("confidence"))}</span>
                </div>
            </div>

            <div class="detail">
                <h3>🔎 취약 코드 / 증거</h3>
                <pre>{_safe_text(f.get("evidence"))}</pre>

                <h3>설명</h3>
                <p>{_safe_text(f.get("description"))}</p>

                <h3>AI 판단 근거</h3>
                <p>{_safe_text(ai_reason)}</p>

                <h3>Validation 판단</h3>
                <p>{_safe_text(f.get("validation_reason"))}</p>

                <h3>🛠 개선 방법</h3>
                <p>{_safe_text(f.get("recommendation"))}</p>

                <h3>🎯 공격 시나리오</h3>
                <div class="guide-box attack-box">
                    {_safe_text(f.get("attack_scenario"))}
                </div>

                <h3>🧪 Regression Test 방법</h3>
                <div class="guide-box regression-box">
                    <p class="guide-note">※ 아래 내용은 수정 후 취약점이 제거되었는지 확인하기 위한 수동 검증 가이드입니다. AI가 테스트를 실행한 결과가 아닙니다.</p>
                    {_safe_text(f.get("regression_test"))}
                </div>

                {fix_section}
            </div>
        </article>
        """)

    findings_html = (
        "\n".join(detail_rows)
        if detail_rows
        else '<div class="empty">취약점이 발견되지 않았습니다.</div>'
    )

    total = len(findings)
    confirmed = sum(
        1
        for f in findings
        if _status(f.get("status")) in {"CONFIRMED", "AI_CONFIRMED"}
    )

    html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AI Source Code Security Report</title>

<style>
* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    padding: 36px;
    background: #f4f6f8;
    color: #222;
    font-family: Arial, "Malgun Gothic", sans-serif;
}}

.container {{
    max-width: 1500px;
    margin: auto;
}}

.header {{
    background: #17191c;
    color: #fff;
    padding: 34px 40px;
    border-radius: 14px;
    margin-bottom: 24px;
}}

.header h1 {{
    margin: 0 0 10px;
    font-size: 30px;
}}

.header p {{
    margin: 5px 0;
    color: #d6d6d6;
}}

.summary {{
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 14px;
    margin-bottom: 28px;
}}

.card {{
    background: #fff;
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 2px 8px rgba(0,0,0,.06);
}}

.card .number {{
    font-size: 30px;
    font-weight: 700;
}}

.card .label {{
    color: #666;
    font-size: 13px;
    margin-top: 6px;
}}

/* =========================================================
   전체 취약점 목록
   ========================================================= */

.overview {{
    background: #fff;
    border-radius: 14px;
    padding: 24px;
    margin-bottom: 32px;
    box-shadow: 0 2px 8px rgba(0,0,0,.06);
}}

.overview h2 {{
    margin: 0 0 18px;
    font-size: 22px;
}}

.table-wrap {{
    overflow-x: auto;
}}

.vulnerability-table {{
    width: 100%;
    border-collapse: collapse;
    min-width: 1000px;
}}

.vulnerability-table th {{
    background: #f1f3f5;
    color: #555;
    font-size: 13px;
    font-weight: 700;
    padding: 13px 12px;
    border-bottom: 2px solid #dfe3e8;
    text-align: left;
    white-space: nowrap;
}}

.vulnerability-table td {{
    padding: 13px 12px;
    border-bottom: 1px solid #e8eaed;
    font-size: 13px;
    vertical-align: middle;
}}

.vulnerability-table tbody tr:hover {{
    background: #f8fafc;
}}

.center {{
    text-align: center !important;
}}

.severity {{
    display: inline-block;
    padding: 5px 11px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    white-space: nowrap;
}}

.critical {{
    background: #fee2e2;
    color: #991b1b;
}}

.high {{
    background: #ffedd5;
    color: #c2410c;
}}

.medium {{
    background: #fef3c7;
    color: #92400e;
}}

.low {{
    background: #dcfce7;
    color: #166534;
}}

.status {{
    display: inline-block;
    padding: 5px 9px;
    border-radius: 6px;
    background: #eef2f7;
    color: #4b5563;
    font-size: 11px;
    font-weight: 700;
    white-space: nowrap;
}}

.status-confirmed,
.status-ai_confirmed {{
    background: #dcfce7;
    color: #166534;
}}

.status-review_required {{
    background: #fef3c7;
    color: #92400e;
}}

.empty-cell {{
    text-align: center;
    padding: 35px !important;
    color: #777;
}}

/* =========================================================
   취약점 상세
   ========================================================= */

.finding {{
    background: #fff;
    border: 1px solid #e2e5e8;
    border-radius: 12px;
    margin-bottom: 22px;
    overflow: hidden;
}}

.finding-header {{
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 18px 22px;
    background: #fafafa;
    border-bottom: 1px solid #e5e7eb;
}}

.finding-header .number {{
    font-size: 14px;
    color: #666;
}}

.title {{
    flex: 1;
    font-size: 19px;
    font-weight: 700;
}}

.meta {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 15px;
    padding: 18px 22px;
}}

.meta div {{
    display: flex;
    flex-direction: column;
    gap: 5px;
}}

.meta b {{
    font-size: 12px;
    color: #777;
}}

.meta span {{
    font-size: 14px;
    word-break: break-all;
}}

.detail {{
    padding: 22px;
    border-top: 1px solid #eee;
}}

.detail h3 {{
    margin: 22px 0 9px;
}}

.detail h3:first-child {{
    margin-top: 0;
}}

.detail p {{
    line-height: 1.7;
}}

.guide-box {{
    padding: 16px 18px;
    border-radius: 8px;
    line-height: 1.75;
    white-space: pre-wrap;
    word-break: break-word;
}}

.attack-box {{
    background: #fff7ed;
    border: 1px solid #fed7aa;
}}

.regression-box {{
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
}}

.guide-note {{
    margin: 0 0 10px !important;
    color: #666;
    font-size: 12px;
}}

pre {{
    background: #1f2937;
    color: #f3f4f6;
    padding: 16px;
    border-radius: 8px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-word;
}}

.code-fix {{
    margin-top: 28px;
    padding: 20px;
    border: 1px solid #dfe3e8;
    border-radius: 10px;
    background: #fafbfc;
}}

.code-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 18px;
}}

.code-grid h4 {{
    margin: 8px 0;
}}

.code-grid pre {{
    min-height: 130px;
}}

.before {{
    border-left: 5px solid #dc2626;
}}

.after {{
    border-left: 5px solid #16a34a;
}}

.code-note {{
    font-size: 12px;
    color: #777;
    margin-bottom: 0;
}}

.fix-footer-note {{
    margin: 24px 0;
    padding: 14px 18px;
    text-align: center;
    color: #666;
    background: #f8f8f8;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    font-size: 13px;
}}

.empty {{
    padding: 60px;
    text-align: center;
    background: #fff;
    border-radius: 12px;
}}

.footer {{
    text-align: center;
    color: #888;
    font-size: 12px;
    margin-top: 25px;
}}

@media(max-width:1000px) {{
    body {{
        padding: 15px;
    }}

    .summary {{
        grid-template-columns: repeat(2, 1fr);
    }}

    .meta {{
        grid-template-columns: repeat(2, 1fr);
    }}

    .code-grid {{
        grid-template-columns: 1fr;
    }}
}}
</style>
</head>

<body>
<div class="container">

<div class="header">
    <h1>AI Source Code Security Report</h1>
    <p>AI 기반 소스코드 보안점검 결과</p>
    <p>생성일시: {_safe_text(generated_at)}</p>
</div>

<div class="summary">
    <div class="card">
        <div class="number">{total}</div>
        <div class="label">전체 취약점</div>
    </div>

    <div class="card">
        <div class="number">{_count(findings, "CRITICAL")}</div>
        <div class="label">Critical</div>
    </div>

    <div class="card">
        <div class="number">{_count(findings, "HIGH")}</div>
        <div class="label">High</div>
    </div>

    <div class="card">
        <div class="number">{_count(findings, "MEDIUM")}</div>
        <div class="label">Medium</div>
    </div>

    <div class="card">
        <div class="number">{_count(findings, "LOW")}</div>
        <div class="label">Low</div>
    </div>

    <div class="card">
        <div class="number">{confirmed}</div>
        <div class="label">Confirmed</div>
    </div>
</div>

<!-- =======================================================
     전체 취약점 목록
     ======================================================= -->

<section class="overview">
    <h2>📋 전체 취약점 목록</h2>

    <div class="table-wrap">
        <table class="vulnerability-table">
            <thead>
                <tr>
                    <th class="center">No.</th>
                    <th>취약점 유형</th>
                    <th>Severity</th>
                    <th>파일</th>
                    <th class="center">라인</th>
                    <th>상태</th>
                    <th>신뢰도</th>
                    <th>탐지 방법</th>
                </tr>
            </thead>

            <tbody>
                {summary_table}
            </tbody>
        </table>
    </div>
</section>

<!-- =======================================================
     취약점 상세 결과
     ======================================================= -->

<section>
    <h2>🔎 취약점 상세 결과</h2>
    {findings_html}
</section>

{(
    '<div class="fix-footer-note">'
    '최종 취약점으로 확정되지 않은 건은 수정 코드 예시를 생성하지 않았습니다.'
    '</div>'
    if any(
        _status(f.get("status")) not in {"CONFIRMED", "AI_CONFIRMED"}
        for f in findings
    )
    else ''
)}

<div class="footer">
    AI Source Code Security Analyzer · Rule Scanner + Qwen + RAG + Validation
</div>

</div>
</body>
</html>
"""

    report_path.write_text(html, encoding="utf-8")
    return str(report_path)
