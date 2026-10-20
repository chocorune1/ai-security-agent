"""Run the existing security agent against a GitLab checkout."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from agent.security_agent import SecurityAgent


BASE_DIR = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the AI Security Agent against source files in a directory."
    )
    parser.add_argument(
        "--source-dir",
        default=os.getenv("CI_PROJECT_DIR", str(BASE_DIR)),
        help="Directory to scan (defaults to CI_PROJECT_DIR or the repository root).",
    )
    args = parser.parse_args()

    source_dir = Path(args.source_dir).expanduser().resolve()
    if not source_dir.is_dir():
        parser.error(f"Source directory does not exist or is not a directory: {source_dir}")

    result = SecurityAgent(source_dir=str(source_dir)).run()
    findings = result.get("findings") or []
    report_dir = BASE_DIR / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    result_path = report_dir / "security_scan.json"
    payload = {
        "source_count": result.get("source_count", 0),
        "finding_count": len(findings),
        "findings": findings,
        "report_file": str(result.get("report_file")) if result.get("report_file") else None,
    }
    result_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )

    source_count = int(result.get("source_count", 0))
    print(f"\n분석 파일: {source_count}개")
    print(f"발견 항목: {len(findings)}개")
    print(f"JSON 결과: {result_path}")
    if payload["report_file"]:
        print(f"HTML 보고서: {payload['report_file']}")

    if source_count == 0:
        print("오류: 점검할 Java, JavaScript, JSP 파일을 찾지 못했습니다.")
        return 2

    for index, finding in enumerate(findings, start=1):
        print(
            f"[{index}] {finding.get('severity', '-')} / "
            f"{finding.get('status', '-')} / {finding.get('type', '-')} / "
            f"{finding.get('file', '-')}: {finding.get('line', '-')}"
        )

    fail_on = {
        item.strip().upper()
        for item in os.getenv("SECURITY_FAIL_ON", "CRITICAL,HIGH").split(",")
        if item.strip()
    }
    confirmed_statuses = {"CONFIRMED", "AI_CONFIRMED"}
    blocking_findings = [
        finding
        for finding in findings
        if str(finding.get("severity") or "").upper() in fail_on
        and str(finding.get("status") or "").upper() in confirmed_statuses
    ]
    if blocking_findings:
        print(
            f"오류: 확정된 {', '.join(sorted(fail_on))} 심각도 취약점 "
            f"{len(blocking_findings)}개가 있어 파이프라인을 실패 처리합니다."
        )
        return 1

    print("차단 기준에 해당하는 확정 취약점이 없습니다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
