from agent.security_agent import SecurityAgent


def main():

    agent = SecurityAgent(
        source_dir="../data/source"
    )

    result = agent.run()

    findings = result.get(
        "findings",
        []
    )

    print()
    print("=" * 70)
    print("최종 보안 점검 결과")
    print("=" * 70)

    if not findings:

        print(
            "취약점이 발견되지 않았습니다."
        )

        return

    for index, finding in enumerate(
        findings,
        start=1
    ):

        print()
        print(
            f"[{index}]"
        )

        print(
            f"취약점: "
            f"{finding.get('type', '-')}"
        )

        print(
            f"심각도: "
            f"{finding.get('severity', '-')}"
        )

        print(
            f"파일: "
            f"{finding.get('file', '-')}"
        )

        print(
            f"라인: "
            f"{finding.get('line', '-')}"
        )

        print(
            f"탐지 방법: "
            f"{finding.get('detection', '-')}"
        )

        print(
            f"상태: "
            f"{finding.get('status', '-')}"
        )

        print(
            f"신뢰도: "
            f"{finding.get('confidence', '-')}"
        )

        print(
            f"증거: "
            f"{finding.get('evidence', '-')}"
        )

        print(
            f"설명: "
            f"{finding.get('description', '-')}"
        )

        print(
            f"판단 근거: "
            f"{finding.get('reason', '-')}"
        )

        print(
            f"개선 방법: "
            f"{finding.get('recommendation', '-')}"
        )

        print("-" * 70)


if __name__ == "__main__":
    main()
