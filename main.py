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

    total_findings = 0

    for source in source_files:

        print(f"[분석] {source['file_name']}")

        # --------------------------------
        # 1. Rule 기반 분석
        # --------------------------------
        rule_findings = analyze_source(source)

        print()
        print(f"Rule Scanner 발견: {len(rule_findings)}개")

        for finding in rule_findings:

            total_findings += 1

            print()
            print(f"[Rule] {finding['severity']} - {finding['type']}")
            print(f"파일 : {finding['file']}")
            print(f"라인 : {finding['line']}")
            print(f"근거 : {finding['evidence']}")

        # --------------------------------
        # 2. Qwen AI 분석
        # --------------------------------
        print()
        print("Qwen AI 분석 중...")
        print()

        ai_result = analyze_with_qwen(
            source,
            rule_findings
        )

        print("========== Qwen 분석 결과 ==========")
        print(ai_result)
        print("====================================")

    print()
    print("===================================")
    print(f"Rule Scanner 총 발견 취약점: {total_findings}개")
    print("===================================")


if __name__ == "__main__":
    main()
