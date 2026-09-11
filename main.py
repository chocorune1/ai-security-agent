from scanner.source_loader import load_source_files
from scanner.rule_analyzer import analyze_source


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

        findings = analyze_source(source)

        for finding in findings:

            total_findings += 1

            print()
            print(f"[{finding['severity']}] {finding['type']}")
            print(f"파일 : {finding['file']}")
            print(f"라인 : {finding['line']}")
            print(f"근거 : {finding['evidence']}")
            print(f"설명 : {finding['description']}")
            print(f"조치 : {finding['recommendation']}")
            print("-----------------------------------")

    print()
    print("===================================")
    print(f"총 취약점: {total_findings}개")
    print("===================================")


if __name__ == "__main__":
    main()
