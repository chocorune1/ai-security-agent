from scanner.source_loader import load_source_files


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

    for source in source_files:
        print(f"파일명   : {source['file_name']}")
        print(f"확장자   : {source['extension']}")
        print(f"경로     : {source['file_path']}")
        print(f"코드 길이: {len(source['content'])} characters")
        print("-----------------------------------")


if __name__ == "__main__":
    main()
