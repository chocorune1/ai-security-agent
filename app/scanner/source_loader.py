from pathlib import Path


SUPPORTED_EXTENSIONS = {
    ".java",
    ".js",
    ".jsp",
}


def load_source_files(source_dir):
    """
    지정된 폴더에서 Java, JavaScript, JSP 소스 파일을 찾아 읽는다.
    """

    source_dir = Path(source_dir)

    if not source_dir.exists():
        raise FileNotFoundError(
            f"Source directory not found: {source_dir}"
        )

    source_files = []

    for file_path in source_dir.rglob("*"):

        if not file_path.is_file():
            continue

        if file_path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue

        try:
            content = file_path.read_text(
                encoding="utf-8"
            )
        except UnicodeDecodeError:
            content = file_path.read_text(
                encoding="cp949"
            )

        source_files.append({
            "file_name": file_path.name,
            "file_path": str(file_path),
            "extension": file_path.suffix.lower(),
            "content": content,
        })

    return source_files
