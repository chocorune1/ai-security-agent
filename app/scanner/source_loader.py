from pathlib import Path


SUPPORTED_EXTENSIONS = {
    ".java",
    ".js",
    ".jsp",
}


def load_source_files(source_path):
    """
    지정된 파일 하나 또는 폴더의 Java, JavaScript, JSP 파일을 읽는다.
    """

    source_path = Path(source_path).expanduser()

    if not source_path.exists():
        raise FileNotFoundError(f"Source path not found: {source_path}")

    source_files = []

    if source_path.is_file():
        if source_path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            supported = ", ".join(sorted(SUPPORTED_EXTENSIONS))
            raise ValueError(
                f"Unsupported source file: {source_path}. Supported extensions: {supported}"
            )
        file_paths = [source_path]
    elif source_path.is_dir():
        file_paths = source_path.rglob("*")
    else:
        raise ValueError(f"Source path is neither a file nor a directory: {source_path}")

    for file_path in file_paths:

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
