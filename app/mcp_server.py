"""MCP stdio server for the existing AI Security Agent."""

from __future__ import annotations

import io
import json
import sys
import threading
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

from mcp.server import MCPServer


APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from agent.security_agent import SecurityAgent  # noqa: E402


mcp = MCPServer("AI Security Agent")
_agent_stdout_lock = threading.Lock()


@mcp.tool()
def security_scan(source_dir: str) -> str:
    """Scan a local source directory containing Java, JavaScript, or JSP files.

    Runs the same SecurityAgent pipeline used by Streamlit and returns a JSON
    string with source count, findings, and the generated HTML report path.
    The path is read for analysis; the report is written to the project's
    existing reports directory.
    """
    scan_path = Path(source_dir).expanduser().resolve()
    if not scan_path.exists():
        raise ValueError(f"Source directory does not exist: {scan_path}")
    if not scan_path.is_dir():
        raise ValueError(f"Source path is not a directory: {scan_path}")

    # SecurityAgent prints progress to stdout. Keep MCP's stdio protocol clean.
    with _agent_stdout_lock, redirect_stdout(io.StringIO()):
        result: dict[str, Any] = SecurityAgent(source_dir=str(scan_path)).run()

    report_path = result.get("report_file")
    payload = {
        "source_count": result.get("source_count", 0),
        "finding_count": len(result.get("findings") or []),
        "findings": result.get("findings") or [],
        "report_file": str(report_path) if report_path else None,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


if __name__ == "__main__":
    # MCP clients launch this process over stdio; do not print to stdout here.
    mcp.run(transport="stdio")
