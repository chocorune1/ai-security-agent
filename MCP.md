# MCP server

The MCP server exposes two tools:

- `security_scan(source_dir)` scans supported files recursively in a directory.
- `security_scan_file(file_path)` scans exactly one `.java`, `.js`, or `.jsp` file.

Both call the existing
`app/agent/security_agent.py` pipeline used by Streamlit, including source
loading, rule and AI analysis, validation, finding merge, and HTML report
generation. Streamlit also supports both folder and single-file scans.

## Install and run

From the repository root, activate the project's existing Python environment
and install the MCP SDK/Inspector command:

```bash
python -m pip install -r requirements-mcp.txt
python app/mcp_server.py
```

The process waits silently for an MCP client over standard input/output. The
client must use `stdio`; do not start this server in a terminal expecting a web
page. Ensure the existing project dependencies (including the Qwen/RAG
dependencies and their configuration) are installed in this same environment.

To test with the official SDK Inspector (in the same activated environment):

```bash
mcp dev app/mcp_server.py
```

Call `security_scan` with an absolute directory path, or `security_scan_file`
with an absolute file path including its filename. The single-file tool only
accepts `.java`, `.js`, and `.jsp`. Both tools write the HTML report under the
project's existing `reports/` directory.

## Cline configuration

In VS Code, open Cline's **MCP Servers** view, choose **Configure**, and select
**Configure MCP Servers**. Add this entry to `cline_mcp_settings.json`, keeping
any existing server entries and replacing the paths with the absolute VDI paths
to the Python environment and repository:

```json
{
  "mcpServers": {
    "ai-security-agent": {
      "command": "C:\\path\\to\\project-venv\\Scripts\\python.exe",
      "args": ["C:\\path\\to\\ai-security-agent\\app\\mcp_server.py"],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

After saving, confirm the server is enabled in **Installed** and that
`security_scan_file` appears in its tool list. In Cline chat, request a scan
using the absolute file path, for example: “Use `security_scan_file` to scan
`C:\\project\\src\\Login.java` and summarize the findings.”

The configured Python must have the project's dependencies and the MCP SDK
installed, and it must be able to reach the Qwen endpoint configured by the
project. Cline's own model connection does not supply Qwen settings to the
Python server.

## Claude Desktop configuration

Replace the paths below with the absolute repository path and the Python
executable from the environment where both the project dependencies and MCP
SDK are installed. Add this entry to Claude Desktop's `claude_desktop_config.json`
under `mcpServers`:

```json
{
  "mcpServers": {
    "ai-security-agent": {
      "command": "/absolute/path/to/project-venv/bin/python",
      "args": ["/absolute/path/to/ai-security-agent/app/mcp_server.py"]
    }
  }
}
```

On Windows, use the environment's `Scripts\\python.exe` path. Restart the MCP
client after saving the configuration. Then ask it to run `security_scan` with
the absolute path to the source directory. The tool returns the findings and
the HTML report path; it does not return the report file contents.

## Streamlit

Continue to start the UI as before:

```bash
streamlit run web/app.py
```
