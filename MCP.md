# MCP server

The MCP server exposes `security_scan(source_dir)`. It calls the existing
`app/agent/security_agent.py` pipeline used by Streamlit, including source
loading, rule and AI analysis, validation, finding merge, and HTML report
generation. Streamlit remains available and is not changed.

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

Call `security_scan` with an absolute directory path. The scanner recursively
reads `.java`, `.js`, and `.jsp` files and writes the HTML report under the
project's existing `reports/` directory.

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
