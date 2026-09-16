# CWE-78: OS Command Injection

## Overview
OS command injection occurs when untrusted input reaches operating-system process execution in a way that lets an attacker influence command execution.

## Detection hints
- Java `Runtime.getRuntime().exec(...)`.
- `ProcessBuilder(...)` with user-controlled values.
- Shell execution such as `sh -c`, `bash -c`, `cmd /c`, or PowerShell.
- Command strings assembled with concatenation.

## False-positive considerations
- Executable and arguments may be fixed constants.
- Input may be restricted by a strict server-side allowlist.
- `Runtime.exec` alone is a review signal, not proof of exploitability.

## Remediation
- Prefer an in-process library/API over OS commands.
- Use fixed executables and structured arguments.
- Allowlist permitted operations and identifiers.
- Never pass untrusted strings to a shell interpreter.
- Run processes with minimum required OS privileges.

## Example
```java
// Risky
Runtime.getRuntime().exec(command);
```
