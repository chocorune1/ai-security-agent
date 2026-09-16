# OWASP A03: Injection

## Overview
Injection occurs when untrusted data is interpreted as part of a command or query language rather than remaining data.

## Relevant examples
- SQL injection
- OS command injection
- LDAP injection
- Expression/template injection
- Other interpreter-oriented injection classes

## Detection questions
1. What is the untrusted source?
2. What interpreter, parser, query engine, or command processor receives it?
3. Does the value become syntax rather than data?
4. Is parameterization, a safe API, or a strict allowlist used?
5. Is the data flow reachable?

## Preferred defenses
- Parameterized database APIs.
- Safe process APIs; avoid shell interpretation.
- Structured APIs instead of string-based command construction.
- Contextual encoding at output boundaries where appropriate.
- Allowlists for values that legitimately select syntax elements.
- Least privilege for downstream services.

## Important scanner rule
Do not classify an issue solely because a keyword such as `PreparedStatement`, `exec`, or `query` appears. Analyze source-to-sink data flow and whether the input is interpreted as syntax.

## Mappings
- CWE-89: SQL Injection
- CWE-78: OS Command Injection
- CWE-79: XSS is commonly discussed with injection risks, but its primary CWE is improper neutralization during web page generation.
