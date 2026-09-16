# CWE-89: SQL Injection

## Overview
SQL injection occurs when untrusted input is incorporated into SQL syntax instead of being kept as data.

## Detection hints
- SQL strings built with `+`, formatting, interpolation, or concatenation using external input.
- `executeQuery`, `executeUpdate`, or similar execution after dynamic SQL construction.
- JSP scriptlets concatenating request parameters into SQL.
- Check whether attacker-controlled data can become SQL syntax.

## False-positive considerations
- SQL fragments may contain only fixed developer-controlled values.
- Prepared statements may use placeholders and bind values separately.
- A framework may safely parameterize the value before execution.

## Remediation
- Use parameterized/prepared statements and bind values separately.
- Do not concatenate untrusted input into SQL.
- For dynamic identifiers, map user choices to a fixed allowlist.
- Apply least-privilege database permissions.

## Example
```java
// Vulnerable
String sql = "SELECT * FROM USERS WHERE USER_ID = '" + userId + "'";
PreparedStatement stmt = conn.prepareStatement(sql);

// Safer
String sql = "SELECT * FROM USERS WHERE USER_ID = ?";
PreparedStatement stmt = conn.prepareStatement(sql);
stmt.setString(1, userId);
```

## Mapping
- OWASP: Injection category
