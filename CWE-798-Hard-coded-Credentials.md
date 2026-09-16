# CWE-798: Use of Hard-coded Credentials

## Overview
Hard-coded credentials occur when passwords, API keys, tokens, private secrets, or other authentication material are embedded directly in source code.

## Detection hints
Look for assignments/constants containing `password`, `passwd`, `pwd`, `secret`, `token`, `apiKey`, `api_key`, private keys, or credential-like values.

## False-positive considerations
- Obvious placeholders such as `CHANGE_ME` may not be real credentials.
- A variable named `password` may hold user-provided input rather than a hard-coded secret.
- Public identifiers are not necessarily credentials.
- Documentation examples may intentionally use fake values.

## Remediation
- Store secrets outside source code using protected runtime configuration or an approved secret manager.
- Rotate credentials that may already have been exposed.
- Never log secrets.
- Separate development/test/production credentials.
- Apply least privilege.

## Example
```java
// Risky
private String dbPassword = "admin1234";

// Safer pattern
String dbPassword = System.getenv("DB_PASSWORD");
```
