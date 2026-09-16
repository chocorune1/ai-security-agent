# CWE-352: Cross-Site Request Forgery (CSRF)

## Overview
CSRF occurs when a web application accepts a state-changing request based on ambient browser credentials without sufficiently verifying that the request was intentionally initiated by the user.

## Detection hints
- State-changing POST/PUT/PATCH/DELETE endpoints.
- Cookie-based authentication.
- Missing or ineffective CSRF tokens.
- Sensitive actions lacking Origin/Referer or equivalent protections where appropriate.

A POST request alone is not proof of CSRF.

## False-positive considerations
- Framework-provided CSRF protection is active.
- A strong per-request token is required and server-validated.
- Authentication uses credentials not automatically attached by a cross-site browser request.
- Appropriate SameSite cookie controls materially mitigate the browser attack path.

## Remediation
- Use framework-provided CSRF protection.
- Require unpredictable, server-validated CSRF tokens for protected browser state changes.
- Configure `SameSite`, `Secure`, and `HttpOnly` appropriately.
- Avoid state changes through GET requests.

## Review note
CSRF assessment depends on authentication architecture and browser behavior, so a rule hit often needs LLM/manual validation.
