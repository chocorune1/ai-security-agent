# CWE-918: Server-Side Request Forgery (SSRF)

## Overview
SSRF occurs when an application makes a server-side network request to a destination that an attacker can influence.

## Detection hints
- User-controlled URLs passed to HTTP clients.
- URL/URI APIs, REST clients, proxy/fetch functions.
- Webhook, image import, URL preview, document fetch, or callback features.
- Redirect following combined with attacker-controlled destinations.

The strongest evidence is a data flow from untrusted input to a server-side outbound request.

## False-positive considerations
- Destination is selected from a strict allowlist.
- Host/IP validation is performed correctly before connection.
- The server cannot reach sensitive internal resources.
- The request is made in the browser, not on the server.

## Remediation
- Allowlist permitted schemes, hosts, and ports.
- Validate resolved destinations and consider DNS rebinding.
- Restrict access to loopback, link-local, private, and other internal ranges according to deployment needs.
- Restrict outbound network access at the infrastructure layer.
- Avoid naive URL prefix checks.

## Review note
Exploitability is deployment-dependent. Cloud metadata services and internal admin interfaces can increase impact, but the actual environment must be reviewed.
