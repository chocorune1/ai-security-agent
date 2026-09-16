# CWE-79: Cross-site Scripting (XSS)

## Overview
XSS occurs when attacker-controlled input reaches a web page or browser-side DOM without appropriate contextual encoding or sanitization, allowing unintended script or markup execution in another user's browser.

## Detection hints
- JSP expressions such as `<%= userInput %>` in HTML output without contextual encoding.
- JavaScript `element.innerHTML = userInput`, `outerHTML`, `insertAdjacentHTML`, `document.write` and similar HTML sinks.
- Data from request parameters, URL, DOM, storage, messages, or network responses flowing into dangerous DOM sinks.
- A source-to-sink data flow is stronger evidence than the API name alone.

## False-positive considerations
- Input may be a fixed constant rather than attacker-controlled.
- A framework may perform correct contextual output encoding.
- `innerHTML` can be safe only when the value is explicitly known-safe or correctly sanitized HTML.
- HTML encoding does not automatically protect JavaScript, CSS, or URL contexts.

## Remediation
- Prefer `textContent` when HTML is not required.
- Apply contextual output encoding at the final output boundary.
- Sanitize required HTML using a maintained allowlist sanitizer.
- Use a restrictive Content Security Policy as defense in depth.

## Example
```javascript
// Risky
const name = getUserName();
document.getElementById("user").innerHTML = name;

// Safer
const name = getUserName();
document.getElementById("user").textContent = name;
```

## Mapping
- OWASP: Injection category
- Related CWE: CWE-116
