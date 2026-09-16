# CWE-434: Unrestricted Upload of File with Dangerous Type

## Overview
A file-upload vulnerability can occur when an application permits dangerous file types or stores uploaded content in a way that enables unintended execution or other security impact.

## Detection hints
Review multipart upload handlers, filename/extension checks, MIME checks, content/signature validation, storage location, permissions, web-server execution behavior, and download authorization.

An extension check alone is weak evidence of safety.

## False-positive considerations
- Uploads are stored outside the executable web root.
- The server explicitly disables execution of uploaded content.
- A strict allowlist and robust content validation are enforced.

## Remediation
- Strictly allowlist supported types.
- Validate content/signature where appropriate, not only client MIME type or extension.
- Generate server-side filenames.
- Store files outside the web root when possible.
- Disable execution of uploaded content.
- Enforce size limits and authorization.

## Review note
Upload permission and download permission are separate controls. Being allowed to upload a file does not automatically authorize retrieval of every retained file.
