# CWE-22: Path Traversal

## Overview
Path traversal occurs when attacker-controlled path information is used without ensuring that the resolved path stays within the intended directory.

## Detection hints
- `File`, `Path`, `Files`, archive extraction, download, or upload code using request parameters.
- File names assembled by string concatenation.
- Download endpoints accepting physical filenames or paths.
- `Paths.get`, `new File`, `Files.readAllBytes`, `Files.copy`, and similar APIs fed by external input.

## False-positive considerations
- User input may be converted to a server-side opaque ID first.
- The resolved path may be normalized and checked against a fixed base directory.
- A strict allowlist may restrict inputs to identifiers instead of filesystem paths.

## Remediation
- Prefer opaque server-side file IDs.
- Resolve against a fixed base directory and verify the normalized result remains inside it.
- Do not rely only on removing `../`; consider encoding, normalization, symbolic links, and platform behavior.
- Enforce authorization separately from path validation.

## Example
```java
Path base = Paths.get(uploadDir).toAbsolutePath().normalize();
Path target = base.resolve(fileId).normalize();
if (!target.startsWith(base)) {
    throw new SecurityException("Invalid path");
}
```
