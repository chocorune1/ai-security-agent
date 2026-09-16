# CWE-862: Missing Authorization

## Overview
Missing authorization occurs when an application authenticates a user but fails to verify that the user is permitted to perform an action or access a requested resource.

## Detection hints
- Service/controller methods retrieving objects by user-supplied IDs without ownership/role/tenant checks.
- Download endpoints accepting physical filenames or object IDs and returning them directly.
- Administrative functions protected only by authentication.
- Multi-tenant operations lacking tenant/corporation scope checks.

## False-positive considerations
- Authorization is enforced by middleware, annotations, interceptors, service-layer policy, or database security outside the shown code.
- The resource is intentionally public.
- A guaranteed earlier authorization check is part of the architecture.

## Remediation
- Enforce authorization server-side for every protected resource/action.
- Check principal, ownership, role, tenant/scope, purpose, and operation as required by the business rule.
- Prefer centralized authorization policies where practical.
- Do not rely on hidden UI controls or predictable IDs.

## Review note
This CWE frequently requires cross-file and architecture-level reasoning. Treat a local rule hit as a candidate unless the missing check is demonstrable.
