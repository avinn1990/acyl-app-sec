# acyl standard goals

Bundled default evaluation goals for any repository. Used automatically when a
target has no local `goals.md` and `--goals` is not passed.

CodeGuard is a detector rule pack — not a goal. Each section maps to CWEs,
OWASP Top 10:2025, and related CodeGuard rules for coverage tracking.

## Hardcoded credentials and secret exposure
id: secrets
CWE: CWE-798
owasp: A02:2025
codeguard: codeguard-1-hardcoded-credentials

Find committed secrets, passwords, API keys, tokens, private keys, and
connection strings in source and config. Treat presence in the repository
as the vulnerability.

## Vulnerable and unpinned dependencies
id: supply-chain
CWE: CWE-1104
owasp: A03:2025
codeguard: codeguard-0-supply-chain-security

Review third-party dependencies and manifests for known-vulnerable versions,
missing pins, and supply-chain risk in package.json, requirements, go.mod,
and similar lock/manifest files.

## Injection
id: injection
CWE: CWE-78
owasp: A05:2025
codeguard: codeguard-0-input-validation-injection

Locate OS/SQL/command injection and unsafe eval sinks reachable from
untrusted input (HTTP, CLI, queues, webhooks). Prefer parameterized APIs;
flag shell=True, exec, and raw string-built queries. Also consider CWE-89.

## Weak or deprecated cryptography
id: crypto
CWE: CWE-327
owasp: A04:2025
codeguard: codeguard-1-crypto-algorithms

Find weak or deprecated cryptographic primitives (MD5, SHA1 for security,
DES/RC4, insecure RNG) and misuse of crypto APIs. Also consider CWE-328
and codeguard-0-additional-cryptography.

## Authentication and credential handling
id: authn
CWE: CWE-287
owasp: A07:2025
codeguard: codeguard-0-authentication-mfa

Locate authentication failures: weak password handling, missing MFA hooks,
insecure token/session issuance, and credential recovery flaws. Also
consider CWE-384 and codeguard-0-session-management-and-cookies.

## Broken access control and IDOR
id: authz
CWE: CWE-639
owasp: A01:2025
codeguard: codeguard-0-authorization-access-control

Find missing or bypassable authorization checks, IDOR-style direct object
references, mass assignment, and privilege escalation paths in handlers
and data access layers. Also consider CWE-862.

## SSRF and unsafe outbound requests
id: ssrf-api
CWE: CWE-918
owasp: A05:2025
codeguard: codeguard-0-api-web-services

Locate server-side request forgery and unsafe outbound HTTP/URL fetches
driven by user input, including webhook and redirect openers without
allowlists or scheme validation.

## XSS and unsafe client sinks
id: xss-client
CWE: CWE-79
owasp: A05:2025
codeguard: codeguard-0-client-side-web-security

Find cross-site scripting sinks: unsafe HTML injection, missing output
encoding, dangerous DOM APIs, and weak CSP/CSRF protections in web clients.

## Unsafe deserialization and XXE
id: deserialization
CWE: CWE-502
owasp: A08:2025
codeguard: codeguard-0-xml-and-serialization

Locate unsafe native deserialization, untrusted pickle/YAML/Java
deserialization, and XML external entity (XXE / CWE-611) parsing without
hardening.

## Path traversal and unsafe file uploads
id: files
CWE: CWE-22
owasp: A01:2025
codeguard: codeguard-0-file-handling-and-uploads

Find path traversal, unrestricted file upload, and unsafe file delivery
patterns that let attackers read or write outside intended directories.
Also consider CWE-434.

## Insecure defaults and cleartext transport
id: misconfig
CWE: CWE-319
owasp: A02:2025
codeguard: codeguard-0-devops-ci-cd-containers

Flag cleartext HTTP to non-local hosts, insecure CI/container defaults,
and Infrastructure-as-Code footguns. Also consider CWE-16 and
codeguard-0-iac-security.

## MCP and agent tool abuse surface
id: agent-mcp
CWE: CWE-1420
owasp: A03:2025
codeguard: codeguard-0-mcp-security

Locate Model Context Protocol and agent-tool configurations that expose
over-broad tools, untrusted skill installs, or missing isolation around
agent-executed commands.
