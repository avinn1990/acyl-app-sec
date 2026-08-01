# acyl minimal goals

Fast preset for small tools. Opt in with:

```bash
acyl scan /path/to/repo --goals goals/minimal.md
```

The bundled default remains `goals/standard.md`.

## Hardcoded credentials and secret exposure
id: secrets
CWE: CWE-798
owasp: A02:2025
codeguard: codeguard-1-hardcoded-credentials

Find committed secrets, passwords, API keys, tokens, and private keys.

## Vulnerable and unpinned dependencies
id: supply-chain
CWE: CWE-1104
owasp: A03:2025
codeguard: codeguard-0-supply-chain-security

Review manifests for known-vulnerable dependency versions.

## Injection
id: injection
CWE: CWE-78
owasp: A05:2025
codeguard: codeguard-0-input-validation-injection

Locate OS/SQL/command injection and unsafe eval sinks from untrusted input.
