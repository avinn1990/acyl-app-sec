# Example goals.md

Copy this file into a repository (or pass `--goals`) before scanning.
Empty goals block the run.

## Secret exposure
CWE: CWE-798
id: secrets

Find committed secrets, tokens, and hard-coded credentials.

## Injection
CWE: CWE-78
id: command-injection

Locate OS command injection sinks reachable from untrusted input.

## Dependency risk
id: sca

Review third-party dependencies for known vulnerable versions.
